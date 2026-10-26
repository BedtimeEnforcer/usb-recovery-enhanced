#pragma once
#include "enhanced_engine.hpp"
#include <deque>
#include <memory>
#include <atomic>

namespace enhanced {
// A resumable cursor retains the directory enumeration position; each page has bounded budgets.
struct DirectoryCursor {
    S path;int depth=0;HANDLE handle=INVALID_HANDLE_VALUE;WIN32_FIND_DATAW next{};bool first=true,descend=true;
    DirectoryCursor(S p,int d):path(std::move(p)),depth(d){}
    ~DirectoryCursor(){if(handle!=INVALID_HANDLE_VALUE)FindClose(handle);}
    bool take(Entry& entry) {
        if(first){noLinks(path);handle=FindFirstFileW(xp(join(path,L"*")).c_str(),&next);first=false;
            if(handle==INVALID_HANDLE_VALUE){if(GetLastError()==ERROR_FILE_NOT_FOUND)return false;fail(L"读取目录："+path);}}
        else if(!FindNextFileW(handle,&next)){if(GetLastError()==ERROR_NO_MORE_FILES)return false;fail(L"继续读取目录："+path);}
        entry={join(path,next.cFileName),next.dwFileAttributes,((uint64_t)next.nFileSizeHigh<<32)|next.nFileSizeLow,next.ftLastWriteTime};return true;
    }
};
struct ScanGroup {
    S title;bool removable=false,critical=false;
    std::deque<std::shared_ptr<DirectoryCursor>> directories;
    std::deque<Entry> direct;
    std::vector<S> roots;
};
struct ScanSession {
    S root;DWORD serial=0;bool initialized=false, cancelled=false, complete=false;
    std::vector<ScanGroup> groups;
    std::set<S> seen;
    std::vector<S> excluded,errors,criticalErrors;
    std::vector<Finding> findings;
    Scanner scanner;
    size_t checked=0, pages=0;
    bool pending() const {for(const auto& g:groups)if(!g.direct.empty() || !g.directories.empty())return true;return false;}
    bool criticalReady() const {
        if(!criticalErrors.empty())return false;
        for(const auto& g:groups)if(g.critical && (!g.direct.empty() || !g.directories.empty()))return false;
        return initialized;
    }
};
inline bool excludedPath(const S& p,const std::vector<S>& excluded){for(const auto& e:excluded)if(underPath(p,e))return true;return false;}
inline void addScanRoot(ScanGroup& group,const S& path) {
    if(path.empty())return;
    for(const auto& p:group.roots)if(same(p,path))return;
    group.roots.push_back(path);group.directories.push_back(std::make_shared<DirectoryCursor>(path,0));
}
inline void initializeScan(ScanSession& session,const S& root,Log log) {
    session=ScanSession{};session.root=root;
    if(!root.empty()){
        if(full(root).size()!=3 || GetDriveTypeW(root.c_str())!=DRIVE_REMOVABLE)throw Error{L"请选择可移动 U 盘"};
        session.serial=volume(root);
    }
    wchar_t windows[MAX_PATH]{},temp[MAX_PATH]{};GetWindowsDirectoryW(windows,MAX_PATH);GetTempPathW(MAX_PATH,temp);
    session.scanner.tempRoots={temp};session.scanner.riskRoots={windows};session.scanner.usbRoot=root;
    ScanGroup immediate{L"运行进程与启动文件",false,true,{}, {}, {}};
    auto direct=[&](const S& path){if(localAbsolute(path) && !excludedPath(path,session.excluded))
        immediate.direct.push_back({path,0,0,{}});};
    auto userLocal=folder(CSIDL_LOCAL_APPDATA);session.excluded.push_back(join(userLocal,L"UsbRecovery"));
    processes([&](DWORD,const S& path){direct(path);},log);
    for(const auto& r:runs(log))for(const auto& path:referencedPaths(r.value))if(exists(path))direct(path);
    ScanGroup priority{L"常见病毒落地位置",false,true,{}, {}, {}};
    addScanRoot(priority,temp);
    for(int id:{CSIDL_APPDATA,CSIDL_LOCAL_APPDATA,CSIDL_STARTUP,CSIDL_COMMON_STARTUP,CSIDL_COMMON_APPDATA,CSIDL_COMMON_DOCUMENTS})
        try{S p=folder(id);addScanRoot(priority,id==CSIDL_COMMON_DOCUMENTS?parent(p):p);
            if(id==CSIDL_APPDATA || id==CSIDL_LOCAL_APPDATA)session.scanner.riskRoots.push_back(p);
        }catch(const Error& e){session.criticalErrors.push_back(e.text);log(e.text);}
    // Top-level enumeration consumes the same page budget, without reading whole roots up front.
    for(const auto& path:std::vector<S>{S(windows),folder(CSIDL_PROFILE)}){
        auto cursor=std::make_shared<DirectoryCursor>(path,0);cursor->descend=false;immediate.directories.push_back(cursor);
    }
    session.groups.push_back(std::move(immediate));session.groups.push_back(std::move(priority));
    ScanGroup usb{L"所选 U 盘",true,true,{}, {}, {}};if(!root.empty())addScanRoot(usb,root);session.groups.push_back(std::move(usb));
    ScanGroup system{L"Windows 系统目录",false,false,{}, {}, {}};addScanRoot(system,windows);session.groups.push_back(std::move(system));
    ScanGroup user{L"桌面、文档与当前用户目录",false,false,{}, {}, {}};addScanRoot(user,folder(CSIDL_PROFILE));session.groups.push_back(std::move(user));
    ScanGroup apps{L"Program Files",false,false,{}, {}, {}};
    for(int id:{CSIDL_PROGRAM_FILES,CSIDL_PROGRAM_FILESX86})try{addScanRoot(apps,folder(id));}catch(const Error& e){log(e.text);}
    wchar_t native[32768]{};DWORD len=GetEnvironmentVariableW(L"ProgramW6432",native,32768);if(len && len<32768)addScanRoot(apps,native);
    session.groups.push_back(std::move(apps));
    wchar_t own[32768];DWORD n=GetModuleFileNameW(nullptr,own,32768);if(n && n<32768)try{session.scanner.selfDigest=hash(S(own,n));}catch(const Error&){}
    session.initialized=true;
}
inline S cancellableHash(const S& path,const std::function<bool()>& cancel,const std::function<void(uint64_t)>& heartbeat={}) {
    noLinks(path);Handle file(CreateFileW(xp(path).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr));
    if(file.h==INVALID_HANDLE_VALUE)fail(L"读取文件："+path);
    HCRYPTPROV provider=0;HCRYPTHASH digest=0;
    if(!CryptAcquireContextW(&provider,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT))fail(L"初始化 SHA-256");
    if(!CryptCreateHash(provider,CALG_SHA_256,0,0,&digest)){CryptReleaseContext(provider,0);fail(L"初始化哈希");}
    S result;
    try{BYTE bytes[65536];DWORD got=0;uint64_t total=0;
        for(;;){if(cancel && cancel())throw Error{L"检查已停止"};if(!ReadFile(file.h,bytes,sizeof(bytes),&got,nullptr))fail(L"读取文件");if(!got)break;
            if(!CryptHashData(digest,bytes,got,0))fail(L"计算哈希");
            total+=got;if(heartbeat)heartbeat(total);}
        BYTE output[32];DWORD length=32;if(!CryptGetHashParam(digest,HP_HASHVAL,output,&length,0))fail(L"读取哈希");
        const wchar_t* hex=L"0123456789ABCDEF";for(BYTE b:output){result+=hex[b>>4];result+=hex[b&15];}
    }catch(...){CryptDestroyHash(digest);CryptReleaseContext(provider,0);throw;}
    CryptDestroyHash(digest);CryptReleaseContext(provider,0);return result;
}
inline void scanPage(ScanSession& s,Log log,ScanProgress progress,const std::function<bool()>& cancel={},size_t limit=ENTRY_LIMIT) {
    NativeFs native;
    struct ResetHash {Scanner& scanner;~ResetHash(){scanner.digestFile=hash;}} reset{s.scanner};
    s.cancelled=false;s.complete=false;++s.pages;
    if(!s.initialized)throw Error{L"检查尚未初始化"};
    if(!s.root.empty() && volume(s.root)!=s.serial)throw Error{L"U 盘已更换，请重新检查"};
    size_t host=0,usb=0;bool advanced=true;
    // Rotating small quanta prevent any large subtree from starving other groups.
    while(advanced){advanced=false;
        for(auto& group:s.groups){size_t& used=group.removable?usb:host;
            for(size_t quantum=0;quantum<64 && used<limit;++quantum){
                if(cancel && cancel()){s.cancelled=true;return;}
                Entry entry{};bool available=false;
                if(!group.direct.empty()){entry=group.direct.front();available=true;}
                else while(!group.directories.empty() && used<limit){
                    if(cancel && cancel()){s.cancelled=true;return;}
                    auto cursor=group.directories.front();
                    try{if(excludedPath(cursor->path,s.excluded)){group.directories.pop_front();continue;}
                        available=cursor->take(entry);
                    }catch(const Error& e){s.errors.push_back(e.text);log(e.text);
                        if(group.critical && (group.removable || cursor->depth==0))s.criticalErrors.push_back(e.text);
                        group.directories.pop_front();continue;}
                    if(!available){group.directories.pop_front();continue;}
                    if(name(entry.path)==L"." || name(entry.path)==L"..")continue;
                    if(entry.attrs&FILE_ATTRIBUTE_REPARSE_POINT){log(L"跳过链接："+entry.path);++used;available=false;continue;}
                    if(entry.attrs&FILE_ATTRIBUTE_DIRECTORY){
                        S n=lower(name(entry.path));
                        if(cursor->descend && n!=L"$recycle.bin" && n!=L"system volume information" && !excludedPath(entry.path,s.excluded)) {
                            if(cursor->depth>=128){S error=L"目录深度达到 128 上限："+entry.path;s.errors.push_back(error);log(error);if(group.critical)s.criticalErrors.push_back(error);}
                            else group.directories.push_back(std::make_shared<DirectoryCursor>(entry.path,cursor->depth+1));
                        }++used;advanced=true;available=false;break;
                    }
                    group.direct.push_back(entry);break;
                }
                if(!available){if(group.directories.empty() && group.direct.empty())break;continue;}
                ++used;advanced=true;
                S identity=lower(full(entry.path));
                if(s.seen.count(identity) || excludedPath(entry.path,s.excluded)){group.direct.pop_front();continue;}
                if(progress)progress(group.title+L" · "+entry.path,s.checked);
                s.scanner.digestFile=[&](const S& p){return cancellableHash(p,cancel,[&](uint64_t n){if(progress)progress(group.title+L" · "+p+L"（已读取 "+num(n/1024)+L" KB）",s.checked);});};
                auto before=s.findings.size();
                s.scanner.inspect(entry.path,s.findings,[&](const S& error){if(cancel && cancel())return;s.errors.push_back(error);log(error);
                    if(group.removable || suspicious(entry.path) || residualName(entry.path))s.criticalErrors.push_back(error);});
                if(cancel && cancel()){s.findings.resize(before);s.cancelled=true;s.scanner.digestFile=hash;return;}
                s.seen.insert(identity);group.direct.pop_front();++s.checked;
                if(progress)progress(group.title+L" · "+entry.path,s.checked);
            }
        }
    }
    s.scanner.digestFile=hash;s.complete=!s.pending();
    if(!s.root.empty() && volume(s.root)!=s.serial)throw Error{L"U 盘已更换，请重新检查"};
    if(!s.complete)log(L"达到本轮检查上限，已保存检查位置，可继续检查。");
}
inline S sessionScope(const ScanSession& s) {
    S text=L"推荐检查：运行进程、Run/RunOnce 引用、常见落地位置、所选 U 盘、Windows、当前用户目录（含桌面/文档/下载）、Program Files。\r\n";
    for(const auto& g:s.groups)text+=g.title+L"："+((g.direct.empty() && g.directories.empty())?L"本轮遍历结束":L"待继续")+L"\r\n";
    text+=L"每轮电脑与 U 盘各最多 200000 项；继续检查从保存的位置进行。目录深度 128，文件哈希 64 MiB，内容解析 1 MiB。其他用户、未选磁盘、压缩包、内存注入不覆盖；链接、隔离区及系统保留目录跳过。\r\n";
    for(const auto& e:s.errors)text+=e+L"\r\n";
    return text;
}
} // namespace enhanced
