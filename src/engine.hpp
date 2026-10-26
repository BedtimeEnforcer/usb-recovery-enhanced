#pragma once
#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif
#define WINVER 0x0601
#define _WIN32_WINNT 0x0601
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <set>
#include <functional>
#include <algorithm>
#include <cwctype>
#include <cstdint>
#include <cstring>

namespace usb {
using S=std::wstring; using Log=std::function<void(const S&)>;
using ScanProgress=std::function<void(const S&,size_t)>;
const S HASH=L"4F1DDA9749E38A76FCF0C5A80BAF2F7166C0787C0EB9D86F50C689B1263E94D2";
struct Error { S text; };
inline S num(uint64_t n){return std::to_wstring(n);}
inline void fail(const S& context){DWORD code=GetLastError();wchar_t* msg=nullptr;FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,nullptr,code,0,(wchar_t*)&msg,0,nullptr);S s=context+L" ["+num(code)+L"] "+(msg?msg:L"");if(msg)LocalFree(msg);throw Error{s};}
struct Handle { HANDLE h=INVALID_HANDLE_VALUE;explicit Handle(HANDLE x=INVALID_HANDLE_VALUE):h(x){}~Handle(){if(h!=INVALID_HANDLE_VALUE&&h)CloseHandle(h);}Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete; };
inline S lower(S s){std::transform(s.begin(),s.end(),s.begin(),towlower);return s;}
inline S full(const S& p){std::vector<wchar_t>b(32768);DWORD n=GetFullPathNameW(p.c_str(),(DWORD)b.size(),b.data(),nullptr);if(!n||n>=b.size())throw Error{L"路径过长或无效："+p};S s(b.data());while(s.size()>3&&s.back()==L'\\')s.pop_back();return s;}
inline S xp(const S& p){S s=full(p);if(s.substr(0,2)==L"\\\\")return L"\\\\?\\UNC\\"+s.substr(2);return L"\\\\?\\"+s;}
inline S parent(const S& p){auto pos=p.find_last_of(L'\\');return pos==2?p.substr(0,3):p.substr(0,pos);}
inline S name(const S& p){return p.substr(p.find_last_of(L'\\')+1);}
inline S join(const S& p,const S& n){return p+(p.back()==L'\\'?L"":L"\\")+n;}
inline bool same(const S&a,const S&b){return lower(full(a))==lower(full(b));}
inline DWORD attr(const S&p){DWORD a=GetFileAttributesW(xp(p).c_str());if(a==INVALID_FILE_ATTRIBUTES)fail(L"读取属性："+p);return a;}
inline bool exists(const S&p){return GetFileAttributesW(xp(p).c_str())!=INVALID_FILE_ATTRIBUTES;}
inline void noLinks(const S&p){S s=full(p);for(;;){if(attr(s)&FILE_ATTRIBUTE_REPARSE_POINT)throw Error{L"拒绝链接/重解析路径："+s};if(s.size()<=3)break;s=parent(s);}}
inline void mkdir(const S&p){if(!CreateDirectoryW(xp(p).c_str(),nullptr)&&GetLastError()!=ERROR_ALREADY_EXISTS)fail(L"创建目录："+p);noLinks(p);}
inline S folder(int id){wchar_t b[MAX_PATH];if(FAILED(SHGetFolderPathW(nullptr,id,nullptr,SHGFP_TYPE_CURRENT,b)))throw Error{L"无法获取用户目录"};return b;}
inline S data(){S p=join(folder(CSIDL_LOCAL_APPDATA),L"UsbRecovery");mkdir(p);return p;}
inline std::string utf8(const S&s){int n=WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0,nullptr,nullptr);std::string b(n,0);WideCharToMultiByte(CP_UTF8,0,s.data(),(int)s.size(),&b[0],n,nullptr,nullptr);return b;}
inline S fromUtf8(const std::string&s){int n=MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0);S b(n,0);if(n)MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),&b[0],n);return b;}
inline S quote(const S&s){S r=L"\"";for(wchar_t c:s){switch(c){case L'"':r+=L"\\\"";break;case L'\\':r+=L"\\\\";break;case L'\n':r+=L"\\n";break;case L'\r':r+=L"\\r";break;case L'\t':r+=L"\\t";break;default:if(c<32){wchar_t t[8];wsprintfW(t,L"\\u%04x",c);r+=t;}else r+=c;}}return r+L"\"";}
inline void write(HANDLE h,const void*p,DWORD n){DWORD done=0;if(n&&(!WriteFile(h,p,n,&done,nullptr)||done!=n))fail(L"写入文件");}
inline void textFile(const S&p,const S&s){Handle h(CreateFileW(xp(p).c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));if(h.h==INVALID_HANDLE_VALUE)fail(L"创建文件："+p);auto b=utf8(s);write(h.h,b.data(),(DWORD)b.size());if(!FlushFileBuffers(h.h))fail(L"保存文件："+p);}
inline S stamp(){SYSTEMTIME t;GetLocalTime(&t);wchar_t b[64];wsprintfW(b,L"%04d%02d%02d-%02d%02d%02d-%03d",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);return b;}
struct Journal { S dir;Handle h;int seq=0; explicit Journal(const S&base){mkdir(base);static LONG serial=0;dir=join(base,stamp()+L"-"+num(GetCurrentProcessId())+L"-"+num(InterlockedIncrement(&serial)));if(!CreateDirectoryW(xp(dir).c_str(),nullptr))fail(L"创建记录目录");h.h=CreateFileW(xp(join(dir,L"operations.jsonl")).c_str(),GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(h.h==INVALID_HANDLE_VALUE)fail(L"创建日志");}void add(const S&a,const S&s,const S&d,const S&detail){auto b=utf8(L"{\"time\":"+quote(stamp())+L",\"action\":"+quote(a)+L",\"source\":"+quote(s)+L",\"destination\":"+quote(d)+L",\"detail\":"+quote(detail)+L"}\r\n");write(h.h,b.data(),(DWORD)b.size());if(!FlushFileBuffers(h.h))fail(L"落盘操作日志");}};
struct Entry{S path;DWORD attrs;uint64_t size;FILETIME time;};
inline std::vector<Entry> list(const S&p){noLinks(p);WIN32_FIND_DATAW d;HANDLE h=FindFirstFileW(xp(join(p,L"*")).c_str(),&d);if(h==INVALID_HANDLE_VALUE){if(GetLastError()==ERROR_FILE_NOT_FOUND)return {};fail(L"列出目录："+p);}std::vector<Entry> r;do{if(wcscmp(d.cFileName,L".")&&wcscmp(d.cFileName,L".."))r.push_back({join(p,d.cFileName),d.dwFileAttributes,((uint64_t)d.nFileSizeHigh<<32)|d.nFileSizeLow,d.ftLastWriteTime});}while(FindNextFileW(h,&d));DWORD err=GetLastError();FindClose(h);if(err!=ERROR_NO_MORE_FILES){SetLastError(err);fail(L"枚举目录："+p);}std::sort(r.begin(),r.end(),[](const Entry&a,const Entry&b){return lower(a.path)<lower(b.path);});return r;}
inline S hashHandle(HANDLE h){LARGE_INTEGER z{};if(!SetFilePointerEx(h,z,nullptr,FILE_BEGIN))fail(L"定位文件");HCRYPTPROV prov=0;HCRYPTHASH hash=0;if(!CryptAcquireContextW(&prov,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT))fail(L"初始化 SHA-256");if(!CryptCreateHash(prov,CALG_SHA_256,0,0,&hash)){CryptReleaseContext(prov,0);fail(L"创建 SHA-256");}BYTE buf[65536];DWORD n;bool ok=true;for(;;){if(!ReadFile(h,buf,sizeof(buf),&n,nullptr)){ok=false;break;}if(!n)break;if(!CryptHashData(hash,buf,n,0)){ok=false;break;}}BYTE digest[32];DWORD len=32;if(ok)ok=CryptGetHashParam(hash,HP_HASHVAL,digest,&len,0)!=0;CryptDestroyHash(hash);CryptReleaseContext(prov,0);if(!ok)fail(L"计算 SHA-256");S r;const wchar_t* hex=L"0123456789ABCDEF";for(BYTE c:digest){r+=hex[c>>4];r+=hex[c&15];}return r;}
inline S hash(const S&p){noLinks(p);Handle h(CreateFileW(xp(p).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr));if(h.h==INVALID_HANDLE_VALUE)fail(L"读取文件："+p);return hashHandle(h.h);}
inline uint64_t size(const S&p){WIN32_FILE_ATTRIBUTE_DATA d;if(!GetFileAttributesExW(xp(p).c_str(),GetFileExInfoStandard,&d))fail(L"读取大小："+p);return ((uint64_t)d.nFileSizeHigh<<32)|d.nFileSizeLow;}
inline bool known(const S&p){return size(p)==85504&&hash(p)==HASH;}
inline bool suspicious(const S&p){S n=lower(name(p));return n==L"drvmgr.exe"||n==L"sysgredlvrs.exe";}
inline bool extension(const S&p,const S&ext){auto n=lower(p);return n.size()>=ext.size()&&n.substr(n.size()-ext.size())==ext;}
inline std::vector<BYTE> bytes(const S&p){noLinks(p);auto n=size(p);if(n>1048576)throw Error{L"文件过大，拒绝解析快捷方式"};Handle h(CreateFileW(xp(p).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));if(h.h==INVALID_HANDLE_VALUE)fail(L"读取快捷方式");std::vector<BYTE>b((size_t)n);DWORD read;if(!ReadFile(h.h,b.data(),(DWORD)n,&read,nullptr)||read!=n)fail(L"读取快捷方式内容");return b;}
inline uint32_t field(const std::vector<BYTE>&b,size_t p,size_t n){if(p>b.size()||n>b.size()-p)throw Error{L"快捷方式结构截断"};uint32_t v=0;for(size_t i=0;i<n;i++)v|=uint32_t(b[p+i])<<(8*i);return v;}
inline S arguments(const S&p){auto b=bytes(p);if(b.size()<76||field(b,0,4)!=76)return L"";const BYTE id[]={1,20,2,0,0,0,0,0,192,0,0,0,0,0,0,70};if(memcmp(b.data()+4,id,16))return L"";auto f=field(b,20,4);size_t pos=76;if(f&1)pos+=2+field(b,pos,2);if(f&2){auto n=field(b,pos,4);if(n<4||n>b.size())throw Error{L"快捷方式结构异常"};pos+=n;}for(auto bit:{4,8,16,32,64})if(f&bit){auto n=field(b,pos,2);pos+=2;size_t len=n*((f&128)?2:1);if(pos>b.size()||len>b.size()-pos)throw Error{L"快捷方式字符串越界"};S s;if(f&128){for(size_t i=0;i<n;i++)s+=(wchar_t)field(b,pos+i*2,2);}else{int len2=MultiByteToWideChar(CP_ACP,0,(char*)b.data()+pos,n,nullptr,0);s.resize(len2);if(len2)MultiByteToWideChar(CP_ACP,0,(char*)b.data()+pos,n,&s[0],len2);}pos+=len;if(bit==32)return s;}return L"";}
struct StaticLink { S target, relative, work, args; };
inline StaticLink parseStaticLink(const std::vector<BYTE>& b) {
    StaticLink r;
    const BYTE clsid[]={1,20,2,0,0,0,0,0,192,0,0,0,0,0,0,70};
    if (b.size()<76 || field(b,0,4)!=76 || memcmp(b.data()+4,clsid,16)) return r;
    auto flags=field(b,20,4); size_t pos=76;
    if (flags&1) { auto n=field(b,pos,2); pos+=2; if (n>b.size()-pos) throw Error{L"快捷方式 IDList 越界"}; pos+=n; }
    if (flags&2) {
        const size_t start=pos, n=field(b,pos,4);
        if (n<28 || pos>b.size() || n>b.size()-pos) throw Error{L"快捷方式 LinkInfo 越界"};
        const size_t header=field(b,start+4,4);
        if (header<28 || header>n || (header>28 && header<36)) throw Error{L"快捷方式 LinkInfo 头异常"};
        auto readPath=[&](size_t offset, bool wide) -> S {
            if (!offset) return L"";
            if (offset<header || offset>=n) throw Error{L"快捷方式路径偏移异常"};
            size_t p=start+offset, end=start+n; S text;
            if (wide) {
                while (p+1<end) { auto c=field(b,p,2); if (!c) return text; text+=wchar_t(c); p+=2; }
            } else {
                size_t begin=p; while(p<end && b[p]) ++p;
                if (p<end) { int len=MultiByteToWideChar(CP_ACP,0,reinterpret_cast<const char*>(b.data()+begin),int(p-begin),nullptr,0); text.resize(len); if(len) MultiByteToWideChar(CP_ACP,0,reinterpret_cast<const char*>(b.data()+begin),int(p-begin),&text[0],len); return text; }
            }
            throw Error{L"快捷方式路径缺少终止符"};
        };
        // 只静态读取本地目标，不解析 IDList 或联系网络共享。
        if (field(b,start+8,4)&1) {
            size_t u=header>=36 ? field(b,start+28,4) : 0;
            r.target=readPath(u ? u : field(b,start+16,4),u!=0);
        }
        pos+=n;
    }
    for (auto bit : {4,8,16,32,64}) if (flags&bit) {
        size_t count=field(b,pos,2); pos+=2;
        size_t len=count*((flags&128)?2:1);
        if (pos>b.size() || len>b.size()-pos) throw Error{L"快捷方式 StringData 越界"};
        S text;
        if(flags&128) { for(size_t i=0;i<count;++i) text+=wchar_t(field(b,pos+i*2,2)); }
        else { int n=MultiByteToWideChar(CP_ACP,0,reinterpret_cast<const char*>(b.data()+pos),int(count),nullptr,0); text.resize(n); if(n) MultiByteToWideChar(CP_ACP,0,reinterpret_cast<const char*>(b.data()+pos),int(count),&text[0],n); }
        pos+=len;
        if(bit==8) r.relative=text;
        if(bit==16) r.work=text;
        if(bit==32) r.args=text;
    }
    while(pos+4<=b.size()) {
        size_t block=field(b,pos,4);if(!block)break;
        if(block<8 || block>b.size()-pos)throw Error{L"快捷方式 ExtraData 越界"};
        if(field(b,pos+4,4)==0xA0000001 && block>=788 && r.target.empty()) {
            S value;for(size_t i=0;i<260;++i){auto c=field(b,pos+268+i*2,2);if(!c)break;value+=wchar_t(c);}
            if(value.empty())for(size_t i=0;i<260 && b[pos+8+i];++i)value+=wchar_t(b[pos+8+i]);
            r.target=value;
        }
        pos+=block;
    }
    return r;
}
inline S normalizedArguments(const S& input) {
    S normalized;bool space=false;
    for(wchar_t c:lower(input)){if(iswspace(c)){space=true;continue;}if(space&&!normalized.empty())normalized+=L' ';space=false;normalized+=c;}
    return normalized;
}
inline bool commandTarget(const StaticLink& link) {
    S target=lower(link.target.empty()?link.relative:link.target);
    if(target.size()>1 && target.front()==L'"' && target.back()==L'"')target=target.substr(1,target.size()-2);
    return target==L"%comspec%" || name(target)==L"cmd.exe";
}
inline bool wormLink(const S& p) {
    auto link=parseStaticLink(bytes(p));
    return commandTarget(link) && normalizedArguments(link.args)==L"/c start \uffff & start \uffff\\drvmgr.exe";
}
inline bool variantWormLink(const S& p) {
    auto link=parseStaticLink(bytes(p));if(!commandTarget(link))return false;
    S args=normalizedArguments(link.args);if(args==L"/c start \uffff & start \uffff\\drvmgr.exe")return false;
    args.erase(std::remove(args.begin(),args.end(),L'"'),args.end());
    return args.find(L"\uffff\\drvmgr.exe")!=S::npos;
}
struct NativeFs { PVOID old=nullptr; bool changed=false; NativeFs(){BOOL wow=FALSE;if(IsWow64Process(GetCurrentProcess(),&wow)&&wow){if(!Wow64DisableWow64FsRedirection(&old))fail(L"无法访问原生系统目录");changed=true;}}~NativeFs(){if(changed)Wow64RevertWow64FsRedirection(old);} };
enum class ReviewKind { None, ResidualName, NumericTemp, HighRiskName, LinkVariant, KnownHash };
struct Finding{S path,digest,reason;bool confirmed,link; ReviewKind review=ReviewKind::None; uint64_t fileSize=0; FILETIME created{};};
inline void inspect(const S&p,std::vector<Finding>&out,Log log,int& missing){try{/* TOCTOU 兜底：扫描期间临时进程可能已退出、文件可能被删，先判存在；不存在则静默跳过并计数，由 scan() 末尾汇总一条日志，消除逐条"未检查…系统找不到指定的文件"噪音。exists() 内部 full() 对极端路径可能抛异常，exists() 为假时立即取 GetLastError：仅 ERROR_FILE_NOT_FOUND(2)/ERROR_PATH_NOT_FOUND(3)（确认不存在）计入静默跳过；拒绝访问等其他错误不静默，继续走下方逐条日志。*/bool present=false;try{present=exists(p);}catch(const Error&){}if(!present){DWORD err=GetLastError();if(err==ERROR_FILE_NOT_FOUND||err==ERROR_PATH_NOT_FOUND){missing++;return;}}noLinks(p);if(known(p))out.push_back({p,HASH,L"SHA-256 精确命中已知 Phorpiex 样本",true,false});else if(extension(p,L".lnk")&&size(p)<=1048576&&wormLink(p))out.push_back({p,hash(p),L"命中特定隐藏目录 + DrvMgr 启动命令",true,true});else if(suspicious(p))out.push_back({p,L"",L"同名但哈希未知，不自动删除",false,false});}catch(const Error&e){log(L"未检查："+p+L" — "+e.text);}}
inline void walk(const S&root,const std::function<void(const Entry&)>&visit,Log log,Log directory={}){std::vector<S> stack{root};size_t count=0;while(!stack.empty()){S d=stack.back();stack.pop_back();if(directory)directory(d);try{for(auto&e:list(d)){if(++count>200000){log(L"达到 200000 项上限，检查不完整。");return;}if(e.attrs&FILE_ATTRIBUTE_REPARSE_POINT){log(L"跳过链接："+e.path);continue;}if(e.attrs&FILE_ATTRIBUTE_DIRECTORY){auto n=lower(name(e.path));if(n!=L"system volume information"&&n!=L"$recycle.bin")stack.push_back(e.path);}else visit(e);}}catch(const Error&e){log(L"未读取目录："+d+L" — "+e.text);}}}
inline S executable(S s){wchar_t buf[32768];DWORD n=ExpandEnvironmentStringsW(s.c_str(),buf,32768);if(!n||n>32768)return L"";s=buf;auto start=s.find_first_not_of(L" \t");if(start==S::npos)return L"";s=s.substr(start);if(s[0]==L'"'){auto end=s.find(L'"',1);return end==S::npos?L"":s.substr(1,end-1);}auto pos=lower(s).find(L".exe");return pos==S::npos?L"":s.substr(0,pos+4);}
struct RunEntry{HKEY hive;REGSAM view;S key,name,value,target;DWORD type;};
inline std::vector<RunEntry> runs(Log log){std::vector<RunEntry>out;for(auto hive:{HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE})for(auto view:{KEY_WOW64_32KEY,KEY_WOW64_64KEY})for(auto key:{L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}){SYSTEM_INFO si;GetNativeSystemInfo(&si);if(view==KEY_WOW64_64KEY && si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL)continue;HKEY h;LONG rc=RegOpenKeyExW(hive,key,0,KEY_READ|view,&h);if(rc==ERROR_FILE_NOT_FOUND||rc==ERROR_INVALID_PARAMETER)continue;if(rc!=ERROR_SUCCESS){log(L"未读取启动项："+S(key)+L" ["+num(rc)+L"]");continue;}for(DWORD i=0;;i++){wchar_t vn[16384];BYTE data[65536];DWORD nc=16384,sz=sizeof(data)-sizeof(wchar_t),type=0;rc=RegEnumValueW(h,i,vn,&nc,nullptr,&type,data,&sz);if(rc==ERROR_NO_MORE_ITEMS)break;if(rc!=ERROR_SUCCESS){log(L"启动项枚举不完整 ["+num(rc)+L"]");break;}if(type!=REG_SZ&&type!=REG_EXPAND_SZ)continue;data[sz]=data[sz+1]=0;S value((wchar_t*)data);out.push_back({hive,(REGSAM)view,key,S(vn,nc),value,executable(value),type});}RegCloseKey(h);}return out;}
inline void processes(const std::function<void(DWORD,const S&)>&visit,Log log){Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));if(snap.h==INVALID_HANDLE_VALUE)fail(L"获取进程列表");PROCESSENTRY32W pe{};pe.dwSize=sizeof(pe);int denied=0;if(Process32FirstW(snap.h,&pe))do{Handle p(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pe.th32ProcessID));wchar_t b[32768];DWORD n=32768;if(p.h&&QueryFullProcessImageNameW(p.h,0,b,&n))visit(pe.th32ProcessID,S(b,n));else denied++;}while(Process32NextW(snap.h,&pe));log(L"无法读取路径的进程数："+num(denied)+L"（包括系统保护进程）");}
inline std::vector<Finding> scan(const S&root,Log log,ScanProgress progress={}){NativeFs nativeFs;size_t checked=0;auto report=[&](const S&p){if(progress)progress(p,checked);};report(L"正在准备检查");std::set<S>files;auto add=[&](const S&p){files.insert(full(p));};wchar_t w[MAX_PATH],t[MAX_PATH];GetWindowsDirectoryW(w,MAX_PATH);GetTempPathW(MAX_PATH,t);std::vector<S>dirs{w,t};for(int id:{CSIDL_PROFILE,CSIDL_APPDATA,CSIDL_LOCAL_APPDATA,CSIDL_STARTUP,CSIDL_COMMON_STARTUP})try{dirs.push_back(folder(id));}catch(const Error&e){log(e.text);}for(auto&d:dirs)try{report(d);for(auto&e:list(d))if(!(e.attrs&FILE_ATTRIBUTE_DIRECTORY))add(e.path);}catch(const Error&e){log(e.text);}processes([&](DWORD,const S&p){add(p);},log);for(auto&r:runs(log))if(!r.target.empty()&&exists(r.target))add(r.target);log(L"检查电脑进程映像、Run/RunOnce 和常见落地目录顶层，共 "+num(files.size())+L" 个文件。");std::vector<Finding>out;int missing=0;for(auto&p:files){report(p);inspect(p,out,log,missing);++checked;report(p);}if(!root.empty()){log(L"检查所选 U 盘："+root);walk(root,[&](const Entry&e){if(!files.count(e.path)){report(e.path);inspect(e.path,out,log,missing);++checked;report(e.path);}},log,report);}if(missing>0)log(L"跳过 "+num(missing)+L" 个确认不存在的文件（临时进程退出等）。");return out;}
inline bool admin(){SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY;PSID sid=nullptr;BOOL yes=FALSE;if(AllocateAndInitializeSid(&authority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&sid)){CheckTokenMembership(nullptr,sid,&yes);FreeSid(sid);}return yes!=FALSE;}
inline void quarantine(const S&p,const S&expected,Journal&j){noLinks(p);Handle in(CreateFileW(xp(p).c_str(),GENERIC_READ|DELETE|FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr));if(in.h==INVALID_HANDLE_VALUE)fail(L"锁定待隔离文件："+p);if(hashHandle(in.h)!=expected)throw Error{L"文件已变化，请重新检查："+p};S dest=join(j.dir,num(++j.seq)+L".quarantine");DWORD original=attr(p);j.add(L"隔离准备",p,dest,expected+L"; attrs="+num(original));{Handle out(CreateFileW(xp(dest).c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));if(out.h==INVALID_HANDLE_VALUE)fail(L"创建隔离文件");LARGE_INTEGER z{};if(!SetFilePointerEx(in.h,z,nullptr,FILE_BEGIN))fail(L"定位文件");BYTE buf[65536];DWORD n;for(;;){if(!ReadFile(in.h,buf,sizeof(buf),&n,nullptr))fail(L"读取隔离源");if(!n)break;write(out.h,buf,n);}if(!FlushFileBuffers(out.h))fail(L"隔离文件落盘");}if(hash(dest)!=expected)throw Error{L"备份校验失败，原文件保留"};FILE_BASIC_INFO bi{};if(!GetFileInformationByHandleEx(in.h,FileBasicInfo,&bi,sizeof(bi)))fail(L"读取原属性");if(original&FILE_ATTRIBUTE_READONLY){bi.FileAttributes=original&~FILE_ATTRIBUTE_READONLY;if(!bi.FileAttributes)bi.FileAttributes=FILE_ATTRIBUTE_NORMAL;if(!SetFileInformationByHandle(in.h,FileBasicInfo,&bi,sizeof(bi)))fail(L"设置隔离属性");}FILE_DISPOSITION_INFO disposition{TRUE};if(!SetFileInformationByHandle(in.h,FileDispositionInfo,&disposition,sizeof(disposition))){DWORD err=GetLastError();bi.FileAttributes=original;SetFileInformationByHandle(in.h,FileBasicInfo,&bi,sizeof(bi));SetLastError(err);fail(L"移除已备份源文件");}j.add(L"隔离完成",p,dest,expected);}
inline S startupError(const S& action, LONG code) {
    if (code == ERROR_ACCESS_DENIED) return L"权限不足，无法" + action + L" [5]";
    return action + L"失败 [" + num(code) + L"]";
}
inline void removeRun(const RunEntry& r, Journal& j) {
    HKEY h;
    LONG rc = RegOpenKeyExW(r.hive, r.key.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE | r.view, &h);
    if (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND) {
        j.add(L"启动项已不存在", r.key, r.name, L"无需移除");
        return;
    }
    if (rc != ERROR_SUCCESS) throw Error{startupError(L"打开启动项", rc)};
    BYTE b[65536]; DWORD type = 0, n = sizeof(b) - 2;
    rc = RegQueryValueExW(h, r.name.c_str(), nullptr, &type, b, &n);
    if (rc == ERROR_FILE_NOT_FOUND) {
        RegCloseKey(h);
        j.add(L"启动项已不存在", r.key, r.name, L"无需移除");
        return;
    }
    if (rc != ERROR_SUCCESS) {
        RegCloseKey(h);
        throw Error{startupError(L"读取启动项", rc)};
    }
    if (n > sizeof(b) - 2) {
        RegCloseKey(h);
        throw Error{L"启动项数据过长，请重新检查"};
    }
    b[n] = b[n + 1] = 0;
    if (type != r.type || S((wchar_t*)b) != r.value) {
        RegCloseKey(h);
        throw Error{L"启动项内容已变化，请重新检查"};
    }
    S source = (r.hive == HKEY_LOCAL_MACHINE ? L"HKLM\\" : L"HKCU\\") + r.key;
    try { j.add(L"启动项备份", source, r.name, L"view=" + num(r.view) + L"; type=" + num(type) + L"; value=" + r.value); }
    catch (...) { RegCloseKey(h); throw; }
    rc = RegDeleteValueW(h, r.name.c_str());
    RegCloseKey(h);
    if (rc == ERROR_FILE_NOT_FOUND) {
        j.add(L"启动项已不存在", source, r.name, L"无需移除");
        return;
    }
    if (rc != ERROR_SUCCESS) throw Error{startupError(L"删除启动项", rc)};
    j.add(L"启动项已移除", source, r.name, r.value);
}
inline void clean(const std::vector<Finding>&items,Log log){NativeFs nativeFs;Journal j(data());log(L"隔离与记录目录："+j.dir);for(auto&f:items)if(f.confirmed)try{if(hash(f.path)!=f.digest)throw Error{L"文件已变化"};if(!f.link){processes([&](DWORD pid,const S&p){if(same(p,f.path)){Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|SYNCHRONIZE,FALSE,pid));if(!h.h)fail(L"打开恶意进程");wchar_t b[32768];DWORD n=32768;if(!QueryFullProcessImageNameW(h.h,0,b,&n)||!same(S(b,n),f.path)||!known(S(b,n)))throw Error{L"进程复核失败"};j.add(L"结束进程前",p,L"",num(pid));if(!TerminateProcess(h.h,1)||WaitForSingleObject(h.h,5000)!=WAIT_OBJECT_0)fail(L"结束恶意进程");log(L"已结束确认命中的进程："+num(pid));}},log);for(auto&r:runs(log))if(!r.target.empty()&&same(r.target,f.path))try{removeRun(r,j);}catch(const Error&e){j.add(L"启动项移除失败",r.name,L"",e.text);log(L"启动项移除失败："+S(r.hive==HKEY_LOCAL_MACHINE?L"HKLM\\":L"HKCU\\")+r.key+L" [view="+num(r.view)+L"] / "+r.name+L" — "+e.text);}}quarantine(f.path,f.digest,j);log(L"已隔离："+f.path);}catch(const Error&e){j.add(L"清理失败",f.path,L"",e.text);log(L"清理失败："+f.path+L" — "+e.text);}}
struct Move{S source,dest,signature;DWORD attrs;};struct Plan{S root,container;DWORD serial;std::vector<Move>items;std::vector<S> skipped;bool partial=false;};
inline bool systemName(const S&p){auto n=lower(name(p));return n==L"system volume information"||n==L"$recycle.bin";}
inline DWORD volume(const S&root){DWORD s=0;if(!GetVolumeInformationW(root.substr(0,3).c_str(),nullptr,0,&s,nullptr,nullptr,nullptr,0))fail(L"确认卷标识");return s;}
inline S treeSignature(const S&p,size_t&count,int depth=0){if(depth>128||++count>200000)throw Error{L"恢复目录过深或项目过多，已停止"};noLinks(p);DWORD a=attr(p);S s=quote(p)+L":"+num(a);if(a&FILE_ATTRIBUTE_DIRECTORY){for(auto&e:list(p))s+=treeSignature(e.path,count,depth+1);}else{if(suspicious(p)||known(p)||(extension(p,L".lnk")&&size(p)<=1048576&&wormLink(p)))throw Error{L"目录内有病毒或可疑入口，请先处理："+p};WIN32_FILE_ATTRIBUTE_DATA d;if(!GetFileAttributesExW(xp(p).c_str(),GetFileExInfoStandard,&d))fail(L"获取恢复元数据");s+=L":"+num(size(p))+L":"+num(((uint64_t)d.ftLastWriteTime.dwHighDateTime<<32)|d.ftLastWriteTime.dwLowDateTime);}return s;}
inline S unique(const S&p,std::set<S>&reserved){S r=p;size_t i=1;S n=name(p);auto dot=n.find_last_of(L'.');if(dot==S::npos||dot==0)dot=n.size();while(exists(r)||reserved.count(lower(r)))r=join(parent(p),n.substr(0,dot)+L"（恢复"+num(i++)+L"）"+n.substr(dot));reserved.insert(lower(r));return r;}
inline Plan plan(const S&root0,const S&container0,bool test=false){S root=full(root0),container=full(container0);noLinks(root);noLinks(container);if(!same(parent(container),root))throw Error{L"只允许恢复根目录的直接子目录"};if(!(attr(container)&FILE_ATTRIBUTE_DIRECTORY)||systemName(container))throw Error{L"拒绝非目录或系统目录"};if(!test){if(root.size()!=3||GetDriveTypeW(root.c_str())!=DRIVE_REMOVABLE)throw Error{L"仅支持可移动磁盘，拒绝固定盘及网络盘"};wchar_t win[MAX_PATH];GetWindowsDirectoryW(win,MAX_PATH);if(towlower(win[0])==towlower(root[0]))throw Error{L"拒绝系统盘"};}Plan p{root,container,volume(root),{},{},false};std::set<S>reserved;size_t count=0;for(auto&e:list(container)){noLinks(e.path);if(!(e.attrs&FILE_ATTRIBUTE_DIRECTORY)&&(suspicious(e.path)||extension(e.path,L".lnk")))continue;auto sig=treeSignature(e.path,count);p.items.push_back({e.path,unique(join(root,name(e.path)),reserved),sig,e.attrs});}return p;}
inline void recover(const Plan&p,Journal&j,Log log,bool test=false){auto fresh=plan(p.root,p.container,test);if(fresh.serial!=p.serial||fresh.items.size()!=p.items.size())throw Error{L"磁盘或目录已变化，请重新预览"};for(size_t i=0;i<p.items.size();i++)if(!same(fresh.items[i].dest,p.items[i].dest)||fresh.items[i].signature!=p.items[i].signature)throw Error{L"目录内容已变化，请重新预览"};for(auto&m:p.items){noLinks(p.root);size_t count=0;if(volume(p.root)!=p.serial||treeSignature(m.source,count)!=m.signature)throw Error{L"恢复前校验失败，已停止"};if(exists(m.dest))throw Error{L"目标已存在，拒绝覆盖"};j.add(L"移动准备",m.source,m.dest,num(m.attrs));if(!MoveFileExW(xp(m.source).c_str(),xp(m.dest).c_str(),MOVEFILE_WRITE_THROUGH))fail(L"移动文件："+m.source);j.add(L"移动完成",m.source,m.dest,num(m.attrs));DWORD a=m.attrs&~(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);if(!a)a=FILE_ATTRIBUTE_NORMAL;if(!SetFileAttributesW(xp(m.dest).c_str(),a))fail(L"恢复可见属性："+m.dest);log(L"已恢复："+m.dest);}log(L"恢复完成；跳过项与原目录保留。记录："+j.dir);}
} // namespace usb
