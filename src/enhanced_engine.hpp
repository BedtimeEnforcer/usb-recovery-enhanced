#pragma once
#include "enhanced_rules.hpp"
#include "review_registry.hpp"

namespace enhanced {
using namespace usb;
constexpr uint64_t HASH_LIMIT = 64ULL * 1024 * 1024;
constexpr size_t ENTRY_LIMIT = 200000;

inline bool has(const S& s, const S& token) { return s.find(token) != S::npos; }
inline bool localAbsolute(const S& s) {
    return s.size() >= 3 && ((s[0] >= L'A' && s[0] <= L'Z') || (s[0] >= L'a' && s[0] <= L'z')) && s[1] == L':' && s[2] == L'\\';
}
inline bool riskyExtension(const S& p) {
    for (const auto* ext : {L".exe", L".dll", L".scr", L".com", L".cpl", L".lnk", L".vbs", L".vbe", L".js", L".jse", L".wsf", L".wsh", L".ps1", L".bat", L".cmd", L".hta", L".msi"})
        if (extension(p, ext)) return true;
    return false;
}
inline S decodeText(const std::vector<BYTE>& b) {
    if (b.size() >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF))) {
        S s;
        for (size_t i=2; i+1<b.size(); i+=2) s += wchar_t(b[0] == 0xFF ? b[i] | (b[i+1]<<8) : (b[i]<<8) | b[i+1]);
        return s;
    }
    size_t start = b.size() >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF ? 3 : 0;
    if (start == b.size()) return L"";
    const char* data = reinterpret_cast<const char*>(b.data()+start);
    int count = int(b.size()-start);
    UINT cp = CP_UTF8; DWORD flags = MB_ERR_INVALID_CHARS;
    int n = MultiByteToWideChar(cp, flags, data, count, nullptr, 0);
    if (!n) { cp=CP_ACP; flags=0; n=MultiByteToWideChar(cp,flags,data,count,nullptr,0); }
    S s(n, 0);
    if (n) MultiByteToWideChar(cp,flags,data,count,&s[0],n);
    return s;
}

struct LinkData { S target, relative, work, args; };
inline LinkData parseLink(const std::vector<BYTE>& b) {
    LinkData r;
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
    return r;
}
inline S linkHint(const LinkData& link) {
    const S cmd=lower(link.target+L" "+link.relative+L" "+link.args);
    if (has(cmd,L".trashes\\") && (has(cmd,L".js") || has(cmd,L".jse")))
        return L"Bondat 风格线索：快捷方式引用 .Trashes 中脚本；需核查，先清电脑脚本驻留，再恢复隐藏文件。";
    if (has(cmd,L"\u00a0") && has(cmd,L"recycler.bin") && (has(cmd,L".dat") || has(cmd,L"x32dbg") || has(cmd,L"rundll32") || has(cmd,L"aug.exe")))
        return L"PlugX USB 风格线索：特殊空白目录、RECYCLER.BIN 与载荷引用组合；需复查侧载 DLL、任务和服务。";
    if ((has(cmd,L"msiexec") && (has(cmd,L"http://") || has(cmd,L"https://"))) ||
        (has(cmd,L"cmd") && has(cmd,L"type ") && (has(cmd,L"|cmd") || has(cmd,L"| cmd"))))
        return L"Raspberry Robin 风格线索：远程安装或 type/cmd 管道；普通安装链接也可能命中，需核查 RunOnce 及真实载荷。";
    return L"";
}
inline bool scriptHint(const S& input) {
    S s=lower(input);
    return has(s,L"scripting.filesystemobject") && has(s,L"wscript.shell") && has(s,L"drivetype") &&
           has(s,L"drives") && has(s,L"createshortcut") && has(s,L"attributes") &&
           (has(s,L"regwrite") || has(s,L"currentversion\\run"));
}
inline bool autorunHint(const S& input) {
    S text=lower(input); bool in=false;
    size_t pos=0;
    while(pos<text.size()) {
        size_t end=text.find(L'\n',pos); if(end==S::npos)end=text.size();
        S line=text.substr(pos,end-pos); pos=end+1;
        auto first=line.find_first_not_of(L" \t\r"); if(first==S::npos)continue;
        line=line.substr(first); if(line[0]==L';' || line[0]==L'#')continue;
        if(line[0]==L'[') { auto close=line.find(L']'); in=close!=S::npos && line.substr(0,close+1)==L"[autorun]"; continue; }
        if(!in)continue;
        auto eq=line.find(L'='); if(eq==S::npos)continue;
        S key=line.substr(0,eq); auto last=key.find_last_not_of(L" \t"); key=key.substr(0,last==S::npos?0:last+1);
        if(key!=L"open" && key!=L"shellexecute" && !(key.rfind(L"shell\\",0)==0 && extension(key,L"\\command")))continue;
        S value=line.substr(eq+1);
        for(auto token:{L"wscript",L"cscript",L"powershell",L".vbs",L".vbe",L".js",L".jse",L".wsf",L".ps1",L".hta"}) if(has(value,token))return true;
    }
    return false;
}
inline bool disguised(const S& p) {
    S n=lower(name(p));
    for(auto tail:{L".exe",L".scr",L".com"}) if(extension(n,tail)) {
        n.resize(n.size()-wcslen(tail));
        for(auto ext:{L".pdf",L".doc",L".docx",L".xls",L".xlsx",L".jpg",L".png",L".txt"})if(extension(n,ext))return true;
    }
    return false;
}
inline bool frozenHint(const std::vector<BYTE>& b) {
    if(b.size()<64 || field(b,0,2)!=0x5A4D)return false;
    size_t pe=field(b,60,4); if(pe>b.size() || b.size()-pe<4 || field(b,pe,4)!=0x4550)return false;
    std::string s(b.begin(),b.end());
    for(auto token:{"path_symantec","symantec_dir","name_svchost","run_cmd","usb_dll_name","name_mutex"})if(s.find(token)==std::string::npos)return false;
    return true;
}

inline bool underPath(const S& path,const S& root) {
    S p=lower(full(path)),r=lower(full(root));return p==r || p.rfind(r+(r.back()==92?S():S(1,wchar_t(92))),0)==0;
}
inline bool residualName(const S& p) {auto n=lower(name(p));return n==L"tbtnds.dat" || n==L"tbtcmds.dat";}
inline bool numericExe(const S& p) {
    S n=lower(name(p));if(n.size()<=4 || !extension(n,L".exe"))return false;
    for(size_t i=0;i<n.size()-4;++i)if(n[i]<L'0'||n[i]>L'9')return false;
    return true;
}
inline S fileTimeText(FILETIME time) {
    SYSTEMTIME utc{},local{};if(!FileTimeToSystemTime(&time,&utc) || !SystemTimeToTzSpecificLocalTime(nullptr,&utc,&local))return L"未知";
    wchar_t b[64];swprintf(b,64,L"%04u-%02u-%02u %02u:%02u:%02u",local.wYear,local.wMonth,local.wDay,local.wHour,local.wMinute,local.wSecond);return b;
}
inline S reviewFileText(const Finding& f) {
    return L"路径："+f.path+L"\r\n大小："+num(f.fileSize)+L" 字节\r\nSHA-256："+(f.digest.empty()?L"未计算（超过上限或读取失败）":f.digest)+L"\r\n创建时间："+fileTimeText(f.created)+L"\r\n判断依据："+f.reason;
}
class Scanner {
    const std::vector<HashRule>& table;
public:
    size_t oversized=0, contentSkipped=0;
    S selfDigest;
    std::vector<S> tempRoots;
    explicit Scanner(const std::vector<HashRule>& catalog=rules()) : table(catalog) {}
    void inspect(const S& p, std::vector<Finding>& out, Log log) {
        try {
            noLinks(p); auto n=size(p);
            std::vector<Finding> base; int missing=0;
            usb::inspect(p,base,log,missing);
            if(!base.empty() && base[0].confirmed) { out.push_back(base[0]); return; }
            S digest;
            if(n<=HASH_LIMIT) {
                digest=hash(p);
                if(const auto* rule=matchDigest(digest,table)) {
                    out.push_back({p,digest,L"SHA-256 精确命中："+rule->family+L"；方案："+rule->solution+L"；来源："+rule->source,true,false});
                    return;
                }
            } else ++oversized;
            ReviewKind kind=ReviewKind::None;
            if(residualName(p))kind=ReviewKind::ResidualName;
            else if(numericExe(p))for(const auto& temp:tempRoots)if(underPath(p,temp)){kind=ReviewKind::NumericTemp;break;}
            if(kind!=ReviewKind::None) {
                WIN32_FILE_ATTRIBUTE_DATA info{};if(!GetFileAttributesExW(xp(p).c_str(),GetFileExInfoStandard,&info))fail(L"读取核查元数据");
                S why=kind==ReviewKind::ResidualName?L"残留文件名匹配；仅名称不能确认病毒，需逐项人工确认":L"Temp 纯数字 EXE，需甄别；未知哈希不自动隔离";
                out.push_back({p,digest,why,false,false,kind,n,info.ftCreationTime});return;
            }
            // 自身携带静态规则文本；相同字节的自身副本不作为内容线索。
            if(!selfDigest.empty() && digest==selfDigest)return;
            S reason;
            if(disguised(p))reason=L"双扩展名可执行文件，可能伪装文档；仅凭名称不能确认病毒，请核查来源。";
            if(n<=1048576) {
                if(extension(p,L".lnk")) reason=linkHint(parseLink(bytes(p)));
                else if(lower(name(p))==L"autorun.inf" && autorunHint(decodeText(bytes(p)))) reason=L"Autorun 启动键引用脚本或脚本宿主；需核查目标，关闭自动运行并完整扫描。";
                else if(extension(p,L".vbs") || extension(p,L".vbe") || extension(p,L".js") || extension(p,L".jse") || extension(p,L".wsf") || extension(p,L".ps1")) {
                    if(scriptHint(decodeText(bytes(p)))) reason=L"脚本包含 USB 枚举、隐藏、快捷方式和驻留组合线索；仅供核查，不执行或自动隔离。";
                } else if(n>=64 && frozenHint(bytes(p))) reason=L"FROZENHILL 配置字段组合线索（非完整 YARA）；需核查，不自动隔离。";
            } else ++contentSkipped;
            if(!reason.empty()) out.push_back({p,digest,reason,false,extension(p,L".lnk")});
            else if(!base.empty())out.push_back(base[0]);
        } catch(const Error& e) { log(L"未检查："+p+L" — "+e.text); }
    }
};

// Windows 参数拆分仅用于提取显式绝对本地路径，不解释或执行命令。
inline std::vector<S> referencedPaths(const S& command) {
    wchar_t expanded[32768]; DWORD n=ExpandEnvironmentStringsW(command.c_str(),expanded,32768);
    if(!n || n>32768)return {};
    int argc=0; wchar_t** argv=CommandLineToArgvW(expanded,&argc); if(!argv)return {};
    std::vector<S> paths;
    S host=argc ? lower(name(S(argv[0]))) : L"";
    for(int i=0;i<argc;++i) {
        S token=argv[i];
        // rundll32 允许任意载荷扩展名；逗号是导出名分隔符，其他命令不猜测。
        if(i>0 && (host==L"rundll32.exe" || host==L"rundll32")) {
            auto comma=token.find(L',');if(comma!=S::npos)token.resize(comma);
        }
        if(localAbsolute(token) && GetDriveTypeW(token.substr(0,3).c_str())!=DRIVE_REMOTE && token.find_first_of(L"*?<>|")==S::npos) {
            try { paths.push_back(full(token)); } catch(const Error&) {}
        }
    }
    LocalFree(argv);
    return paths;
}
inline bool references(const S& command, const S& path) {
    for(const auto& p:referencedPaths(command))if(same(p,path))return true;
    return false;
}
struct WalkBudget { size_t entries=0; bool limited=false; };
inline void boundedWalk(const S& root, const std::function<void(const Entry&)>& visit, Log log, WalkBudget& budget, const std::vector<S>& excluded={}, Log directory={}) {
    std::vector<std::pair<S,int>> stack{{root,0}};
    while(!stack.empty() && !budget.limited) {
        auto current=stack.back(); stack.pop_back();
        bool skip=false; for(const auto& p:excluded)if(same(current.first,p)){skip=true;break;} if(skip)continue;
        if(current.second>128){log(L"达到目录深度 128 上限，检查不完整："+current.first);continue;}
        if(directory)directory(current.first);
        try {
            for(const auto& e:list(current.first)) {
                if(++budget.entries>ENTRY_LIMIT){budget.limited=true;log(L"达到 200000 项上限，检查不完整。");return;}
                if(e.attrs&FILE_ATTRIBUTE_REPARSE_POINT){log(L"跳过链接："+e.path);continue;}
                if(e.attrs&FILE_ATTRIBUTE_DIRECTORY) {
                    S n=lower(name(e.path)); if(n!=L"system volume information" && n!=L"$recycle.bin")stack.push_back({e.path,current.second+1});
                } else visit(e);
            }
        } catch(const Error& e){log(L"未读取目录："+current.first+L" — "+e.text);}
    }
}
inline std::vector<Finding> scan(const S& root, Log log, ScanProgress progress={}) {
    NativeFs native;
    size_t checked=0;
    auto report=[&](const S& p){if(progress)progress(p,checked);};
    report(L"正在准备检查");
    if(!root.empty() && (full(root).size()!=3 || GetDriveTypeW(root.c_str())!=DRIVE_REMOVABLE))throw Error{L"加强版仅检查所选可移动卷，拒绝固定盘和网络盘"};
    Scanner scanner; wchar_t own[32768]; DWORD n=GetModuleFileNameW(nullptr,own,32768);
    if(n && n<32768)try{scanner.selfDigest=hash(S(own,n));}catch(const Error&){}
    std::set<S> seen; std::vector<Finding> out;
    auto inspect=[&](const S& p){if(!localAbsolute(p))return; if(seen.insert(lower(full(p))).second){report(p);scanner.inspect(p,out,log);++checked;report(p);}};
    log(L"加强版规则 "+S(RULE_VERSION)+L"：15 条精确指纹 + 原版 LNK + 7 类组合线索；新增家族未做真实感染测试。");
    wchar_t windows[MAX_PATH],temp[MAX_PATH]; GetWindowsDirectoryW(windows,MAX_PATH); GetTempPathW(MAX_PATH,temp);
    scanner.tempRoots.push_back(temp);
    std::vector<S> top{windows}, recursive{temp}, excluded;
    for(int id:{CSIDL_PROFILE,CSIDL_APPDATA,CSIDL_LOCAL_APPDATA,CSIDL_STARTUP,CSIDL_COMMON_STARTUP,CSIDL_COMMON_APPDATA,CSIDL_COMMON_DOCUMENTS}) {
        try {
            S p=folder(id);
            if(id==CSIDL_PROFILE)top.push_back(p);
            else if(id==CSIDL_COMMON_DOCUMENTS)recursive.push_back(parent(p));
            else recursive.push_back(p);
            if(id==CSIDL_LOCAL_APPDATA)excluded.push_back(join(p,L"UsbRecovery"));
        } catch(const Error& e){log(e.text);}
    }
    processes([&](DWORD,const S& p){inspect(p);},log);
    for(const auto& r:runs(log))for(const auto& p:referencedPaths(r.value))if(exists(p) && !(attr(p)&FILE_ATTRIBUTE_DIRECTORY))inspect(p);
    for(const auto& dir:top)try{report(dir);for(const auto& e:list(dir))if(!(e.attrs&FILE_ATTRIBUTE_DIRECTORY))inspect(e.path);}catch(const Error& e){log(e.text);}
    // 每个本机范围共用预算，U 盘另有独立预算，避免本机上限吞掉 U 盘检查。
    WalkBudget host;
    std::sort(recursive.begin(),recursive.end(),[](const S& a,const S& b){return a.size()<b.size();});
    std::vector<S> traversed;
    for(const auto& dir:recursive) {
        S path=lower(full(dir)); bool covered=false;
        for(const auto& prior:traversed)if(path==prior || path.rfind(prior+L"\\",0)==0){covered=true;break;}
        if(!covered && exists(dir)) { traversed.push_back(path); boundedWalk(dir,[&](const Entry& e){inspect(e.path);},log,host,excluded,report); }
    }
    if(!root.empty()) { log(L"检查所选 U 盘："+root); WalkBudget usbBudget; boundedWalk(root,[&](const Entry& e){inspect(e.path);},log,usbBudget,{},report); }
    if(scanner.oversized)log(L"未计算哈希："+num(scanner.oversized)+L" 个文件超过 64 MiB；这些文件不在精确指纹覆盖范围。");
    if(scanner.contentSkipped)log(L"未作内容/LNK 解析："+num(scanner.contentSkipped)+L" 个文件超过 1 MiB（小于等于 64 MiB 的文件已作哈希检查）。");
    log(L"加强版检查结束，共处理 "+num(seen.size())+L" 个不同路径。隔离目录不参与递归。");
    return out;
}

struct HostActions { std::function<void(const Finding&,Journal&,Log)> stop, persistence; };
inline void stopExact(const Finding& f, Journal& j, Log log) {
    processes([&](DWORD pid,const S& path){
        if(!same(path,f.path))return;
        Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|SYNCHRONIZE,FALSE,pid));
        if(!h.h)fail(L"打开恶意进程");
        wchar_t actual[32768]; DWORD n=32768;
        if(!QueryFullProcessImageNameW(h.h,0,actual,&n) || !same(S(actual,n),f.path) || hash(S(actual,n))!=f.digest)throw Error{L"进程复核失败"};
        j.add(L"结束进程前",path,L"",num(pid));
        if(!TerminateProcess(h.h,1) || WaitForSingleObject(h.h,5000)!=WAIT_OBJECT_0)fail(L"结束恶意进程");
        log(L"已结束确认命中的进程："+num(pid));
    },log);
}
inline void removeReferences(const Finding& f, Journal& j, Log log) {
    for(const auto& r:runs(log))if(references(r.value,f.path)) {
        try{removeRun(r,j);log(L"已移除精确关联启动项："+r.name);}
        catch(const Error& e){j.add(L"启动项移除失败",r.name,L"",e.text);log(L"启动项移除失败（已跳过，不影响文件隔离）："+r.name+L" — "+e.text);}
    }
}
inline void cleanOne(const Finding& f, Journal& j, Log log, const HostActions& actions, const std::vector<HashRule>& table=rules()) {
    if(!f.confirmed) { log(L"需核查项保留："+f.path); return; }
    try {
        noLinks(f.path);
        if(size(f.path)>HASH_LIMIT || hash(f.path)!=f.digest)throw Error{L"文件已变化或超过处理上限，请重新检查"};
        const auto* rule=matchDigest(f.digest,table);
        const bool originalLink=f.link && extension(f.path,L".lnk") && wormLink(f.path);
        if(!rule && !originalLink)throw Error{L"未命中当前内置规则，拒绝仅凭确认标记隔离"};
        if(!originalLink) {
            if(actions.stop)actions.stop(f,j,log);
            if(actions.persistence)actions.persistence(f,j,log);
        }
        if(rule && rule->digest!=HASH)log(L"处置待复核："+rule->family+L" — "+rule->solution);
        // 最后再次锁定并复核同一哈希，继承原版的备份校验后删除。
        quarantine(f.path,f.digest,j);
        log(L"已隔离："+f.path);
    } catch(const Error& e){j.add(L"清理失败",f.path,L"",e.text);log(L"清理失败："+f.path+L" — "+e.text);}
}
inline bool quarantineReviewed(const Finding& f,bool consent,Journal& j,Log log) {
    if(!consent){log(L"用户保留核查文件："+f.path);return false;}
    if(f.review!=ReviewKind::ResidualName || !residualName(f.path))throw Error{L"该线索不在可人工确认隔离范围"};
    noLinks(f.path);
    if(f.digest.empty() || size(f.path)>HASH_LIMIT || size(f.path)!=f.fileSize || hash(f.path)!=f.digest)throw Error{L"核查文件已变化或无法复核，请重新检查"};
    WIN32_FILE_ATTRIBUTE_DATA info{};if(!GetFileAttributesExW(xp(f.path).c_str(),GetFileExInfoStandard,&info))fail(L"读取核查元数据");
    if(CompareFileTime(&info.ftCreationTime,&f.created)!=0)throw Error{L"核查文件已替换，请重新检查"};
    j.add(L"用户逐项确认隔离",f.path,L"",f.reason);
    quarantine(f.path,f.digest,j);log(L"已隔离："+f.path);return true;
}
inline void clean(const std::vector<Finding>& items, Log log) {
    NativeFs native; Journal j(data()); log(L"隔离与记录目录："+j.dir);
    HostActions actions{stopExact,removeReferences};
    for(const auto& f:items)cleanOne(f,j,log,actions);
}

inline bool numeric(const S& s) { if(s.empty() || s.size()>10)return false; for(auto c:s)if(c<L'0'||c>L'9')return false; return true; }
inline bool allowedContainer(const S& root,const S& container) {
    return same(parent(container),root) || (same(parent(parent(container)),root) && lower(name(parent(container)))==L".trashes" && numeric(name(container)));
}
inline std::vector<S> recoveryFolders(const S& root) {
    std::vector<S> result;
    for(const auto& e:list(root))if((e.attrs&FILE_ATTRIBUTE_DIRECTORY) && !(e.attrs&FILE_ATTRIBUTE_REPARSE_POINT) && !systemName(e.path)) {
        if((e.attrs&FILE_ATTRIBUTE_HIDDEN) || name(e.path)==L"\uffff" || lower(name(e.path))==L".trashes")result.push_back(e.path);
        if(lower(name(e.path))==L".trashes") {
            for(const auto& child:list(e.path))if((child.attrs&FILE_ATTRIBUTE_DIRECTORY) && !(child.attrs&FILE_ATTRIBUTE_REPARSE_POINT) && numeric(name(child.path))) {
                if(result.size()>=128)throw Error{L"隐藏恢复候选过多，请人工核查"};
                result.push_back(child.path);
            }
        }
    }
    return result;
}
inline S recoverySignature(const S& p, size_t& count, int depth=0) {
    if(depth>128 || ++count>ENTRY_LIMIT)throw Error{L"恢复目录过深或项目过多"};
    noLinks(p); DWORD a=attr(p); S sig=quote(p)+L":"+num(a);
    if(a&FILE_ATTRIBUTE_DIRECTORY) {
        for(const auto& e:list(p))sig+=recoverySignature(e.path,count,depth+1);
    } else {
        if(riskyExtension(p) || suspicious(p))throw Error{L"目录含可执行文件、脚本或快捷方式，已停止恢复，请先人工核查："+p};
        auto n=size(p);
        if(n<=HASH_LIMIT && matchDigest(hash(p)))throw Error{L"目录内有精确命中载荷，请先隔离："+p};
        if(lower(name(p))==L"autorun.inf" && n<=1048576 && autorunHint(decodeText(bytes(p))))throw Error{L"目录内有可疑 Autorun 入口，请先核查："+p};
        WIN32_FILE_ATTRIBUTE_DATA d; if(!GetFileAttributesExW(xp(p).c_str(),GetFileExInfoStandard,&d))fail(L"读取恢复元数据");
        sig+=L":"+num(n)+L":"+num(((uint64_t)d.ftLastWriteTime.dwHighDateTime<<32)|d.ftLastWriteTime.dwLowDateTime);
    }
    return sig;
}
inline Plan plan(const S& root0,const S& container0,bool test=false) {
    S root=full(root0),container=full(container0); noLinks(root);noLinks(container);
    if(!allowedContainer(root,container) || !(attr(container)&FILE_ATTRIBUTE_DIRECTORY) || systemName(container))throw Error{L"只允许根目录容器或 .Trashes 下一级数字目录"};
    if(!test) {
        if(root.size()!=3 || GetDriveTypeW(root.c_str())!=DRIVE_REMOVABLE)throw Error{L"仅允许可移动磁盘"};
        wchar_t windows[MAX_PATH];GetWindowsDirectoryW(windows,MAX_PATH);if(towlower(windows[0])==towlower(root[0]))throw Error{L"拒绝系统盘"};
    }
    Plan p{root,container,volume(root),{}};std::set<S> reserved;size_t count=0;
    for(const auto& e:list(container)) {
        noLinks(e.path);
        if(!(e.attrs&FILE_ATTRIBUTE_DIRECTORY) && (riskyExtension(e.path) || suspicious(e.path)))continue;
        auto signature=recoverySignature(e.path,count);
        p.items.push_back({e.path,unique(join(root,name(e.path)),reserved),signature,e.attrs});
    }
    return p;
}
inline void recover(const Plan& p,Journal& j,Log log,bool test=false) {
    auto fresh=enhanced::plan(p.root,p.container,test);
    if(fresh.serial!=p.serial || fresh.items.size()!=p.items.size())throw Error{L"磁盘或目录已变化，请重新预览"};
    for(size_t i=0;i<p.items.size();++i)if(!same(fresh.items[i].dest,p.items[i].dest) || fresh.items[i].signature!=p.items[i].signature)throw Error{L"目录内容已变化，请重新预览"};
    for(const auto& m:p.items) {
        noLinks(p.root);size_t count=0;
        if(volume(p.root)!=p.serial || recoverySignature(m.source,count)!=m.signature)throw Error{L"恢复前复核失败"};
        if(exists(m.dest))throw Error{L"目标已存在，拒绝覆盖"};
        j.add(L"移动准备",m.source,m.dest,num(m.attrs));
        if(!MoveFileExW(xp(m.source).c_str(),xp(m.dest).c_str(),MOVEFILE_WRITE_THROUGH))fail(L"恢复移动文件");
        j.add(L"移动完成",m.source,m.dest,num(m.attrs));
        DWORD a=m.attrs&~(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);if(!a)a=FILE_ATTRIBUTE_NORMAL;
        if(!SetFileAttributesW(xp(m.dest).c_str(),a))fail(L"恢复可见属性");
        log(L"已恢复："+m.dest);
    }
    log(L"恢复完成；被跳过的可执行文件和脚本保留原处。记录："+j.dir);
}
} // namespace enhanced
