#pragma once
#include "workflow.hpp"

namespace enhanced {
enum class RunMode { Full, UsbOnly };
struct DiskTarget { S root,label; DWORD serial=0; };
inline std::vector<DiskTarget> removableTargets() {
    std::vector<DiskTarget> result;DWORD bits=GetLogicalDrives();
    for(int i=0;i<26;++i)if(bits&(1u<<i)) {
        S root=L"A:\\";root[0]+=i;if(GetDriveTypeW(root.c_str())!=DRIVE_REMOVABLE)continue;
        wchar_t label[256]{};DWORD serial=0;
        if(GetVolumeInformationW(root.c_str(),label,256,&serial,nullptr,nullptr,nullptr,0))result.push_back({root,label,serial});
    }
    return result;
}
inline std::vector<S> fixedTargets() {
    std::vector<S> result;DWORD bits=GetLogicalDrives();
    for(int i=0;i<26;++i)if(bits&(1u<<i)){S root=L"A:\\";root[0]+=i;if(GetDriveTypeW(root.c_str())==DRIVE_FIXED)result.push_back(root);}
    return result;
}
inline void validateTarget(const DiskTarget& target,bool test=false) {
    if(target.root.empty() || (!test && (full(target.root).size()!=3 || GetDriveTypeW(target.root.c_str())!=DRIVE_REMOVABLE)))throw Error{L"U 盘已拔出，请重新选择"};
    noLinks(target.root);if(volume(target.root)!=target.serial)throw Error{L"U 盘已更换，请重新选择"};
}
inline void initializeUsbOnly(ScanSession& scan,const DiskTarget& target,bool test=false) {
    validateTarget(target,test);scan=ScanSession{};scan.root=target.root;scan.serial=target.serial;
    scan.scanner.usbRoot=target.root;
    ScanGroup group{L"U盘专杀",true,true,{}, {}, {}};addScanRoot(group,target.root);scan.groups.push_back(std::move(group));
    scan.initialized=true;
}
inline void addFixedDisks(ScanSession& scan,const std::vector<S>& disks) {
    // Process / Run references may point into a USB. Its own volume-bound scan owns
    // those files, avoiding a second cleanup attempt after host quarantine.
    auto onFixed=[&](const S& path){for(const auto& disk:disks)if(underPath(path,disk))return true;return false;};
    for(auto& prior:scan.groups) {
        prior.direct.erase(std::remove_if(prior.direct.begin(),prior.direct.end(),[&](const Entry& entry){return !onFixed(entry.path);}),prior.direct.end());
        prior.directories.erase(std::remove_if(prior.directories.begin(),prior.directories.end(),[&](const std::shared_ptr<DirectoryCursor>& cursor){return !onFixed(cursor->path);}),prior.directories.end());
        prior.roots.erase(std::remove_if(prior.roots.begin(),prior.roots.end(),[&](const S& path){return !onFixed(path);}),prior.roots.end());
    }
    ScanGroup group{L"本机全部固定磁盘",false,false,{}, {}, {}};
    for(const auto& disk:disks)addScanRoot(group,disk);
    scan.groups.push_back(std::move(group));
}
struct OneClickResult {
    RunMode mode=RunMode::Full;
    Workflow host;
    std::vector<Workflow> usbs;
    std::vector<S> issues;
    std::vector<S> restoredPaths,visiblePaths,removedContainers;
    size_t checked=0,isolated=0,restored=0,skipped=0,unresolved=0;
    size_t recoveryFailures=0;
    bool stopped=false;
};
inline bool automaticFinding(const Finding& finding) {
    return finding.confirmed || finding.review==ReviewKind::KnownHash;
}
// USB-only processing supplies no host actions, including during recurrence checks.
inline void treatAutomatic(Workflow& w,bool host,Journal& journal,Log log,
    const std::vector<HashRule>& catalog=rules(),const HostActions* testActions=nullptr,
    const std::function<bool()>& cancel={}) {
    const HostActions noHost{};auto found=w.scan.findings;
    for(const auto& f:found){if(cancel && cancel())return;
        if(automaticFinding(f))treatFinding(f,true,w,journal,log,host?testActions:&noHost,catalog);
        else log(L"可疑项保留，未自动删除："+f.path);
    }
}
inline void recheckAutomatic(Workflow& w,bool host,Log log,unsigned observations=3,DWORD interval=1000) {
    if(w.treatment.isolated.empty())return;
    std::function<std::vector<S>()> noProcesses;
    if(!host)noProcesses=[]{return std::vector<S>{};};
    recheckTreatment(w,log,observations,interval,exists,noProcesses);
}
inline void requireHostReady(const Workflow& host) {
    if(!host.scan.initialized || !host.scan.complete || host.scan.cancelled)
        throw Error{L"电脑扫描尚未结束，暂未恢复 U 盘文件"};
    if(host.treatment.blocked())throw Error{L"电脑病毒未清理完成，暂未恢复 U 盘文件"};
    for(const auto& f:host.scan.findings)if(automaticFinding(f))throw Error{L"电脑仍有已知病毒，暂未恢复 U 盘文件"};
}
inline RecoveryContext automaticRecoveryContext(const Workflow& w) {
    auto context=w.recovery();
    // Unreadable unrelated entries are diagnostics, not proof of a remaining virus.
    // Each recovery candidate is separately read, checked and revalidated by plan/recover.
    context.criticalComplete=w.scan.initialized && w.scan.complete && !w.scan.cancelled;
    return context;
}
inline std::vector<S> automaticRecoveryFolders(const S& root,Log log,const std::function<bool()>& cancel={}) {
    std::vector<S> result;size_t checked=0;
    std::function<void(const S&,int)> visit=[&](const S& path,int depth){
        if(cancel && cancel())return;
        if(depth>128 || ++checked>ENTRY_LIMIT)throw Error{L"恢复目录过深或项目过多"};
        noLinks(path);
        std::vector<Entry> entries;
        try{entries=list(path);}catch(const Error& error){log(error.text);return;}
        for(const auto& entry:entries) {
            if(cancel && cancel())return;
            if(++checked>ENTRY_LIMIT)throw Error{L"恢复项目过多"};
            if(!(entry.attrs&FILE_ATTRIBUTE_DIRECTORY) || (entry.attrs&FILE_ATTRIBUTE_REPARSE_POINT) || systemName(entry.path))continue;
            if(specialRecoveryContainer(root,entry.path) || (same(path,root) && (entry.attrs&FILE_ATTRIBUTE_HIDDEN)))result.push_back(entry.path);
            visit(entry.path,depth+1);
        }
    };
    visit(root,0);return result;
}
inline void recoverAutomatic(Workflow& w,Journal& journal,Log log,OneClickResult& result,bool test=false,
    const std::function<bool()>& cancel={}) {
    auto context=automaticRecoveryContext(w);requireContext(context,w.scan.root,volume(w.scan.root));
    const S root=w.scan.root;
    auto candidates=automaticRecoveryFolders(root,log,cancel);
    // Empty nested wrappers before an ancestor is moved, keeping every destination at the USB root.
    std::sort(candidates.begin(),candidates.end(),[](const S& a,const S& b){return a.size()>b.size();});
    for(const auto& path:candidates) {
        if(cancel && cancel()){result.stopped=true;return;}
        try {
            auto current=automaticRecoveryContext(w);requireContext(current,root,volume(root));
            bool container=specialRecoveryContainer(root,path);
            if(container) {
                auto preview=plan(root,path,test,true,true);
                result.skipped+=preview.skipped.size();for(const auto& entry:preview.skipped)log(L"暂未恢复："+entry);
                // Count each completed move even when a later move fails.
                size_t moved=0;
                try { recover(preview,journal,[&](const S& line){if(line.find(L"已恢复：")==0){
                        const auto& item=preview.items.at(moved);result.restoredPaths.push_back(item.source+L" → "+item.dest);
                        ++moved;++result.restored;}log(line);},test,&current);
                    w.recoveryPerformed=true;w.restoredItems+=moved; }
                catch(...){w.restoredItems+=moved;throw;}
                if(canDeleteEmptyContainer(preview,test) && deleteEmptyContainer(preview,true,journal,test))result.removedContainers.push_back(preview.container);
            } else if(lower(name(path))!=L".trashes") {
                size_t checked=0;recoverySignature(path,checked);
                noLinks(root);if(volume(root)!=w.scan.serial)throw Error{L"U 盘已更换"};
                size_t visible=0;makeTreeVisible(path,journal,visible);++result.restored;result.visiblePaths.push_back(path);log(L"已显示隐藏文件夹："+path);
            }
        }catch(const Error& e){++result.skipped;++result.recoveryFailures;result.issues.push_back(e.text);log(e.text);}
    }
    for(const auto& entry:list(root)) {
        if(cancel && cancel()){result.stopped=true;return;}
        if((entry.attrs&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) || !(entry.attrs&(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)) || systemName(entry.path))continue;
        if(riskyExtension(entry.path) || suspicious(entry.path)){++result.skipped;continue;}
        try{requireContext(automaticRecoveryContext(w),root,volume(root));size_t count=0;recoverySignature(entry.path,count);size_t visible=0;makeTreeVisible(entry.path,journal,visible);++result.restored;result.visiblePaths.push_back(entry.path);}
        catch(const Error& e){++result.skipped;++result.recoveryFailures;result.issues.push_back(e.text);log(e.text);}
    }
}
inline void restoreAutomaticDisks(OneClickResult& result,Journal& journal,Log log,ScanProgress progress={},
    const std::function<bool()>& cancel={},bool test=false) {
    if(result.mode==RunMode::Full) {
        try{requireHostReady(result.host);
            for(const auto& w:result.usbs)if(w.treatment.blocked())throw Error{L"还有病毒未清理完成，暂未恢复 U 盘文件"};
        }catch(const Error& error){++result.recoveryFailures;result.issues.push_back(error.text);log(error.text);return;}
    }
    for(auto& w:result.usbs) {
        if(cancel && cancel()){result.stopped=true;break;}
        if(!w.scan.initialized)continue;
        try{validateTarget({w.scan.root,L"",w.scan.serial},test);if(progress)progress(L"恢复隐藏文件："+w.scan.root,result.checked);
            recheckAutomatic(w,result.mode==RunMode::Full && !test,log,1,0);recoverAutomatic(w,journal,log,result,test,cancel);
        }catch(const Error& error){++result.recoveryFailures;result.issues.push_back(error.text);log(error.text);}
    }
}
inline void summarizeAutomatic(OneClickResult& result) {
    result.isolated=0;result.unresolved=0;
    auto count=[&](const Workflow& w){result.isolated+=w.treatment.count(ActionKind::File,ActionStatus::Done);result.unresolved+=w.scan.findings.size();
        for(const auto& action:w.treatment.actions)if(action.status==ActionStatus::Failed || action.status==ActionStatus::Pending)++result.unresolved;};
    if(result.mode==RunMode::Full)count(result.host);
    for(const auto& w:result.usbs)count(w);
}
inline const wchar_t* usbOnlyReminder() {return L"若重新插入 U 盘仍出现快捷方式，说明电脑已中病毒，请使用“全盘杀毒”。";}
inline UiReport automaticReport(const OneClickResult& result) {
    UiReport report;report.warning=result.stopped || result.unresolved || result.skipped || result.recoveryFailures;
    report.headline=result.stopped?L"操作已停止":report.warning?L"处理结束，有项目未完成":L"处理完成";
    report.content=L"已清理 "+num(result.isolated)+L" 个病毒文件。\r\n";
    if(!result.restoredPaths.empty())report.content+=L"已将 U 盘隐藏文件夹中的 "+num(result.restoredPaths.size())+L" 项内容恢复到根目录。";
    else report.content+=L"本次没有文件移回 U 盘根目录。";
    if(!result.visiblePaths.empty())report.content+=L"\r\n另有 "+num(result.visiblePaths.size())+L" 项隐藏内容已恢复可见。";
    if(result.unresolved || result.skipped || result.recoveryFailures)report.content+=L"\r\n部分文件未处理，具体原因见操作记录。";
    if(!result.isolated && !result.unresolved && !result.stopped && result.issues.empty())report.content+=L"\r\n未发现本工具支持的已知病毒。";
    if(result.mode==RunMode::UsbOnly)report.content+=L"\r\n\r\n"+S(usbOnlyReminder());
    else if(result.isolated)report.content+=L"\r\n请保存文件，重启后再次扫描。";
    report.details=L"已清理的病毒文件：\r\n";std::set<S> cleaned;
    auto details=[&](const Workflow& w){for(const auto& action:w.treatment.actions)if(action.kind==ActionKind::File && action.status==ActionStatus::Done)cleaned.insert(action.target);};
    if(result.mode==RunMode::Full)details(result.host);
    for(const auto& w:result.usbs)details(w);
    if(cleaned.empty())report.details+=L"无\r\n";else for(const auto& path:cleaned)report.details+=path+L"\r\n";
    report.details+=L"\r\n已恢复到 U 盘根目录：\r\n";
    if(result.restoredPaths.empty())report.details+=L"无\r\n";else for(const auto& path:result.restoredPaths)report.details+=path+L"\r\n";
    if(!result.removedContainers.empty()){report.details+=L"\r\n已删除的空隐藏文件夹：\r\n";for(const auto& path:result.removedContainers)report.details+=path+L"\r\n";}
    return report;
}
inline void runAutomatic(OneClickResult& result,RunMode mode,const std::vector<DiskTarget>& targets,Log log,ScanProgress progress,
    const std::function<bool()>& cancel={},size_t pageLimit=ENTRY_LIMIT,
    bool test=false,const S& testJournal=L"",const std::vector<HashRule>& catalog=rules()) {
    if(test && (mode!=RunMode::UsbOnly || testJournal.empty()))throw Error{L"测试仅允许独立临时 U 盘目录和日志目录"};
    if(!pageLimit)throw Error{L"扫描批次上限无效"};
    NativeFs native;result=OneClickResult{};result.mode=mode;
    auto stopped=[&]{if(cancel && cancel()){result.stopped=true;return true;}return false;};
    auto scan=[&](Workflow& w){size_t base=result.checked;
        do{scanPage(w.scan,log,[&](const S& p,size_t n){if(progress)progress(p,base+n);},cancel,pageLimit);}while(w.scan.pending() && !stopped());
        result.checked=base+w.scan.checked;if(w.scan.cancelled)result.stopped=true;
        if(!w.scan.errors.empty())result.issues.push_back(L"部分位置无法读取，请查看详情");
        if(w.scan.scanner.oversized)log(L"超过 64 MiB 未作指纹检查："+num(w.scan.scanner.oversized)+L" 个文件");
    };
    if(mode==RunMode::Full) {
        auto& host=result.host;initializeScan(host.scan,L"",log);addFixedDisks(host.scan,fixedTargets());scan(host);if(stopped())return;
        auto diagnostic=[&](const S& text){host.diagnostics.push_back(text);log(text);};
        if(progress)progress(L"核对电脑启动项",result.checked);
        host.registryChecked=true;
        // Name-only registry candidates and user display policies are never removed automatically.
        namedStartupCandidates(diagnostic,&host.registryChecked);
        host.inventoryComplete=true;
        auto inventoryLog=[&](const S& text){diagnostic(text);host.inventoryComplete=false;result.issues.push_back(text);};
        host.persistence=serviceInventory(inventoryLog,cancel);auto tasks=taskInventory(inventoryLog,cancel);
        host.persistence.insert(host.persistence.end(),tasks.begin(),tasks.end());host.inventoryComplete=host.inventoryComplete && !stopped();
    }
    for(const auto& target:targets) {
        if(stopped())return;
        result.usbs.emplace_back();auto& w=result.usbs.back();
        try{initializeUsbOnly(w.scan,target,test);if(test){w.scan.scanner=Scanner(catalog);w.scan.scanner.usbRoot=target.root;}w.registryChecked=true;w.inventoryComplete=true;scan(w);}
        catch(const Error& e){++result.recoveryFailures;result.issues.push_back(target.root+L" "+e.text);log(e.text);}
    }
    if(stopped())return;
    Journal journal(test?testJournal:data());
    if(mode==RunMode::Full) {
        if(progress)progress(L"清理电脑病毒",result.checked);
        treatAutomatic(result.host,true,journal,log,rules(),nullptr,cancel);recheckAutomatic(result.host,true,log);
    }
    for(auto& w:result.usbs) {
        if(stopped())break;
        try {
            if(!w.scan.initialized)continue;
            validateTarget({w.scan.root,L"",w.scan.serial},test);
            if(progress)progress(L"清理 U 盘："+w.scan.root,result.checked);
            // Full mode also removes host references to payloads found on USB.
            if(mode==RunMode::Full)w.persistence=result.host.persistence;
            treatAutomatic(w,mode==RunMode::Full,journal,log,catalog,nullptr,cancel);
            recheckAutomatic(w,mode==RunMode::Full,log,3,test?0:1000);
        }catch(const Error& e){++result.recoveryFailures;result.issues.push_back(e.text);log(e.text);}
    }
    if(mode==RunMode::Full)recheckAutomatic(result.host,true,log,1,0);
    restoreAutomaticDisks(result,journal,log,progress,cancel,test);
    summarizeAutomatic(result);
}
} // namespace enhanced
