#pragma once
#include "scan_session.hpp"
#include "persistence.hpp"
#include "ui_results.hpp"

namespace enhanced {
struct Workflow {
    ScanSession scan;
    Treatment treatment;
    std::set<S> retained;
    std::vector<RunEntry> retryRuns;
    std::vector<RegistrySnapshot> policies,startups;
    std::vector<PersistenceItem> persistence;
    std::vector<S> diagnostics;
    bool registryChecked=false,inventoryComplete=false;
    size_t restoredItems=0;
    bool recoveryPerformed=false;
    RecoveryContext recovery() const {
        RecoveryContext c;c.scanned=scan.initialized;c.criticalComplete=scan.criticalReady() && registryChecked;
        c.root=scan.root;c.serial=scan.serial;c.outstanding=scan.findings;c.retained=retained;c.treatment=treatment;
        for(const auto* values:{&startups,&policies})for(const auto& value:*values)c.unreviewedSettings.push_back(registryLocation(value));
        return c;
    }
};
inline Plan prepareRecovery(const Workflow& w,const S& root,const S& container,bool test=false) {
    auto context=w.recovery();requireContext(context,root,volume(root));
    return plan(root,container,test,true);
}
inline void executeRecovery(Workflow& w,const Plan& preview,Journal& journal,Log log,bool test=false) {
    auto context=w.recovery();requireContext(context,preview.root,volume(preview.root));
    recover(preview,journal,log,test,&context);
    w.recoveryPerformed=true;w.restoredItems+=preview.items.size();
}
inline void setAction(Treatment& t,ActionKind kind,ActionStatus status,const S& target,const S& reason=L"",bool blocks=false) {
    for(auto& a:t.actions)if(a.kind==kind && a.target==target){a={kind,status,target,reason,blocks};return;}
    t.add(kind,status,target,reason,blocks);
}
inline void cleanReferences(const Finding& f,Workflow& w,Journal& journal,Log log) {
    auto entries=runs(log);
    for(const auto& r:entries)if(references(r.value,f.path)){
        S target=registryLocation(r.hive,r.view,r.key,r.name);
        try{removeRun(r,journal);setAction(w.treatment,ActionKind::Startup,ActionStatus::Done,target);log(L"已移除关联启动项："+target);}
        catch(const Error& e){setAction(w.treatment,ActionKind::Startup,ActionStatus::Failed,target,e.text,true);w.retryRuns.push_back(r);log(L"启动项移除失败："+target+L" — "+e.text);}
    }
}
inline void retryReferences(Workflow& w,Journal& journal,Log log) {
    auto prior=w.retryRuns;w.retryRuns.clear();std::set<S> seen;
    for(const auto& r:prior){S target=registryLocation(r.hive,r.view,r.key,r.name);if(!seen.insert(target).second)continue;
        try{removeRun(r,journal);setAction(w.treatment,ActionKind::Startup,ActionStatus::Done,target);log(L"已解决启动项："+target);}
        catch(const Error& e){setAction(w.treatment,ActionKind::Startup,ActionStatus::Failed,target,e.text,true);w.retryRuns.push_back(r);}}
}
inline void checkPersistence(const Finding& f,Workflow& w,Journal& journal) {
    for(auto& p:w.persistence)if(linked(p,f)) {
        try{disablePersistence(p,true,journal);p.enabled=false;setAction(w.treatment,p.kind,ActionStatus::Done,p.name);}
        catch(const Error& e){setAction(w.treatment,p.kind,ActionStatus::Failed,p.name,e.text,true);}
    }
}
inline void treatFinding(const Finding& f,bool consent,Workflow& w,Journal& journal,Log log,const HostActions* mock=nullptr,const std::vector<HashRule>& catalog=rules()) {
    if(!consent){w.retained.insert(findingKey(f));journal.add(L"用户选择保留",f.path,L"",f.reason);setAction(w.treatment,ActionKind::File,ActionStatus::Kept,f.path,L"用户保留，未处理",f.confirmed);return;}
    w.retained.erase(findingKey(f));
    try {
        // Validate BEFORE touching any referenced persistence; consent alone is not evidence.
        noLinks(f.path);if(f.digest.empty() || size(f.path)>HASH_LIMIT || hash(f.path)!=f.digest || (f.fileSize && size(f.path)!=f.fileSize))throw Error{L"文件已变化，请重新检查"};
        HostActions actions;
        actions.stop=[&](const Finding& item,Journal& j,Log l){
            try{if(mock){if(mock->stop)mock->stop(item,j,l);}else{checkPersistence(item,w,j);stopExact(item,j,l);}
                setAction(w.treatment,ActionKind::Process,ActionStatus::Done,item.path);
            }catch(const Error& e){setAction(w.treatment,ActionKind::Process,ActionStatus::Failed,item.path,e.text,true);throw;}
        };
        actions.persistence=[&](const Finding& item,Journal& j,Log l){if(mock){if(mock->persistence)mock->persistence(item,j,l);}else cleanReferences(item,w,j,l);};
        ActionResult result{ActionKind::File,ActionStatus::Pending,f.path,L"",true};
        if(f.confirmed)cleanOne(f,journal,log,actions,catalog,&result);
        else {
            quarantineReviewed(f,true,journal,log,[&](const Finding& item,Journal& j,Log l){actions.stop(item,j,l);actions.persistence(item,j,l);},catalog);
            result.status=ActionStatus::Done;
        }
        setAction(w.treatment,result.kind,result.status,result.target,result.reason,result.status!=ActionStatus::Done);
        if(result.status==ActionStatus::Done){
            setAction(w.treatment,ActionKind::Recheck,ActionStatus::Pending,f.path,L"等待清理后复查",true);
            bool recorded=false;for(const auto& prior:w.treatment.isolated)if(same(prior.path,f.path))recorded=true;
            if(!recorded)w.treatment.isolated.push_back(f);
            w.scan.findings.erase(std::remove_if(w.scan.findings.begin(),w.scan.findings.end(),[&](const Finding& candidate){return same(candidate.path,f.path);}),w.scan.findings.end());
        }
    }catch(const Error& e){setAction(w.treatment,ActionKind::File,ActionStatus::Failed,f.path,e.text,true);journal.add(L"处理失败",f.path,L"",e.text);log(e.text);}
}
inline void treatRegistry(const RegistrySnapshot& item,bool consent,bool policy,Workflow& w,Journal& journal,Log log) {
    ActionKind kind=policy?ActionKind::Policy:ActionKind::Startup;S target=registryLocation(item);
    if(!consent){
        for(const auto& a:w.treatment.actions)if(a.kind==kind && a.target==target && (a.status==ActionStatus::Done || a.blocksRecovery)){
            journal.add(L"沿用关联处理结果",target,L"",L"未勾选不会覆盖已经执行的关联处理或失败状态");return;}
        journal.add(L"用户选择保留设置",target,L"",registryValueText(item));setAction(w.treatment,kind,ActionStatus::Kept,target,L"用户保留");return;}
    try{removeReviewedValue(item,true,journal,log);setAction(w.treatment,kind,ActionStatus::Done,target);}
    catch(const Error& e){setAction(w.treatment,kind,ActionStatus::Failed,target,e.text,!policy);log(e.text);}
}
inline void recheckTreatment(Workflow& w,Log log,unsigned observations=3,DWORD interval=1000,
    std::function<bool(const S&)> present=exists,std::function<std::vector<S>()> processList={}) {
    for(unsigned pass=0;pass<observations;++pass){if(pass && interval)Sleep(interval);
        std::vector<S> paths;
        if(processList)paths=processList();else processes([&](DWORD,const S& path){paths.push_back(path);},log);
        for(const auto& item:w.treatment.isolated){bool alive=present(item.path);for(const auto& path:paths)if(same(path,item.path))alive=true;
            if(alive){setAction(w.treatment,ActionKind::Recheck,ActionStatus::Failed,item.path,L"文件或进程重新出现，请继续检查传播源",true);log(L"复查发现文件或进程重现："+item.path);}
            else {
                // An earlier observed recurrence must not disappear from the outcome by itself.
                bool failed=false;for(const auto& a:w.treatment.actions)if(a.kind==ActionKind::Recheck && a.target==item.path && a.status==ActionStatus::Failed)failed=true;
                if(!failed)setAction(w.treatment,ActionKind::Recheck,ActionStatus::Done,item.path);
            }
        }
        if(!processList && !w.treatment.isolated.empty()) {
            for(const auto& run:runs(log))for(const auto& item:w.treatment.isolated)if(references(run.value,item.path)) {
                S target=registryLocation(run.hive,run.view,run.key,run.name);
                setAction(w.treatment,ActionKind::Startup,ActionStatus::Failed,target,L"关联启动项仍存在或重新出现，请重试处理",true);
                w.retryRuns.push_back(run);log(L"复查发现关联启动项："+target);
            }
        }
    }
}
inline S actionName(ActionKind kind) {
    switch(kind){case ActionKind::File:return L"文件";case ActionKind::Process:return L"进程";case ActionKind::Startup:return L"启动项";
    case ActionKind::Policy:return L"磁盘显示设置";case ActionKind::Service:return L"服务";case ActionKind::Task:return L"计划任务";default:return L"清理后复查";}
}
inline UiReport treatmentReport(const Workflow& w) {
    UiReport r;size_t isolated=w.treatment.count(ActionKind::File,ActionStatus::Done),failed=0,kept=0;
    r.anyIsolated=isolated>0;
    r.details=L"【本次处理记录】\r\n";
    for(const auto& a:w.treatment.actions){if(a.status==ActionStatus::Failed || a.status==ActionStatus::Pending)++failed;if(a.status==ActionStatus::Kept)++kept;
        S status=a.status==ActionStatus::Done?L"已处理":a.status==ActionStatus::Kept?L"已保留":L"未解决";
        r.details+=actionName(a.kind)+L" · "+status+L" · "+a.target+L"\r\n"+a.reason+L"\r\n";}
    r.headline=failed?L"还有 "+num(failed)+L" 项未处理成功":(kept?L"处理结束，另有 "+num(kept)+L" 项保留":L"本次选择的项目已处理");
    r.content=L"已隔离 "+num(isolated)+L" 个文件，移除 "+num(w.treatment.count(ActionKind::Startup,ActionStatus::Done))+L" 个启动项。";
    for(const auto& a:w.treatment.actions)if(a.status==ActionStatus::Failed || a.status==ActionStatus::Pending){
        r.content+=L"\r\n"+actionName(a.kind)+L"未解决："+name(a.target);
        if(a.reason.find(L"[5]")!=S::npos || a.reason.find(L"权限")!=S::npos)r.content+=admin()?L"。已有管理员权限，但系统仍拒绝访问。":L"。需要管理员权限。";
        else if(a.reason.find(L"变化")!=S::npos)r.content+=L"。内容已变化，请重新检查。";
        else if(a.kind==ActionKind::Recheck)r.content+=L"。文件或进程重新出现。";
        else r.content+=L"。具体原因见详情。";
        break;
    }
    if(!w.scan.findings.empty())r.content+=L"\r\n还有 "+num(w.scan.findings.size())+L" 项发现未隔离，可返回处理列表查看。";
    if(isolated && !w.scan.root.empty() && !w.recoveryPerformed)r.content+=L"\r\n隐藏文件尚未恢复。请点击“恢复隐藏文件到根目录”。";
    if(w.recoveryPerformed)r.content+=L"\r\n已恢复 "+num(w.restoredItems)+L" 项文件或文件夹到 U 盘根目录。";
    if(isolated)r.content+=L"\r\n完成文件恢复后，请保存文件并重启复查。";
    r.warning=failed || kept || !w.scan.findings.empty();r.details+=L"\r\n"+aftercareChecklist();return r;
}
} // namespace enhanced
