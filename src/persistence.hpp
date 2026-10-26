#pragma once
#include "enhanced_engine.hpp"
#include <taskschd.h>
#include <oleauto.h>

namespace enhanced {
template<class T> struct Com {
    T* p=nullptr;~Com(){if(p)p->Release();}T** put(){return &p;}T* operator->()const{return p;}
};
struct Bstr {
    BSTR p=nullptr;Bstr()=default;explicit Bstr(const S& s):p(SysAllocString(s.c_str())){}
    ~Bstr(){SysFreeString(p);}BSTR* put(){return &p;}S value()const{return p?S(p,SysStringLen(p)):S();}
};
struct ComApartment {HRESULT hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED);~ComApartment(){if(SUCCEEDED(hr))CoUninitialize();}};
inline void comCheck(HRESULT hr,const S& action){if(FAILED(hr))throw Error{action+L" [HRESULT "+num((DWORD)hr)+L"]"};}
struct ServiceHandle {SC_HANDLE h=nullptr;explicit ServiceHandle(SC_HANDLE value):h(value){}~ServiceHandle(){if(h)CloseServiceHandle(h);}};
struct PersistenceItem {
    ActionKind kind=ActionKind::Service;S name,command,snapshot;DWORD start=0,type=0;bool enabled=false;
    std::vector<S> references;
};
inline std::vector<BYTE> serviceConfig(SC_HANDLE service) {
    DWORD needed=0;QueryServiceConfigW(service,nullptr,0,&needed);
    if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER || needed>1024*1024)fail(L"读取服务配置大小");
    std::vector<BYTE> buffer(needed);if(!QueryServiceConfigW(service,(QUERY_SERVICE_CONFIGW*)buffer.data(),needed,&needed))fail(L"读取服务配置");return buffer;
}
inline PersistenceItem serviceItem(const S& name,SC_HANDLE service) {
    auto bytes=serviceConfig(service);auto config=(QUERY_SERVICE_CONFIGW*)bytes.data();
    PersistenceItem item;item.kind=ActionKind::Service;item.name=name;item.command=config->lpBinaryPathName;
    item.start=config->dwStartType;item.type=config->dwServiceType;item.enabled=item.start!=SERVICE_DISABLED;
    item.snapshot=item.command+L"|"+num(item.type)+L"|"+num(item.start)+L"|"+config->lpServiceStartName;
    item.references=referencedPaths(item.command);return item;
}
inline std::vector<PersistenceItem> serviceInventory(Log log,const std::function<bool()>& cancel={}) {
    std::vector<PersistenceItem> out;ServiceHandle manager(OpenSCManagerW(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE));
    if(!manager.h){log(L"无法检查服务配置，可能需要管理员权限");return out;}
    DWORD needed=0,count=0,resume=0;std::vector<BYTE> buffer(256*1024);
    do{
        BOOL ok=EnumServicesStatusExW(manager.h,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,buffer.data(),DWORD(buffer.size()),&needed,&count,&resume,nullptr);
        DWORD error=ok?ERROR_SUCCESS:GetLastError();if(!ok && error!=ERROR_MORE_DATA){log(L"枚举服务失败 ["+num(error)+L"]");break;}
        auto entries=(ENUM_SERVICE_STATUS_PROCESSW*)buffer.data();
        for(DWORD i=0;i<count && out.size()<10000;++i){if(cancel && cancel())return out;ServiceHandle service(OpenServiceW(manager.h,entries[i].lpServiceName,SERVICE_QUERY_CONFIG));
            if(!service.h){log(L"未读取服务："+S(entries[i].lpServiceName));continue;}
            try{out.push_back(serviceItem(entries[i].lpServiceName,service.h));}catch(const Error& e){log(e.text);}}
        if(out.size()>=10000){log(L"服务检查达到 10000 项上限");break;}if(ok)break;
    }while(resume);
    return out;
}
inline void connectScheduler(Com<ITaskService>& service) {
    comCheck(CoCreateInstance(CLSID_TaskScheduler,nullptr,CLSCTX_INPROC_SERVER,IID_ITaskService,(void**)service.put()),L"打开计划任务");
    VARIANT empty;VariantInit(&empty);comCheck(service->Connect(empty,empty,empty,empty),L"连接计划任务");
}
inline PersistenceItem taskItem(IRegisteredTask* task) {
    PersistenceItem item;item.kind=ActionKind::Task;Bstr path,xml;VARIANT_BOOL enabled=VARIANT_FALSE;
    comCheck(task->get_Path(path.put()),L"读取任务路径");comCheck(task->get_Xml(xml.put()),L"备份任务配置");comCheck(task->get_Enabled(&enabled),L"读取任务状态");
    item.name=path.value();item.snapshot=xml.value();item.enabled=enabled!=VARIANT_FALSE;
    Com<ITaskDefinition> definition;Com<IActionCollection> actions;
    comCheck(task->get_Definition(definition.put()),L"读取任务定义");comCheck(definition->get_Actions(actions.put()),L"读取任务动作");
    LONG count=0;comCheck(actions->get_Count(&count),L"读取动作数量");
    for(LONG i=1;i<=count && i<=128;++i){Com<IAction> action;comCheck(actions->get_Item(i,action.put()),L"读取任务动作");TASK_ACTION_TYPE type;
        comCheck(action->get_Type(&type),L"读取任务动作类型");if(type!=TASK_ACTION_EXEC)continue;
        Com<IExecAction> exec;comCheck(action->QueryInterface(IID_IExecAction,(void**)exec.put()),L"读取执行配置");Bstr pathArg,args;
        comCheck(exec->get_Path(pathArg.put()),L"读取执行路径");comCheck(exec->get_Arguments(args.put()),L"读取执行参数");
        S command=L"\""+pathArg.value()+L"\" "+args.value();if(!item.command.empty())item.command+=L"\r\n";item.command+=command;
        auto refs=referencedPaths(command);item.references.insert(item.references.end(),refs.begin(),refs.end());
    }return item;
}
inline std::vector<PersistenceItem> taskInventory(Log log,const std::function<bool()>& cancel={}) {
    std::vector<PersistenceItem> out;ComApartment apartment;
    try{comCheck(apartment.hr,L"初始化任务检查");Com<ITaskService> service;connectScheduler(service);
        std::vector<std::pair<S,int>> folders{{L"\\",0}};size_t visited=0;
        while(!folders.empty() && visited++<4096){if(cancel && cancel())return out;auto current=folders.back();folders.pop_back();if(current.second>32){log(L"计划任务目录达到深度上限");continue;}
            try{Com<ITaskFolder> folder;Bstr folderName(current.first);comCheck(service->GetFolder(folderName.p,folder.put()),L"读取任务目录");
                Com<IRegisteredTaskCollection> tasks;comCheck(folder->GetTasks(TASK_ENUM_HIDDEN,tasks.put()),L"列出任务");LONG n=0;comCheck(tasks->get_Count(&n),L"读取任务数量");
                for(LONG i=1;i<=n && out.size()<10000;++i){if(cancel && cancel())return out;VARIANT index;VariantInit(&index);index.vt=VT_I4;index.lVal=i;Com<IRegisteredTask> task;
                    try{comCheck(tasks->get_Item(index,task.put()),L"读取任务");out.push_back(taskItem(task.p));}catch(const Error& e){log(e.text);}}
                Com<ITaskFolderCollection> children;comCheck(folder->GetFolders(0,children.put()),L"列出任务子目录");comCheck(children->get_Count(&n),L"读取子目录数量");
                for(LONG i=1;i<=n && folders.size()<4096;++i){VARIANT index;VariantInit(&index);index.vt=VT_I4;index.lVal=i;Com<ITaskFolder> child;Bstr path;
                    comCheck(children->get_Item(index,child.put()),L"读取子目录");comCheck(child->get_Path(path.put()),L"读取子目录路径");folders.push_back({path.value(),current.second+1});}
                if(out.size()>=10000){log(L"计划任务达到 10000 项上限");break;}
            }catch(const Error& e){log(L"未检查任务目录："+current.first+L" — "+e.text);}
        }
    }catch(const Error& e){log(e.text);}return out;
}
inline bool linked(const PersistenceItem& item,const Finding& f) {
    if(!item.enabled)return false;
    for(const auto& p:item.references)if(same(p,f.path))return true;
    return false;
}
inline void disablePersistence(const PersistenceItem& expected,bool consent,Journal& journal) {
    if(!consent)throw Error{L"未同意停用此启动入口"};
    if(expected.kind==ActionKind::Service){
        // Shared hosts and driver services are diagnostic only. Never terminate by service name.
        if(expected.type!=SERVICE_WIN32_OWN_PROCESS)throw Error{L"共享宿主服务不在自动处理范围，请使用完整杀毒软件复查"};
        ServiceHandle manager(OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT));if(!manager.h)fail(L"打开服务管理器");
        ServiceHandle service(OpenServiceW(manager.h,expected.name.c_str(),SERVICE_QUERY_CONFIG|SERVICE_CHANGE_CONFIG));if(!service.h)fail(L"打开关联服务");
        auto current=serviceItem(expected.name,service.h);if(current.snapshot!=expected.snapshot)throw Error{L"服务配置已经变化，请重新检查"};
        journal.add(L"备份关联服务配置",expected.name,L"",expected.snapshot);
        if(!ChangeServiceConfigW(service.h,SERVICE_NO_CHANGE,SERVICE_DISABLED,SERVICE_NO_CHANGE,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr))fail(L"停用关联服务");
        if(serviceItem(expected.name,service.h).enabled)throw Error{L"服务停用后复核失败"};
    }else if(expected.kind==ActionKind::Task){
        ComApartment apartment;comCheck(apartment.hr,L"初始化任务处理");Com<ITaskService> service;connectScheduler(service);
        Com<ITaskFolder> root;Bstr rootName(L"\\"),name(expected.name);comCheck(service->GetFolder(rootName.p,root.put()),L"打开任务根目录");
        Com<IRegisteredTask> task;comCheck(root->GetTask(name.p,task.put()),L"打开关联任务");auto current=taskItem(task.p);
        if(current.snapshot!=expected.snapshot || current.enabled!=expected.enabled)throw Error{L"任务配置已经变化，请重新检查"};
        journal.add(L"备份关联任务 XML",expected.name,L"",expected.snapshot);
        comCheck(task->put_Enabled(VARIANT_FALSE),L"停用关联任务");VARIANT_BOOL enabled;comCheck(task->get_Enabled(&enabled),L"复核任务状态");
        if(enabled!=VARIANT_FALSE)throw Error{L"任务停用后复核失败"};
    }else throw Error{L"未知的启动入口类型"};
    journal.add(L"已停用关联启动入口",expected.name,L"",L"保留配置备份，未删除系统服务或计划任务");
}
inline void mutexDiagnostic(Log log) {
    // A candidate from the supplied report; existence is never a malware verdict.
    for(const auto* name:{L"l9e8r7h8e",L"Global\\l9e8r7h8e"}){Handle h(OpenMutexW(SYNCHRONIZE,FALSE,name));
        if(h.h)log(L"诊断线索：候选互斥体存在："+S(name)+L"；不据此定罪或结束进程");
        else if(GetLastError()==ERROR_ACCESS_DENIED)log(L"候选互斥体不可读取："+S(name));}
}
} // namespace enhanced
