#pragma once
#include "engine.hpp"
namespace usb {
struct RegistrySnapshot {
    HKEY hive; REGSAM view; S key, name; DWORD type; std::vector<BYTE> value;
};
inline S registryLocation(HKEY hive, REGSAM view, const S& key, const S& name) {
    return S(hive==HKEY_LOCAL_MACHINE?L"HKLM\\":L"HKCU\\")+key+L" ["+num(view==KEY_WOW64_64KEY?64:32)+L" 位] / "+name;
}
inline S hexBytes(const std::vector<BYTE>& value) {
    S out; const wchar_t* digits=L"0123456789ABCDEF";
    for(auto b:value){out+=digits[b>>4];out+=digits[b&15];}return out;
}
inline S registryLocation(const RegistrySnapshot& s) {return registryLocation(s.hive,s.view,s.key,s.name);}
inline std::vector<RegistrySnapshot> readRegistryValue(HKEY hive,REGSAM view,const S& key,const S& name,Log log,bool* readable=nullptr) {
    HKEY h=nullptr;LONG rc=RegOpenKeyExW(hive,key.c_str(),0,KEY_QUERY_VALUE|view,&h);
    if(rc==ERROR_FILE_NOT_FOUND || rc==ERROR_PATH_NOT_FOUND)return {};
    const S location=registryLocation(hive,view,key,name);
    if(rc!=ERROR_SUCCESS){if(readable)*readable=false;log(L"未读取注册表："+location+L" — "+startupError(L"读取",rc));return {};}
    DWORD type=0,n=0;rc=RegQueryValueExW(h,name.c_str(),nullptr,&type,nullptr,&n);
    if(rc==ERROR_FILE_NOT_FOUND){RegCloseKey(h);return {};}
    if(rc!=ERROR_SUCCESS || n>65536){if(readable)*readable=false;RegCloseKey(h);log(L"未读取注册表："+location+L" — "+startupError(L"读取",rc==ERROR_SUCCESS?ERROR_MORE_DATA:rc));return {};}
    std::vector<BYTE> value(n);rc=RegQueryValueExW(h,name.c_str(),nullptr,&type,value.data(),&n);RegCloseKey(h);
    if(rc!=ERROR_SUCCESS){if(readable)*readable=false;log(L"未读取注册表："+location+L" — "+startupError(L"读取",rc));return {};}
    value.resize(n);return {{hive,view,key,name,type,value}};
}
inline S registryIdentity(const RegistrySnapshot& s) {
    // HKCU Run and HKLM Policies are shared on supported Windows. HKLM Run views are distinct.
    bool shared=s.hive==HKEY_CURRENT_USER || lower(s.key).rfind(L"software\\microsoft\\windows\\currentversion\\policies",0)==0;
    return S(s.hive==HKEY_LOCAL_MACHINE?L"HKLM|":L"HKCU|")+lower(s.key)+L"|"+lower(s.name)+L"|"+num(shared?0:s.view);
}
inline std::vector<RegistrySnapshot> uniqueRegistry(const std::vector<RegistrySnapshot>& values) {
    std::vector<RegistrySnapshot> out;std::set<S> seen;
    for(const auto& v:values)if(seen.insert(registryIdentity(v)+L"|"+num(v.type)+L"|"+hexBytes(v.value)).second)out.push_back(v);
    return out;
}
inline std::vector<RegistrySnapshot> noDrivesPolicies(Log log) {
    std::vector<RegistrySnapshot> out;
    SYSTEM_INFO si;GetNativeSystemInfo(&si);
    for(auto hive:{HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE})for(auto view:{KEY_WOW64_32KEY,KEY_WOW64_64KEY}) {
        if(view==KEY_WOW64_64KEY && si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL)continue;
        auto values=readRegistryValue(hive,view,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",L"NoDrives",log);
        out.insert(out.end(),values.begin(),values.end());
    }return uniqueRegistry(out);
}
inline S registryValueText(const RegistrySnapshot& s) {
    S text=L"类型："+num(s.type)+L"；原始值（十六进制）："+hexBytes(s.value);
    if(s.type==REG_DWORD && s.value.size()==sizeof(DWORD)){DWORD d;memcpy(&d,s.value.data(),sizeof(d));text+=L"；十进制："+num(d);}
    if((s.type==REG_SZ || s.type==REG_EXPAND_SZ) && s.value.size()%2==0) {
        S value;for(size_t i=0;i+1<s.value.size();i+=2){wchar_t c=wchar_t(s.value[i]|(s.value[i+1]<<8));if(!c)break;value+=c;}text+=L"\r\n内容："+value;
    }return text;
}
// Consent is separate from detection; snapshots are compared byte-for-byte before deletion.
inline bool removeReviewedValue(const RegistrySnapshot& s,bool consent,Journal& j,Log log) {
    if(!consent){log(L"用户保留注册表项："+registryLocation(s));return false;}
    HKEY h=nullptr;LONG rc=RegOpenKeyExW(s.hive,s.key.c_str(),0,KEY_QUERY_VALUE|KEY_SET_VALUE|s.view,&h);
    if(rc==ERROR_FILE_NOT_FOUND || rc==ERROR_PATH_NOT_FOUND){log(L"注册表项已不存在："+registryLocation(s));return true;}
    if(rc!=ERROR_SUCCESS)throw Error{startupError(L"打开注册表项",rc)};
    DWORD type=0,n=65536;std::vector<BYTE> current(n);
    rc=RegQueryValueExW(h,s.name.c_str(),nullptr,&type,current.data(),&n);
    if(rc==ERROR_FILE_NOT_FOUND){RegCloseKey(h);log(L"注册表项已不存在："+registryLocation(s));return true;}
    if(rc!=ERROR_SUCCESS){RegCloseKey(h);throw Error{startupError(L"读取注册表项",rc)};}
    current.resize(n);
    if(type!=s.type || current!=s.value){RegCloseKey(h);throw Error{L"注册表项内容已变化，请重新检查"};}
    try{j.add(L"注册表原值备份",registryLocation(s),L"",L"type="+num(s.type)+L"; bytes="+hexBytes(s.value));}
    catch(...){RegCloseKey(h);throw;}
    rc=RegDeleteValueW(h,s.name.c_str());RegCloseKey(h);
    if(rc!=ERROR_SUCCESS && rc!=ERROR_FILE_NOT_FOUND)throw Error{startupError(L"删除注册表项",rc)};
    j.add(L"人工确认移除注册表项",registryLocation(s),L"",L"已备份原始字节");
    log(L"已移除人工确认注册表项："+registryLocation(s));return true;
}
inline std::vector<RegistrySnapshot> namedStartupCandidates(const std::vector<RunEntry>& entries,Log log) {
    std::vector<RegistrySnapshot> out;
    for(const auto& r:entries)if(lower(r.name)==L"windows settings") {
        auto values=readRegistryValue(r.hive,r.view,r.key,r.name,log);
        out.insert(out.end(),values.begin(),values.end());
    }return uniqueRegistry(out);
}
inline std::vector<RegistrySnapshot> namedStartupCandidates(Log log,bool* readable=nullptr) {
    std::vector<RegistrySnapshot> out;SYSTEM_INFO si;GetNativeSystemInfo(&si);
    for(auto hive:{HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE})for(auto view:{KEY_WOW64_32KEY,KEY_WOW64_64KEY}) {
        if(view==KEY_WOW64_64KEY && si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL)continue;
        for(const auto* key:{L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}) {
            auto values=readRegistryValue(hive,view,key,L"Windows Settings",log,readable);
            out.insert(out.end(),values.begin(),values.end());
        }
    }return uniqueRegistry(out);
}
using ReviewedValueAction=std::function<bool(const RegistrySnapshot&,bool,Journal&,Log)>;
inline void cleanReviewedStartup(const RegistrySnapshot& s,bool consent,Journal& j,Log log,ReviewedValueAction action=removeReviewedValue) {
    if(lower(s.name)!=L"windows settings")throw Error{L"不是待确认的指定启动值名"};
    try{action(s,consent,j,log);}
    catch(const Error& e){
        j.add(L"启动项移除失败",registryLocation(s),L"",e.text);
        log(L"启动项移除失败："+registryLocation(s)+L" — "+e.text);
    }
}
} // namespace usb
