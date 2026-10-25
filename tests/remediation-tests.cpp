#include "enhanced_engine.hpp"
#include "ui_results.hpp"
#include <iostream>
using namespace usb;namespace e=enhanced;
static int passed=0;
static void check(bool ok,const char* text){if(!ok)throw Error{fromUtf8(text)};++passed;std::cout<<"PASS "<<text<<std::endl;}
static void rejects(const std::function<void()>& fn,const char* text){bool rejected=false;try{fn();}catch(const Error&){rejected=true;}check(rejected,text);}
struct TestRegistry {
    S path=L"Software\\UsbRecovery-RemediationTest-"+num(GetCurrentProcessId())+L"-"+num(GetTickCount64());
    HKEY h=nullptr;
    TestRegistry(){if(RegCreateKeyExW(HKEY_CURRENT_USER,path.c_str(),0,nullptr,0,KEY_ALL_ACCESS,nullptr,&h,nullptr)!=ERROR_SUCCESS)throw Error{L"fixture registry"};}
    ~TestRegistry(){if(h)RegCloseKey(h);RegDeleteKeyW(HKEY_CURRENT_USER,path.c_str());}
    void dword(const S& name,DWORD value){if(RegSetValueExW(h,name.c_str(),0,REG_DWORD,(BYTE*)&value,sizeof(value))!=ERROR_SUCCESS)throw Error{L"fixture dword"};}
    void string(const S& name,const S& value){if(RegSetValueExW(h,name.c_str(),0,REG_SZ,(const BYTE*)value.c_str(),DWORD((value.size()+1)*2))!=ERROR_SUCCESS)throw Error{L"fixture string"};}
};
int wmain(int argc,wchar_t** argv){try{
    if(argc!=2)return 2;
    S root=full(argv[1]);mkdir(root);S temp=join(root,L"temp");mkdir(temp);
    e::Scanner scanner;scanner.tempRoots={temp};std::vector<Finding> findings;std::vector<S> logs;
    auto log=[&](const S& line){logs.push_back(line);};
    S dat1=join(temp,L"tbtnds.dat"),dat2=join(temp,L"tbtcmds.dat"),numeric=join(temp,L"12345.exe");
    textFile(dat1,L"");textFile(dat2,L"");textFile(numeric,L"harmless numeric executable fixture");
    scanner.inspect(dat1,findings,log);scanner.inspect(dat2,findings,log);scanner.inspect(numeric,findings,log);
    check(findings.size()==3 && !findings[0].confirmed && findings[0].review==ReviewKind::ResidualName && findings[1].review==ReviewKind::ResidualName,"P0-1 residual names require explicit review rather than forged confirmation");
    check(findings[2].review==ReviewKind::NumericTemp && !findings[2].confirmed && findings[2].fileSize==size(numeric) && !findings[2].digest.empty() && findings[2].created.dwHighDateTime!=0,"P0-1 numeric Temp exe includes size hash and creation time without automatic isolation");
    S outside=join(root,L"456.exe");textFile(outside,L"harmless outside temp");std::vector<Finding> outsideFindings;scanner.inspect(outside,outsideFindings,log);
    check(outsideFindings.empty(),"P0-1 numeric exe outside Temp is not a Temp finding");
    {Journal j(join(root,L"journals"));
        check(!e::quarantineReviewed(findings[0],false,j,log) && exists(dat1),"P0-1 residual remains without per-item consent");
        check(e::quarantineReviewed(findings[0],true,j,log) && !exists(dat1) && hash(join(j.dir,L"1.quarantine"))==findings[0].digest,"P0-1 consented residual quarantine verifies backup before removal");
        rejects([&]{e::quarantineReviewed(findings[2],true,j,log);},"P0-1 numeric-only unknown executable cannot enter reviewed quarantine");
    }
    TestRegistry key;key.dword(L"NoDrives",8);
    auto policies=readRegistryValue(HKEY_CURRENT_USER,0,key.path,L"NoDrives",log);
    check(policies.size()==1 && policies[0].type==REG_DWORD && registryValueText(policies[0]).find(L"十进制：8")!=S::npos,"P0-1 NoDrives snapshot preserves original value for display");
    {Journal j(join(root,L"registry-journals"));
        check(!removeReviewedValue(policies[0],false,j,log) && RegQueryValueExW(key.h,L"NoDrives",nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS,"P0-1 policy survives without consent");
        key.dword(L"NoDrives",16);
        rejects([&]{removeReviewedValue(policies[0],true,j,log);},"P0-1 changed policy is retained instead of deleting a stale snapshot");
        policies=readRegistryValue(HKEY_CURRENT_USER,0,key.path,L"NoDrives",log);
        check(removeReviewedValue(policies[0],true,j,log) && RegQueryValueExW(key.h,L"NoDrives",nullptr,nullptr,nullptr,nullptr)==ERROR_FILE_NOT_FOUND,"P0-1 consented policy is removed from disposable test key");
        auto backup=std::string();{Handle h(CreateFileW(xp(join(j.dir,L"operations.jsonl")).c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr));char b[8192];DWORD n=0;ReadFile(h.h,b,sizeof(b),&n,nullptr);backup.assign(b,n);}
        check(backup.find("type=4; bytes=10000000")!=std::string::npos,"P0-1 registry backup records exact type and bytes before removal");
    }
    auto report=cleanReport({L"已隔离：fixture"});
    check(report.details.find(L"UPnP")!=S::npos && report.details.find(L"45.141.233.6")!=S::npos && report.details.find(L"94.26.90.235")!=S::npos && report.details.find(L"P2P")!=S::npos,"P0-1 completion contains manual network checklist");
    check(report.details.find(L"逐笔核对收款地址")!=S::npos && report.details.find(L"密码")!=S::npos && report.details.find(L"新助记词")!=S::npos,"P0-1 completion contains clipboard transfer and credential checklist");
    // More task-specific regression cases are appended here.
    std::cout<<"TOTAL PASS "<<passed<<std::endl;return 0;
}catch(const Error& error){std::cerr<<utf8(error.text)<<std::endl;return 1;}}
