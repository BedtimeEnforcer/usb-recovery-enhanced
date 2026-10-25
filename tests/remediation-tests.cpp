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
static void shortcut(const S& path,const S& target,const S& args) {
    std::vector<BYTE> b(80+(target.size()+args.size())*2);b[0]=76;
    BYTE clsid[]={1,20,2,0,0,0,0,0,192,0,0,0,0,0,0,70};memcpy(b.data()+4,clsid,16);b[20]=168;
    size_t pos=76;auto append=[&](const S& value){b[pos++]=BYTE(value.size());b[pos++]=BYTE(value.size()>>8);memcpy(b.data()+pos,value.data(),value.size()*2);pos+=value.size()*2;};append(target);append(args);
    Handle h(CreateFileW(xp(path).c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,0,nullptr));if(h.h==INVALID_HANDLE_VALUE)fail(L"shortcut fixture");write(h.h,b.data(),DWORD(b.size()));
}
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
    key.string(L"Windows Settings",L"cmd.exe /c missing.exe");
    RunEntry orphan{HKEY_CURRENT_USER,0,key.path,L"Windows Settings",L"cmd.exe /c missing.exe",L"",REG_SZ};
    auto startups=namedStartupCandidates({orphan},log);
    check(startups.size()==1 && registryValueText(startups[0]).find(L"missing.exe")!=S::npos,"P0-2 orphan named startup remains visible without an existing target");
    {Journal j(join(root,L"run-journals"));cleanReviewedStartup(startups[0],false,j,log);check(RegQueryValueExW(key.h,L"Windows Settings",nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS,"P0-2 named startup is not deleted without consent");
        std::vector<S> failedLog;
        cleanReviewedStartup(startups[0],true,j,[&](const S& line){failedLog.push_back(line);},[](const RegistrySnapshot&,bool,Journal&,Log)->bool{throw Error{L"权限不足 [5]"};});
        auto failedReport=cleanReport({L"已隔离：fixture",failedLog.at(0)});
        check(failedReport.warning && failedReport.content.rfind(L"启动项未清除",0)==0 && failedReport.content.find(key.path)!=S::npos && failedReport.content.find(L"HKCU")!=S::npos && failedReport.content.find(L"Windows Settings")!=S::npos && failedReport.content.find(L"重启后复查")!=S::npos,"P0-2 startup deletion failure is first with hive key value reason and rescan instruction");
        cleanReviewedStartup(startups[0],true,j,log);
        check(RegQueryValueExW(key.h,L"Windows Settings",nullptr,nullptr,nullptr,nullptr)==ERROR_FILE_NOT_FOUND,"P0-2 consent removes backed-up orphan named startup");
    }
    key.string(L"Windows Settings",L"rundll32.exe C:\\fixture\\missing.dll,Entry");
    auto indirect=namedStartupCandidates({orphan},log);
    check(indirect.size()==1 && registryValueText(indirect[0]).find(L"rundll32")!=S::npos,"P0-2 indirect named startup is listed for confirmation");
    check(e::references(L"\"C:\\fixture\\confirmed.exe\" /a",L"C:\\fixture\\confirmed.exe"),"P0-2 direct confirmed-file reference still matches");
    S expanded=join(root,L"Windows"),system=join(expanded,L"System32");mkdir(expanded);mkdir(system);
    S fixture=join(system,L"harmless.bin");textFile(fixture,L"harmless expanded scope hash fixture");
    std::vector<e::HashRule> fixtureRules{{hash(fixture),L"fixture",L"local harmless",L"fixture only"}};
    e::Scanner fixtureScanner(fixtureRules);std::set<S> seen;std::vector<Finding> found; e::WalkBudget scopeBudget;
    e::scanTrees({expanded},fixtureScanner,seen,found,log,scopeBudget);
    check(found.size()==1 && found[0].confirmed && same(found[0].path,fixture),"P0-3 expanded tree traversal detects harmless custom fingerprint in System32 fixture");
    check(e::scopeDescription(false).find(L"未扫描位置")!=S::npos && e::scopeDescription(false).find(L"桌面/文档/下载")!=S::npos && e::scopeDescription(true).find(L"扩展检查已启用")!=S::npos,"P0-3 both modes list actual scope and blind spots");
    auto coverage=scanReport({}, {L"检查范围："+e::scopeDescription(false),L"未读取目录：fixture [5]"});
    check(coverage.details.find(L"未扫描位置")!=S::npos && coverage.details.find(L"fixture [5]")!=S::npos && coverage.details.find(L"未命中不代表整机无毒")!=S::npos,"P0-3 scan result retains scope and access failures in expandable details");
    e::WalkBudget exhausted;exhausted.limited=true;std::vector<S> coverageLogs;
    e::scanTrees({expanded},fixtureScanner,seen,found,[&](const S& line){coverageLogs.push_back(line);},exhausted);
    check(!coverageLogs.empty() && coverageLogs[0].find(L"预算用尽")!=S::npos,"P0-3 exhausted budget records roots that were not scanned");
    rejects([&]{e::requireRecoveryReady(false,{});},"P0-4 recovery requires completed selected-drive scan");
    rejects([&]{e::requireRecoveryReady(true,{{L"fixture",L"",L"",true,false}});},"P0-4 outstanding confirmed file blocks recovery");
    e::requireRecoveryReady(true,{{L"unknown",L"",L"",false,false}});check(true,"P0-4 unconfirmed advisory does not forge a confirmed blocker");
    S disk=join(root,L"disk"),container=join(disk,L"\uffff"),nested=join(container,L"documents"),sub=join(nested,L"sub");mkdir(disk);mkdir(container);mkdir(nested);mkdir(sub);
    S document=join(sub,L"report.txt");textFile(document,L"harmless user document");
    SetFileAttributesW(xp(container).c_str(),FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
    SetFileAttributesW(xp(nested).c_str(),FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
    SetFileAttributesW(xp(sub).c_str(),FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
    SetFileAttributesW(xp(document).c_str(),FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);
    auto recovery=e::plan(disk,container,true);
    {Journal j(join(root,L"recover-journals"));e::recover(recovery,j,log,true);}
    S moved=join(disk,L"documents");
    check(!(attr(moved)&(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)) && !(attr(join(moved,L"sub"))&(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)) && !(attr(join(join(moved,L"sub"),L"report.txt"))&(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)),"P0-4 nested directories and user files all become visible");
    check(e::canDeleteEmptyContainer(recovery,true),"P0-4 empty UFFFF container offers cleanup");
    {Journal j(join(root,L"empty-journals"));check(!e::deleteEmptyContainer(recovery,false,j,true) && exists(container),"P0-4 empty folder remains without explicit cleanup consent");
        textFile(join(container,L"new-user-file.txt"),L"preserve me");
        check(!e::canDeleteEmptyContainer(recovery,true),"P0-4 nonempty container does not offer enabled deletion");
        rejects([&]{e::deleteEmptyContainer(recovery,true,j,true);},"P0-4 content added after offer prevents deletion");
        check(exists(join(container,L"new-user-file.txt")),"P0-4 newly appeared user file is preserved");
    }
    S emptyDisk=join(root,L"empty-disk"),emptyContainer=join(emptyDisk,L"\uffff");mkdir(emptyDisk);mkdir(emptyContainer);
    auto emptyPlan=e::plan(emptyDisk,emptyContainer,true);
    {Journal j(join(root,L"empty-journals"));check(e::deleteEmptyContainer(emptyPlan,true,j,true),"P0-4 explicit empty-only deletion succeeds");}
    check(!exists(emptyContainer),"P0-4 disposition removes only verified empty container");
    S unsafe=join(container,L"nested");mkdir(unsafe);textFile(join(unsafe,L"harmless.exe"),L"inert");
    rejects([&]{e::plan(disk,container,true);},"P0-4 nested executable still rejects directory recovery");
    S originalLink=join(root,L"original.lnk"),variantLink=join(root,L"variant.lnk"),normalTarget=join(root,L"normal-target.lnk"),plain=join(root,L"plain.lnk");
    const S originalArgs=L"/c start \uffff & start \uffff\\DrvMgr.exe";
    shortcut(originalLink,L"%comspec%",originalArgs);
    shortcut(variantLink,L"C:\\Windows\\System32\\cmd.exe",originalArgs+L" /extra");
    shortcut(normalTarget,L"C:\\Program Files\\Normal\\normal.exe",originalArgs);
    shortcut(plain,L"C:\\Windows\\notepad.exe",L"document.txt");
    check(wormLink(originalLink) && !variantWormLink(originalLink),"P1-5 original lure requires cmd or comspec target and remains confirmed");
    std::vector<Finding> variants;scanner.inspect(variantLink,variants,log);
    check(variants.size()==1 && !variants[0].confirmed && variants[0].review==ReviewKind::LinkVariant,"P1-5 appended-argument lure becomes high suspicious review candidate");
    check(!wormLink(normalTarget) && !variantWormLink(normalTarget) && !wormLink(plain) && !variantWormLink(plain),"P1-5 non-cmd and ordinary shortcuts are not lure matches");
    S driveVariant=join(root,L"drive-variant.lnk");shortcut(driveVariant,L"cmd.exe",L"/c start E:\\uffff & start E:\\uffff\\DrvMgr.exe /x");
    // Explicit U+FFFF rather than the literal letters in the drive-prefix fixture.
    S driveArgs=L"/c start E:\\"+S(1,wchar_t(0xffff))+L" & start E:\\"+S(1,wchar_t(0xffff))+L"\\DrvMgr.exe /x";
    S realDriveVariant=join(root,L"drive-prefix.lnk");shortcut(realDriveVariant,L"cmd.exe",driveArgs);
    check(variantWormLink(realDriveVariant) && !wormLink(realDriveVariant),"P1-5 drive-prefixed lure is review-only");
    {Journal j(join(root,L"variant-journals"));check(!e::quarantineReviewed(variants[0],false,j,log) && exists(variantLink),"P1-5 variant shortcut retained without consent");
        check(e::quarantineReviewed(variants[0],true,j,log) && !exists(variantLink),"P1-5 explicit reviewed shortcut quarantine succeeds without weakening cleanOne");}
    S high=join(temp,L"sysgredlvrs.exe");textFile(high,L"unknown harmless named payload fixture");
    std::vector<Finding> highFindings;scanner.inspect(high,highFindings,log);
    check(highFindings.size()==1 && !highFindings[0].confirmed && highFindings[0].review==ReviewKind::HighRiskName,"P1-6 unknown same-name payload in Temp is high suspicious rather than confirmed");
    S ordinary=join(root,L"ordinary");mkdir(ordinary);S ordinaryName=join(ordinary,L"DrvMgr.exe");textFile(ordinaryName,L"harmless normal directory name");
    std::vector<Finding> ordinaryFindings;scanner.inspect(ordinaryName,ordinaryFindings,log);
    check(ordinaryFindings.size()==1 && ordinaryFindings[0].review==ReviewKind::None && !ordinaryFindings[0].confirmed,"P1-6 same name outside configured risky roots remains advisory only");
    {Journal j(join(root,L"reviewed-high-journals"));int stopped=0;
        auto stop=[&](const Finding& f,Journal&,Log){++stopped;check(same(f.path,high),"P1-6 reviewed stop callback is limited to confirmed user-selected path");};
        check(!e::quarantineReviewed(highFindings[0],false,j,log,stop) && stopped==0 && exists(high),"P1-6 no process or file action without per-item consent");
        check(e::quarantineReviewed(highFindings[0],true,j,log,stop) && stopped==1 && !exists(high),"P1-6 consented high-risk file uses revalidation and mocked exact process action");
        rejects([&]{e::quarantineReviewed(ordinaryFindings[0],true,j,log,stop);},"P1-6 ordinary same-name advisory cannot enter manual isolation");
    }
    std::vector<S> revivalLog;
    bool revival=e::postCleanReview({{high,L"",L"",true,false}},{high},[&](const S& line){revivalLog.push_back(line);},[](const S&){return true;});
    auto revivalResult=cleanReport(revivalLog);
    check(revival && revivalResult.warning && revivalResult.content.find(L"重启后复查")!=S::npos,"P1-6 file and process revival snapshot produces warning and reboot rescan steps");
    check(!e::postCleanReview({{high,L"",L"",true,false}},{},log,[](const S&){return false;}),"P1-6 absent file and process do not invent a revival");
    // More task-specific regression cases are appended here.
    std::cout<<"TOTAL PASS "<<passed<<std::endl;return 0;
}catch(const Error& error){std::cerr<<utf8(error.text)<<std::endl;return 1;}}
