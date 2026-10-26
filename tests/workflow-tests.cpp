#include "workflow.hpp"
#include <iostream>
using namespace usb;namespace e=enhanced;
static int passed=0;
static void check(bool value,const char* message){if(!value)throw Error{fromUtf8(message)};++passed;std::cout<<"PASS "<<message<<std::endl;}
static void rejects(const std::function<void()>& fn,const char* message){bool rejected=false;try{fn();}catch(const Error&){rejected=true;}check(rejected,message);}
static void seed(e::ScanSession& s,const std::vector<S>& roots,bool removable=false) {
    s.initialized=true;e::ScanGroup g{L"fixture",removable,true,{}, {}, {}};
    for(const auto& r:roots)e::addScanRoot(g,r);
    s.groups.push_back(std::move(g));
}
static Finding inspect(const S& path,const std::vector<e::HashRule>& catalog) {
    e::Scanner scan(catalog);std::vector<Finding> found;scan.inspect(path,found,[](const S&){});if(found.empty())throw Error{L"fixture not detected"};return found[0];
}
int wmain(int argc,wchar_t** argv){try{
    if(argc!=2)return 2;
    S root=full(argv[1]);mkdir(root);auto quiet=[](const S&){};
    S a=join(root,L"scan-a"),b=join(root,L"scan-b");mkdir(a);mkdir(b);
    for(int i=0;i<7;++i)textFile(join(a,L"data-"+num(i)+L".txt"),L"harmless scan data");
    textFile(join(b,L"second.txt"),L"second group");
    e::ScanSession scan;seed(scan,{a});seed(scan,{b},true);
    e::scanPage(scan,quiet,{}, {},2);
    check(scan.pending() && !scan.complete && scan.checked==3,"paged host limit does not consume independent USB budget");
    size_t previous=scan.checked;std::vector<size_t> progress;
    e::scanPage(scan,quiet,[&](const S&,size_t n){progress.push_back(n);},{},2);
    check(scan.checked>previous && scan.checked<=previous+2,"resume continues without rereading completed files");
    for(size_t i=1;i<progress.size();++i)check(progress[i]>=progress[i-1],"resumed progress count is monotonic");
    while(scan.pending())e::scanPage(scan,quiet,{}, {},2);
    check(scan.complete && scan.checked==8 && scan.seen.size()==8,"all pages enumerate each distinct file once");
    check(scan.criticalReady(),"complete selected scope permits critical-ready state");
    e::ScanSession cancelled;seed(cancelled,{a});e::scanPage(cancelled,quiet,{},[]{return true;},2);
    check(cancelled.cancelled && cancelled.pending() && cancelled.checked==0,"stop before read retains resumable work");
    e::scanPage(cancelled,quiet,{}, {},100);check(cancelled.complete && cancelled.checked==7,"stopped scan can resume");
    e::ScanSession excluded;seed(excluded,{a});excluded.excluded={a};e::scanPage(excluded,quiet,{});
    check(excluded.checked==0 && excluded.complete,"quarantine subtree is not scanned");
    e::ScanSession missing;seed(missing,{join(root,L"missing")},true);e::scanPage(missing,quiet,{});
    check(!missing.criticalReady() && !missing.criticalErrors.empty(),"unreadable USB directory prevents recovery readiness");
    S large=join(root,L"hash.bin");textFile(large,S(100000,L'x'));int beats=0;
    check(e::cancellableHash(large,[]{return false;},[&](uint64_t){++beats;})==hash(large) && beats>1,"cancellable streaming hash matches normal SHA256");
    rejects([&]{e::cancellableHash(large,[]{return true;});},"cancellation interrupts hashing at a block boundary");
    check(exists(large),"scan cancellation never removes source data");

    S payload=join(root,L"payload.dat");textFile(payload,L"known inert bytes");
    std::vector<e::HashRule> catalog{{hash(payload),L"INERT TEST",L"fixture",L"fixture",size(payload)}};
    Finding exact=inspect(payload,catalog);check(exact.confirmed,"synthetic size and fingerprint match is confirmed");
    auto advisoryCatalog=catalog;advisoryCatalog[0].expectedSize=0;
    auto advisory=inspect(payload,advisoryCatalog);
    check(!advisory.confirmed && advisory.review==ReviewKind::KnownHash && advisory.created.dwHighDateTime,"known hash missing catalog size has explicit review capability and snapshot");
    e::RecoveryContext context;context.root=root;context.serial=volume(root);context.scanned=true;context.criticalComplete=true;
    context.outstanding={exact};rejects([&]{e::requireContext(context,root,context.serial);},"unisolated confirmed threat blocks recovery in engine");
    context.outstanding={advisory};context.retained.insert(e::findingKey(advisory));rejects([&]{e::requireContext(context,root,context.serial);},"keeping a known malicious fingerprint cannot unlock normal recovery");
    Finding candidate=advisory;candidate.review=ReviewKind::ResidualName;context.outstanding={candidate};context.retained.clear();
    rejects([&]{e::requireContext(context,root,context.serial);},"unreviewed relevant residual requires a decision");
    context.retained.insert(e::findingKey(candidate));e::requireContext(context,root,context.serial);check(true,"explicitly retained uncertain residual does not masquerade as isolation");
    context.outstanding[0].digest=L"changed";rejects([&]{e::requireContext(context,root,context.serial);},"retention decision cannot survive changed file evidence");
    candidate.review=ReviewKind::NumericTemp;context.outstanding={candidate};context.retained.clear();e::requireContext(context,root,context.serial);check(true,"numeric filename alone does not block recovery");
    context.outstanding.clear();context.treatment.add(e::ActionKind::Startup,e::ActionStatus::Failed,L"fixture",L"access denied",true);
    rejects([&]{e::requireContext(context,root,context.serial);},"failed startup blocks recovery even after file leaves findings");
    e::setAction(context.treatment,e::ActionKind::Startup,e::ActionStatus::Done,L"fixture");e::requireContext(context,root,context.serial);check(true,"successful retry replaces failed operation state");
    context.criticalComplete=false;rejects([&]{e::requireContext(context,root,context.serial);},"incomplete critical scan blocks recovery");context.criticalComplete=true;
    rejects([&]{e::requireContext(context,root,context.serial+1);},"wrong volume identity blocks recovery");

    e::Workflow w;w.scan.findings={exact};int stopped=0,persisted=0;
    e::HostActions mocks{[&](const Finding&,Journal&,Log){++stopped;},[&](const Finding&,Journal&,Log){++persisted;e::setAction(w.treatment,e::ActionKind::Startup,e::ActionStatus::Failed,L"synthetic-run",L"[5] simulated denied",true);}};
    {Journal journal(join(root,L"journals"));e::treatFinding(exact,true,w,journal,quiet,&mocks,catalog);}
    check(!exists(payload) && w.scan.findings.empty() && stopped==1 && persisted==1,"structured treatment isolates verified file and runs exact associated hooks");
    check(w.treatment.blocked() && w.treatment.count(e::ActionKind::File,e::ActionStatus::Done)==1,"startup failure survives successful file isolation");
    auto report=e::treatmentReport(w);check(report.warning && report.headline.find(L"未处理成功")!=S::npos,"structured failure has unambiguous visible result");
    e::recheckTreatment(w,quiet,3,0,[](const S&){return false;},[]{return std::vector<S>{};});
    check(w.treatment.count(e::ActionKind::Recheck,e::ActionStatus::Done)==1,"bounded repeated observations record clean snapshot");
    int observations=0;e::recheckTreatment(w,quiet,3,0,[&](const S&){return ++observations==2;},[]{return std::vector<S>{};});
    check(w.treatment.count(e::ActionKind::Recheck,e::ActionStatus::Failed)==1,"transient recurrence remains recorded after later absence");
    S reviewed=join(root,L"review.dat");textFile(reviewed,L"reviewable inert known bytes");auto reviewedCatalog=std::vector<e::HashRule>{{hash(reviewed),L"INERT",L"fixture",L"fixture",0}};
    Finding review=inspect(reviewed,reviewedCatalog);e::Workflow manual;manual.scan.findings={review};int manualStop=0,manualRun=0;
    e::HostActions manualMocks{[&](const Finding&,Journal&,Log){++manualStop;},[&](const Finding&,Journal&,Log){++manualRun;}};
    {Journal journal(join(root,L"journals"));e::treatFinding(review,false,manual,journal,quiet,&manualMocks,reviewedCatalog);}
    check(exists(reviewed) && manualStop==0 && manualRun==0,"manual known-hash review requires explicit consent");
    {Journal journal(join(root,L"journals"));e::treatFinding(review,true,manual,journal,quiet,&manualMocks,reviewedCatalog);}
    check(!exists(reviewed) && manualStop==1 && manualRun==1,"manual known-hash isolation handles associated startup path");
    S changed=join(root,L"changed.dat");textFile(changed,L"before");auto changedCatalog=std::vector<e::HashRule>{{hash(changed),L"INERT",L"fixture",L"fixture",size(changed)}};
    Finding stale=inspect(changed,changedCatalog);{Handle file(CreateFileW(xp(changed).c_str(),GENERIC_WRITE,0,nullptr,TRUNCATE_EXISTING,0,nullptr));write(file.h,"new",3);}
    e::Workflow staleWork;{Journal journal(join(root,L"journals"));e::treatFinding(stale,true,staleWork,journal,quiet,&manualMocks,changedCatalog);}
    check(exists(changed) && manualRun==1 && staleWork.treatment.blocked(),"stale source never reaches host cleanup or deletion");

    RegistrySnapshot policy{HKEY_LOCAL_MACHINE,KEY_WOW64_32KEY,L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",L"NoDrives",REG_DWORD,{8,0,0,0}};
    auto duplicate=policy;duplicate.view=KEY_WOW64_64KEY;check(uniqueRegistry({policy,duplicate}).size()==1,"shared NoDrives views produce one decision");
    policy.key=L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";duplicate=policy;duplicate.view=KEY_WOW64_64KEY;
    check(uniqueRegistry({policy,duplicate}).size()==2,"distinct HKLM Run views are not merged just because bytes match");
    policy.hive=HKEY_CURRENT_USER;duplicate=policy;duplicate.view=KEY_WOW64_64KEY;
    check(uniqueRegistry({policy,duplicate}).size()==1,"shared HKCU Run views are deduplicated");
    duplicate.value={16,0,0,0};check(uniqueRegistry({policy,duplicate}).size()==2,"different shared snapshots are preserved for revalidation");

    e::PersistenceItem service;service.kind=e::ActionKind::Service;service.enabled=true;service.references={exact.path};
    check(e::linked(service,exact),"persistence association uses exact file reference");service.references={exact.path+L".backup"};check(!e::linked(service,exact),"substring persistence association is rejected");
    service.references={exact.path};service.enabled=false;check(!e::linked(service,exact),"disabled persistence is not an active restart source");
    {Journal journal(join(root,L"journals"));rejects([&]{e::disablePersistence(service,false,journal);},"persistence cannot change without consent");service.type=SERVICE_WIN32_SHARE_PROCESS;
        rejects([&]{e::disablePersistence(service,true,journal);},"shared service host is rejected before opening service manager for writes");}

    S disk=join(root,L"disk"),hidden=join(disk,L"hidden"),safe=join(hidden,L"safe"),unsafe=join(hidden,L"program");mkdir(disk);mkdir(hidden);mkdir(safe);mkdir(unsafe);
    textFile(join(safe,L"document.txt"),L"user document");textFile(join(unsafe,L"normal.exe"),L"harmless executable-named fixture");
    rejects([&]{e::plan(disk,hidden,true);},"legacy strict recovery still rejects nested executable");
    auto partial=e::plan(disk,hidden,true,true);check(partial.items.size()==1 && partial.skipped.size()==1,"partial recovery isolates the blocked subtree without blocking unrelated documents");
    {Journal journal(join(root,L"journals"));rejects([&]{e::recover(partial,journal,quiet);},"production engine recovery refuses missing workflow context");e::recover(partial,journal,quiet,true);}
    check(exists(join(disk,L"safe\\document.txt")) && exists(join(unsafe,L"normal.exe")),"partial recovery preserves original blocked subtree and restores other documents");
    check(!e::canDeleteEmptyContainer(partial,true),"nonempty original container cannot be deleted after partial restore");
    S numericPath=join(root,L"12345.exe");textFile(numericPath,L"innocent");e::Scanner numericScan;numericScan.tempRoots={root};std::vector<Finding> numeric;numericScan.inspect(numericPath,numeric,quiet);
    {Journal journal(join(root,L"journals"));rejects([&]{e::quarantineReviewed(numeric.front(),true,journal,quiet);},"numeric-only unknown remains diagnostic rather than name-based deletion");}
    check(exists(numericPath),"numeric-only refusal preserves source");
    // Keeping an already handled associated value must not overwrite its real outcome.
    e::Workflow registryWorkflow;RegistrySnapshot dummy{HKEY_CURRENT_USER,0,L"Software\\UsbRecovery-Inert",L"fixture",REG_SZ,{0,0}};
    S identity=registryLocation(dummy);e::setAction(registryWorkflow.treatment,e::ActionKind::Startup,e::ActionStatus::Done,identity);
    {Journal journal(join(root,L"journals"));e::treatRegistry(dummy,false,false,registryWorkflow,journal,quiet);}
    check(registryWorkflow.treatment.count(e::ActionKind::Startup,e::ActionStatus::Done)==1,"unchecked duplicate cannot overwrite successful associated startup removal");
    e::setAction(registryWorkflow.treatment,e::ActionKind::Startup,e::ActionStatus::Failed,identity,L"fixture error",true);
    {Journal journal(join(root,L"journals"));e::treatRegistry(dummy,false,false,registryWorkflow,journal,quiet);}
    check(registryWorkflow.treatment.blocked(),"unchecked duplicate cannot downgrade blocking startup failure to retained");
    e::ScanSession metadata;metadata.initialized=true;e::ScanGroup top{L"top",false,true,{}, {}, {}};
    auto topCursor=std::make_shared<e::DirectoryCursor>(disk,0);topCursor->descend=false;top.directories.push_back(topCursor);metadata.groups.push_back(top);
    e::scanPage(metadata,quiet,{}, {},1);
    check(metadata.pending() && metadata.checked==0,"top-level directory metadata consumes page budget without descending");
    S remembered=join(root,L"tbtcmds.dat");textFile(remembered,L"original retained file");e::Scanner retainedScanner;std::vector<Finding> retainedFiles;retainedScanner.inspect(remembered,retainedFiles,quiet);
    e::RecoveryContext retainedContext;retainedContext.scanned=true;retainedContext.criticalComplete=true;retainedContext.root=root;retainedContext.serial=volume(root);retainedContext.outstanding=retainedFiles;retainedContext.retained.insert(e::findingKey(retainedFiles.front()));
    e::requireContext(retainedContext,root,retainedContext.serial);
    {Handle handle(CreateFileW(xp(remembered).c_str(),GENERIC_WRITE,0,nullptr,TRUNCATE_EXISTING,0,nullptr));write(handle.h,"changed",7);}
    rejects([&]{e::requireContext(retainedContext,root,retainedContext.serial);},"engine revalidates retained files against actual disk before recovery");
    e::Workflow pendingSettings;pendingSettings.scan.initialized=true;pendingSettings.registryChecked=true;pendingSettings.scan.root=root;pendingSettings.scan.serial=volume(root);pendingSettings.startups={dummy};
    auto unreviewed=pendingSettings.recovery();
    rejects([&]{e::requireContext(unreviewed,root,volume(root));},"unreviewed startup settings cannot be silently omitted from recovery context");
    std::cout<<"TOTAL PASS "<<passed<<std::endl;return 0;
}catch(const Error& e){std::cerr<<utf8(e.text)<<std::endl;return 1;}}
