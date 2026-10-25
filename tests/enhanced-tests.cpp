#include "enhanced_engine.hpp"
#include "ui_results.hpp"
#include <iostream>
using namespace usb;
namespace e=enhanced;
int passed=0;
void check(bool b,const char* message) { if(!b)throw Error{L"Assertion failed: "+fromUtf8(message)}; ++passed; std::cout<<"PASS "<<message<<std::endl; }
void rejects(const std::function<void()>& f,const char* message) { bool rejected=false;try{f();}catch(const Error&){rejected=true;}check(rejected,message); }
void setField(std::vector<BYTE>& b,size_t p,uint32_t value,size_t n=4) { for(size_t i=0;i<n;++i)b[p+i]=BYTE(value>>(i*8)); }
std::vector<BYTE> linkBytes(const S& target,const S& args) {
    std::vector<BYTE>b(76);b[0]=76;
    BYTE clsid[]={1,20,2,0,0,0,0,0,192,0,0,0,0,0,0,70};memcpy(b.data()+4,clsid,16);
    b[20]=0xA0;
    if(!target.empty()) {
        b[20]|=2;size_t start=b.size(),n=36+(target.size()+1)*2;
        b.resize(start+n);setField(b,start,uint32_t(n));setField(b,start+4,36);setField(b,start+8,1);setField(b,start+28,36);
        memcpy(b.data()+start+36,target.data(),target.size()*2);
    }
    size_t pos=b.size();b.resize(pos+2+args.size()*2);setField(b,pos,uint32_t(args.size()),2);memcpy(b.data()+pos+2,args.data(),args.size()*2);
    return b;
}
void binaryFile(const S& p,const std::vector<BYTE>& b) { Handle h(CreateFileW(xp(p).c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,0,nullptr));if(h.h==INVALID_HANDLE_VALUE)fail(L"create fixture");write(h.h,b.data(),DWORD(b.size())); }
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc!=2)return 2;
        S root=full(argv[1]);mkdir(root);
        // Disposable test key, outside all Windows startup locations.
        struct TestKey {
            S path = L"Software\\UsbRecoveryTest-" + num(GetCurrentProcessId()) + L"-" + num(GetTickCount64());
            HKEY h = nullptr;
            ~TestKey() { if(h)RegCloseKey(h); RegDeleteKeyW(HKEY_CURRENT_USER,path.c_str()); }
        } key;
        check(RegCreateKeyExW(HKEY_CURRENT_USER,key.path.c_str(),0,nullptr,0,KEY_ALL_ACCESS,nullptr,&key.h,nullptr)==ERROR_SUCCESS,"create isolated registry fixture");
        RunEntry entry{HKEY_CURRENT_USER,0,key.path,L"fixture",L"original",L"",REG_SZ};
        auto setValue = [&](const S& value) { check(RegSetValueExW(key.h,entry.name.c_str(),0,REG_SZ,(const BYTE*)value.c_str(),DWORD((value.size()+1)*sizeof(wchar_t)))==ERROR_SUCCESS,"write isolated registry fixture"); };
        {
            Journal j(join(root,L"registry-journal"));
            removeRun(entry,j);
            check(true,"already absent startup value is not a failure");
            setValue(L"changed");
            bool changed=false;try{removeRun(entry,j);}catch(const Error& error){changed=error.text.find(L"内容已变化")!=S::npos;}
            check(changed && RegQueryValueExW(key.h,entry.name.c_str(),nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS,"changed startup value is preserved with precise reason");
            setValue(entry.value);removeRun(entry,j);
            check(RegQueryValueExW(key.h,entry.name.c_str(),nullptr,nullptr,nullptr,nullptr)==ERROR_FILE_NOT_FOUND,"matching startup value is removed after backup");
            auto missing=entry;missing.key+=L"\\Missing";removeRun(missing,j);
            check(true,"already absent startup key is not a failure");
        }
        check(startupError(L"读取启动项",ERROR_ACCESS_DENIED).find(L"权限不足")!=S::npos && startupError(L"读取启动项",ERROR_INVALID_DATA).find(L"[13]")!=S::npos,"registry errors distinguish permissions and retain other codes");
        std::set<S> unique;
        bool valid=true;for(const auto& r:e::rules()) { valid=valid && r.digest.size()==64 && !r.family.empty() && !r.source.empty() && !r.solution.empty(); for(auto c:r.digest)valid=valid && ((c>=L'0'&&c<=L'9')||(c>=L'A'&&c<=L'F'));unique.insert(r.digest); }
        check(valid && unique.size()==15,"15 unique well-formed sourced fingerprints");
        check(e::matchDigest(lower(e::rules()[5].digest))->family==e::rules()[5].family,"catalog lookup accepts lowercase SHA256");
        check(!e::matchDigest(L"bad") && !e::matchDigest(S(64,L'0')),"unknown and malformed hashes rejected");
        check(e::rulesText().find(L"尚未进行加强版虚拟机真实感染验收")!=S::npos && e::rulesText().find(L"SHA-256")!=S::npos,"offline catalog includes provenance and validation limits");

        auto quiet=[](const S&){};
        S exact=join(root,L"renamed-payload.data");textFile(exact,L"inert exact-match test data");S digest=hash(exact);
        std::vector<e::HashRule> fixtureRules{{digest,L"TEST ONLY",L"local inert fixture",L"fixture remediation",size(exact)}};
        e::Scanner scanner(fixtureRules);std::vector<Finding> found;scanner.inspect(exact,found,quiet);
        check(found.size()==1 && found[0].confirmed && found[0].digest==digest,"exact matching works for new sizes and arbitrary extensions");
        S innocent=join(root,L"DrvMgr.exe");textFile(innocent,L"harmless same name");found.clear();scanner.inspect(innocent,found,quiet);
        check(found.size()==1 && !found[0].confirmed && exists(innocent),"same-name unknown executable is never confirmed");
        S doc=join(root,L"normal.pdf");textFile(doc,L"normal content");found.clear();scanner.inspect(doc,found,quiet);
        check(found.empty(),"normal document has no finding");
        S disguised=join(root,L"invoice.pdf.exe");textFile(disguised,L"not executable");found.clear();scanner.inspect(disguised,found,quiet);
        check(found.size()==1 && !found[0].confirmed,"double extension is advisory only");

        auto link=linkBytes(L"C:\\Windows\\System32\\msiexec.exe",L"/i https://example.invalid/inert.msi");
        auto parsed=e::parseLink(link);
        check(parsed.target==L"C:\\Windows\\System32\\msiexec.exe" && parsed.args==L"/i https://example.invalid/inert.msi","bounded parser reads Unicode LinkInfo target and arguments");
        check(!e::linkHint(parsed).empty(),"remote msiexec shortcut produces advisory");
        check(e::linkHint({L"C:\\normal.exe",L"",L"",L"/help"}).empty(),"normal application shortcut preserved");
        check(e::linkHint({L"",L"",L"",L"E:\\.Trashes\\586\\payload.js"}).find(L"Bondat")!=S::npos,"Bondat-style script path recognized without executing target");
        check(e::linkHint({L"",L"",L"",L"E:\\资料\\report.js"}).empty(),"ordinary JavaScript reference alone is not a worm");
        check(e::linkHint({L"",L"",L"",L"E:\\\u00a0\\RECYCLER.BIN\\x32dbg.exe"}).find(L"PlugX")!=S::npos,"PlugX-style Unicode path combination recognized");
        check(e::linkHint({L"",L"",L"",L"E:\\RECYCLER.BIN\\notes.txt"}).empty(),"recycler folder name alone is not malware");
        check(e::linkHint({L"cmd.exe",L"",L"",L"/c type inert.usb|cmd"}).find(L"Raspberry")!=S::npos,"type-cmd shortcut pipeline is advisory");
        auto cut=link;cut.resize(80);rejects([&]{e::parseLink(cut);},"truncated LinkInfo rejected");
        auto offset=link;setField(offset,76+28,0xFFFFFFF0);rejects([&]{e::parseLink(offset);},"out-of-range LinkInfo offset rejected");
        auto stringCut=linkBytes(L"",L"abc");stringCut.pop_back();rejects([&]{e::parseLink(stringCut);},"truncated StringData rejected");
        check(e::parseLink(std::vector<BYTE>(76,0)).args.empty(),"non-LNK data is not parsed as a command");
        S suspectLink=join(root,L"suspect.lnk");binaryFile(suspectLink,link);found.clear();scanner.inspect(suspectLink,found,quiet);
        check(found.size()==1 && !found[0].confirmed,"new shortcut heuristic cannot enable automatic isolation");

        S script=L"inert tokens only: Scripting.FileSystemObject WScript.Shell DriveType Drives CreateShortcut Attributes RegWrite";
        check(e::scriptHint(script) && !e::scriptHint(L"WScript.Shell CreateShortcut"),"USB script requires multiple independent propagation clues");
        std::vector<BYTE> unicode{0xFF,0xFE};for(auto c:script){unicode.push_back(BYTE(c));unicode.push_back(BYTE(c>>8));}
        check(e::scriptHint(e::decodeText(unicode)),"UTF16 script content supported");
        std::vector<BYTE> utf8bom{0xEF,0xBB,0xBF,'a','b','c'};check(e::decodeText(utf8bom)==L"abc","UTF8 BOM decoded correctly");
        S scriptPath=join(root,L"inert.vbs");textFile(scriptPath,script);found.clear();scanner.inspect(scriptPath,found,quiet);
        check(found.size()==1 && !found[0].confirmed,"script clues stay unconfirmed");
        check(e::autorunHint(L"[autorun]\r\nopen=wscript.exe inert.vbs"),"Autorun script entry detected");
        check(!e::autorunHint(L"[autorun]\nicon=usb.ico\nopen=setup.exe") && !e::autorunHint(L"[other]\nopen=wscript inert.vbs"),"legitimate Autorun icon and unrelated sections preserved");
        check(!e::autorunHint(L"[autorun]\n;open=wscript inert.vbs\nlabel=Data"),"commented Autorun command ignored");
        check(e::autorunHint(L"[autorun]\nshell\\open\\command=cscript inert.js"),"Autorun shell command key supported");
        std::vector<BYTE> pe(128,0);pe[0]='M';pe[1]='Z';setField(pe,60,64);pe[64]='P';pe[65]='E';
        std::string fields="path_symantec symantec_dir name_svchost run_cmd usb_dll_name name_mutex";pe.insert(pe.end(),fields.begin(),fields.end());
        check(e::frozenHint(pe),"FROZENHILL PE and configuration combination recognized");pe[0]=0;check(!e::frozenHint(pe),"configuration text alone without PE is not matched");

        S command=L"C:\\Windows\\System32\\rundll32.exe \"C:\\Users\\Public\\bad.dll,Start\"";
        check(e::references(command,L"C:\\Users\\Public\\bad.dll") && !e::references(command,L"C:\\Users\\Public\\bad.dll.bak"),"DLL Run reference uses full path rather than substring");
        check(e::references(L"rundll32.exe C:\\Users\\Public\\random.vdm,Start",L"C:\\Users\\Public\\random.vdm"),"rundll32 persistence supports nonstandard payload extensions");
        check(e::referencedPaths(L"wscript.exe script.vbs").empty() && e::referencedPaths(L"\\\\server\\share\\script.vbs").empty(),"relative and UNC command paths are not followed");
        check(e::references(L"\"C:\\folder with spaces\\script.vbs\"",L"C:\\folder with spaces\\script.vbs"),"quoted direct script persistence path supported");

        int stopCalls=0,runCalls=0;
        e::HostActions mock{[&](const Finding&,Journal&,Log){++stopCalls;},[&](const Finding&,Journal&,Log log){++runCalls;log(L"启动项移除失败（测试）：fixture — denied");}};
        std::vector<S> logs;Finding f{exact,digest,L"test",true,false};
        {Journal j(join(root,L"journals"));e::cleanOne(f,j,[&](const S& s){logs.push_back(s);},mock,fixtureRules);check(!exists(exact) && hash(join(j.dir,L"1.quarantine"))==digest,"new-family cleanup verifies quarantine backup before removal");}
        auto report=cleanReport(logs);check(stopCalls==1 && runCalls==1 && report.warning && report.anyIsolated && report.content.find(L"完整杀毒软件")!=S::npos && report.content.find(L"启动项未清除")!=S::npos,"startup failure and incomplete family remediation remain visible after isolation");
        e::HostActions noHost;
        S unknown=join(root,L"unknown.bin");textFile(unknown,L"unknown");logs.clear();
        {Journal j(join(root,L"journals"));e::cleanOne({unknown,hash(unknown),L"forged confirmed",true,false},j,[&](const S&s){logs.push_back(s);},noHost);}
        check(exists(unknown) && cleanReport(logs).warning,"forged confirmed flag cannot bypass built-in rule validation");
        S changed=join(root,L"changed.bin");textFile(changed,L"changed");logs.clear();
        {Journal j(join(root,L"journals"));e::cleanOne({changed,digest,L"stale",true,false},j,[&](const S&s){logs.push_back(s);},noHost,fixtureRules);}
        check(exists(changed) && !cleanReport(logs).anyIsolated,"changed file is retained");
        {Journal j(join(root,L"journals"));e::cleanOne({unknown,hash(unknown),L"advisory",false,false},j,quiet,mock,fixtureRules);}
        check(exists(unknown) && stopCalls==1,"unconfirmed advisory never invokes host cleanup");

        S disk=join(root,L"disk"),trashes=join(disk,L".Trashes"),container=join(trashes,L"586");mkdir(disk);mkdir(trashes);mkdir(container);
        textFile(join(container,L"report.txt"),L"restorable");textFile(join(disk,L"report.txt"),L"keep original");textFile(join(container,L"payload.js"),L"inert");
        auto p=e::plan(disk,container,true);check(p.items.size()==1 && name(p.items[0].dest)==L"report（恢复1）.txt","Bondat-style nested container recovery skips script and preserves conflicts");
        {Journal j(join(root,L"journals"));e::recover(p,j,quiet,true);}
        check(exists(join(container,L"payload.js")) && exists(join(disk,L"report（恢复1）.txt")),"nested recovery preserves script and restores only user document");
        rejects([&]{e::plan(disk,container);},"production recovery rejects synthetic non-volume root");
        S arbitrary=join(trashes,L"not-numeric");mkdir(arbitrary);rejects([&]{e::plan(disk,arbitrary,true);},"arbitrary nested recovery container rejected");
        auto candidates=e::recoveryFolders(disk);check(std::find(candidates.begin(),candidates.end(),container)!=candidates.end(),"numeric Trashes container appears in recovery choices");
        S nested=join(container,L"nested");mkdir(nested);textFile(join(nested,L"inert.exe"),L"not executable");
        rejects([&]{e::plan(disk,container,true);},"nested executable prevents unsafe directory restoration");
        S safe=join(disk,L"safe");mkdir(safe);textFile(join(safe,L"one.txt"),L"one");auto stale=e::plan(disk,safe,true);textFile(join(safe,L"two.txt"),L"two");
        {Journal j(join(root,L"journals"));rejects([&]{e::recover(stale,j,quiet,true);},"stale enhanced recovery preview rejected");}
        check(exists(join(safe,L"one.txt")),"stale preview rejection preserves original files");
        e::WalkBudget budget;budget.entries=e::ENTRY_LIMIT;int visited=0;e::boundedWalk(safe,[&](const Entry&){++visited;},quiet,budget);
        check(budget.limited && visited==0,"bounded traversal stops before processing beyond limit");
        std::cout<<"TOTAL PASS "<<passed<<std::endl;return 0;
    }catch(const Error& error){std::cerr<<utf8(error.text)<<std::endl;return 1;}
}
