#include "one_click.hpp"
#include <iostream>
using namespace usb; namespace e=enhanced;
static int passed=0;
static void check(bool ok,const char* message){if(!ok)throw Error{fromUtf8(message)};++passed;std::cout<<"PASS "<<message<<std::endl;}
static void rejects(const std::function<void()>& fn,const char* message){bool caught=false;try{fn();}catch(const Error&){caught=true;}check(caught,message);}
int wmain(int argc,wchar_t** argv){try{
    if(argc!=2)return 2;
    S base=full(argv[1]);mkdir(base);auto quiet=[](const S&){};
    S root=join(base,L"usb"),wrapper=join(root,L"\uffff"),app=join(wrapper,L"乘务员软件"),libs=join(app,L"contents");
    mkdir(root);mkdir(wrapper);mkdir(app);mkdir(libs);
    textFile(join(libs,L"ordinary.dll"),L"inert DLL-named data");
    textFile(join(libs,L"app.js"),L"inert script-named data");
    textFile(join(app,L"document.txt"),L"document inside application");
    textFile(join(wrapper,L"U盘修复助手.exe"),L"inert EXE-named data");
    textFile(join(root,L"U盘修复助手.exe"),L"existing root file");
    const std::vector<S> formats={L"exe",L"dll",L"scr",L"com",L"cpl",L"lnk",L"vbs",L"vbe",L"js",L"jse",L"wsf",L"wsh",L"ps1",L"bat",L"cmd",L"hta",L"msi",L"docx",L"zip",L"jpg",L"unknownformat"};
    for(const auto& format:formats)textFile(join(wrapper,L"file."+format),L"inert file data");
    S nestedParent=join(wrapper,L"资料"),nested=join(nestedParent,L"\uffff");mkdir(nestedParent);mkdir(nested);
    textFile(join(nested,L"nested.txt"),L"nested document");
    S outsideParent=join(root,L"以前恢复的目录"),outside=join(outsideParent,L"\uffff");mkdir(outsideParent);mkdir(outside);
    textFile(join(outside,L"nested.txt"),L"second nested document");
    S emptyParent=join(root,L"旧目录"),empty=join(emptyParent,L"\uffff");mkdir(emptyParent);mkdir(empty);
    for(const auto& path:{wrapper,nested,outside,empty})SetFileAttributesW(xp(path).c_str(),FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_READONLY);
    S dllHash=hash(join(libs,L"ordinary.dll")),exeHash=hash(join(wrapper,L"U盘修复助手.exe"));
    S docHash=hash(join(nested,L"nested.txt")),otherHash=hash(join(outside,L"nested.txt"));
    e::OneClickResult result;result.mode=e::RunMode::Full;result.host.scan.initialized=true;result.host.scan.complete=true;
    result.usbs.emplace_back();auto& usb=result.usbs.back();
    e::initializeUsbOnly(usb.scan,{root,L"fixture",volume(root)},true);
    while(!usb.scan.complete)e::scanPage(usb.scan,quiet,{}, {},3);
    {Journal journal(join(base,L"journals"));e::restoreAutomaticDisks(result,journal,quiet,{}, {},true);}
    check(result.recoveryFailures==0 && result.skipped==0,"full-mode restoration accepts ordinary application files after scan");
    check(exists(join(root,L"乘务员软件\\contents\\ordinary.dll")),"application containing DLL and script moves intact to USB root");
    check(hash(join(root,L"乘务员软件\\contents\\ordinary.dll"))==dllHash,"restored application bytes remain unchanged");
    check(hash(join(root,L"U盘修复助手（恢复1）.exe"))==exeHash,"direct executable is restored and colliding original retained");
    bool allFormats=true;for(const auto& format:formats)if(!exists(join(root,L"file."+format)))allFormats=false;
    check(allFormats,"automatic restoration moves every tested extension including scripts installers shortcuts and unknown formats");
    check(hash(join(root,L"nested.txt"))==docHash || hash(join(root,L"nested.txt"))==otherHash,"nested wrapper data reaches USB root");
    check(exists(join(root,L"nested（恢复1）.txt")) && hash(join(root,L"nested.txt"))!=hash(join(root,L"nested（恢复1）.txt")),"nested wrappers preserve both colliding documents");
    check(!exists(wrapper) && !exists(outside) && !exists(empty) && result.removedContainers.size()==4,"all verified empty wrappers including nested and read-only wrappers are removed");
    check(exists(emptyParent) && exists(outsideParent),"ordinary parent directories are preserved");
    check(!(attr(join(root,L"乘务员软件"))&(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)),"restored application is visible");
    S guard=join(root,L"\uffff");mkdir(guard);textFile(join(guard,L"normal.exe"),L"unchanged program data");
    auto legacy=e::plan(root,guard,true,true);
    check(legacy.items.empty() && legacy.skipped.size()==1,"manual recovery keeps its existing strict program policy");
    auto stale=e::plan(root,guard,true,true,true);
    {Handle file(CreateFileW(xp(join(guard,L"normal.exe")).c_str(),GENERIC_WRITE,0,nullptr,TRUNCATE_EXISTING,0,nullptr));if(file.h==INVALID_HANDLE_VALUE)fail(L"change fixture");write(file.h,"changed program data",20);}
    {Journal journal(join(base,L"stale-journal"));rejects([&]{e::recover(stale,journal,quiet,true);},"program data changed after preview is rejected without moving it");}
    check(exists(join(guard,L"normal.exe")),"changed program source remains intact");
    textFile(join(guard,L"DrvMgr.exe"),L"unknown same-name program");
    auto blocked=e::plan(root,guard,true,true,true);
    check(blocked.skipped.size()==1 && exists(join(guard,L"DrvMgr.exe")),"suspicious program names remain blocked and are never deleted");
    check(!e::canDeleteEmptyContainer(blocked,true),"nonempty wrapper is never deleted");
    rejects([&]{e::plan(root,emptyParent,true,true,true);},"program-data recovery cannot flatten an ordinary user folder");
    S sibling=join(base,L"usb-other");mkdir(sibling);S escaped=join(sibling,L"\uffff");mkdir(escaped);
    rejects([&]{e::plan(root,escaped,true,true,true);},"nested wrapper outside selected disk is rejected");
    std::cout<<"TOTAL PASS "<<passed<<std::endl;return 0;
}catch(const Error& error){std::cerr<<utf8(error.text)<<std::endl;return 1;}}
