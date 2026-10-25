#define wWinMain UsbRecoveryEntry
#include "../src/main.cpp"
#undef wWinMain
#include <iostream>

static void pump() {
    MSG message;
    while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)) {
        TranslateMessage(&message); DispatchMessageW(&message);
    }
}
static S text(HWND h) { wchar_t b[32768]; GetWindowTextW(h,b,32768);return b; }
static void check(bool ok,const char* message) {
    if(!ok)throw Error{fromUtf8(message)};
    std::cout<<"PASS "<<message<<std::endl;
}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc!=2)return 2;
        S root=full(argv[1]);mkdir(root);
        for(int i=0;i<30;++i)textFile(join(root,L"file-"+num(i)+L".txt"),L"harmless progress fixture");
        INITCOMMONCONTROLSEX cc{sizeof(cc),ICC_STANDARD_CLASSES|ICC_PROGRESS_CLASS};InitCommonControlsEx(&cc);
        WNDCLASSW cls{};cls.lpfnWndProc=proc;cls.hInstance=GetModuleHandleW(nullptr);cls.lpszClassName=L"UsbProgressTest";RegisterClassW(&cls);
        window=CreateWindowW(cls.lpszClassName,L"Progress UI test",WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,0,0,900,630,nullptr,nullptr,cls.hInstance,nullptr);
        check(window!=nullptr,"create real application controls");
        ShowWindow(window,SW_SHOWNOACTIVATE);
        startScanProgress();
        run(L"正在检查，请稍候……",[root]{
            enhanced::WalkBudget budget;size_t count=0;
            enhanced::Scanner scanner;
            std::vector<Finding> results;
            enhanced::boundedWalk(root,[&](const Entry& entry){
                scanProgress(entry.path,count);
                Sleep(150); // deterministic slow read for timer and heartbeat checks
                scanner.inspect(entry.path,results,[](const S&){});
                scanProgress(entry.path,++count);
            },[](const S&){},budget,{},[&](const S& path){scanProgress(path,count);});
        });
        const auto deadline=GetTickCount64()+10000;
        size_t samples=0;S prior;bool changed=false,sawPath=false,sawCount=false;
        while(busy && GetTickCount64()<deadline) {
            pump();Sleep(25);
            S status=text(statusBox),path=text(scanPathBox);
            if(status.find(L"已检查")!=S::npos) {
                if(!prior.empty() && prior!=status)changed=true;
                prior=status;++samples;
                sawPath=sawPath || path.find(root)!=S::npos;
                sawCount=sawCount || status.find(L"已检查 0 个")==S::npos;
            }
            if(busy) {
                check(IsWindowVisible(progressBox)!=FALSE && (GetWindowLongW(progressBox,GWL_STYLE)&PBS_MARQUEE),"marquee stays visible during work");
                break;
            }
        }
        while(busy && GetTickCount64()<deadline) {
            pump();Sleep(25);
            if(busy) {
                S status=text(statusBox),path=text(scanPathBox);
                if(status.find(L"已检查")!=S::npos) {
                    if(!prior.empty() && prior!=status)changed=true;
                    prior=status;++samples;
                    sawPath=sawPath || path.find(root)!=S::npos;
                    sawCount=sawCount || status.find(L"已检查 0 个")==S::npos;
                }
            }
        }
        check(!busy && samples>10 && changed,"UI timer updates while worker scans files");
        check(sawPath && sawCount,"current real file path and completed count reach controls");
        check(scanChecked==30 && text(statusBox).find(L"共检查 30 个文件")!=S::npos,"final summary retains actual file count");
        check(!scanning && !IsWindowVisible(progressBox) && !IsWindowVisible(scanPathBox),"completion stops progress and clears stale path");
        RECT pathRect,barRect,client;GetWindowRect(scanPathBox,&pathRect);GetWindowRect(progressBox,&barRect);GetClientRect(window,&client);
        check(pathRect.bottom<=barRect.top && client.bottom>0,"progress text and bar do not overlap");
        DestroyWindow(window);
        std::cout<<"TOTAL PASS 7"<<std::endl;return 0;
    }catch(const Error& e){std::cerr<<utf8(e.text)<<std::endl;return 1;}
}
