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
static int passed=0;
static void check(bool ok,const char* message) {
    if(!ok)throw Error{fromUtf8(message)};
    ++passed;std::cout<<"PASS "<<message<<std::endl;
}
static bool reviewDefaults=false,reviewBlocked=false,cancelReview=false;
static void CALLBACK reviewTimer(HWND,UINT,UINT_PTR timer,DWORD) {
    HWND h=FindWindowW(L"UsbTreatmentList",nullptr);if(!h)return;KillTimer(nullptr,timer);
    HWND list=GetDlgItem(h,1);
    reviewDefaults=ListView_GetCheckState(list,0) && !ListView_GetCheckState(list,1) && !ListView_GetCheckState(list,2);
    ListView_SetCheckState(list,1,TRUE);reviewBlocked=!ListView_GetCheckState(list,1);
    ListView_SetCheckState(list,2,TRUE);
    PostMessageW(h,WM_COMMAND,cancelReview?3:2,0);
}
static int dialogStage=0,measuredWidth=0,detailWidth=0;
static bool detailPreserved=false;
static S longDiagnostic;
static void CALLBACK dialogTimer(HWND,UINT,UINT_PTR timer,DWORD) {
    HWND dialog=FindWindowW(L"#32770",L"宽度回归测试");if(!dialog)return;
    if(dialogStage==0){RECT rect{};GetWindowRect(dialog,&rect);measuredWidth=rect.right-rect.left;
        dialogStage=1;PostMessageW(dialog,TDM_CLICK_BUTTON,4090,0);return;}
    HWND detail=FindWindowW(L"UsbReviewReport",L"宽度回归测试 · 详情");if(!detail)return;
    RECT rect{};GetWindowRect(detail,&rect);detailWidth=rect.right-rect.left;
    detailPreserved=controlText(GetDlgItem(detail,1))==longDiagnostic;
    DestroyWindow(detail);KillTimer(nullptr,timer);PostMessageW(dialog,TDM_CLICK_BUTTON,401,0);
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
        HWND extended=GetDlgItem(window,ID_EXPANDED),reviewButton=GetDlgItem(window,ID_REVIEW);
        check(extended && text(extended).find(L"推荐检查")!=S::npos && IsWindowVisible(extended),"recommended scope always includes extended locations");
        check(reviewButton && IsWindowVisible(reviewButton),"manual review is a visible independent entry point");
        showTextReport(L"fixture aftercare",aftercareChecklist());
        HWND aftercare=FindWindowW(L"UsbReviewReport",L"fixture aftercare");
        check(aftercare && text(GetDlgItem(aftercare,1)).find(L"UPnP")!=S::npos && text(GetDlgItem(aftercare,1)).find(L"新助记词")!=S::npos,"scrollable completion checklist exposes network and credential instructions");
        DestroyWindow(aftercare);
        showTextReport(L"fixture scope",enhanced::scopeDescription(false));
        HWND scope=FindWindowW(L"UsbReviewReport",L"fixture scope");
        check(scope && text(GetDlgItem(scope,1)).find(L"未扫描位置")!=S::npos,"scrollable result exposes unscanned locations");
        DestroyWindow(scope);
        startScanProgress();stopRequested=false;
        SendMessageW(window,WM_COMMAND,ID_STOP,0);
        check(stopRequested.load() && scanning,"stop button requests cooperative cancellation without destroying worker UI");
        stopScanProgress();
        ReviewWindow review;
        Finding exact{join(root,L"file-0.txt"),L"",L"fixture",true,false};
        Finding numeric{join(root,L"file-1.txt"),L"",L"numeric diagnostic",false,false,ReviewKind::NumericTemp};
        Finding suspect{join(root,L"file-2.txt"),L"",L"reviewable fixture",false,false,ReviewKind::ResidualName};
        review.rows={{0,exact,{},true,true},{0,numeric,{},false,false},{0,suspect,{},true,false}};
        SetTimer(nullptr,0,200,reviewTimer);
        check(chooseTreatment(review),"unified list returns explicit confirmation");
        check(reviewDefaults,"confirmed defaults selected while uncertain entries default preserved");
        check(reviewBlocked && !review.rows[1].selected,"diagnostic-only row cannot be selected for destructive treatment");
        check(review.rows[0].selected && review.rows[2].selected,"per-item choices survive unified list submission");
        check(exists(exact.path) && exists(suspect.path),"review UI itself does not modify files");
        ReviewWindow cancellation;cancellation.rows=review.rows;cancelReview=true;
        SetTimer(nullptr,0,200,reviewTimer);
        check(!chooseTreatment(cancellation),"cancel exits the complete decision sheet without applying choices");
        longDiagnostic=L"未扫描：C:\\Windows\\"+S(12000,L'x')+L"\\locked.dat";
        SetTimer(nullptr,0,200,dialogTimer);
        int dialogResult=workflowDialog(L"宽度回归测试",L"检查结束",L"本次发现 3 项病毒。\r\n请选择下一步。",
            {{401,L"查杀 / 查看发现"},{402,L"继续检查"},{403,L"恢复隐藏文件到根目录"},{405,L"检查详情与善后"},{406,L"重新检查 / 重试失败项"},{407,L"保存文件后重启"}},longDiagnostic,true);
        RECT ownerRect{};GetWindowRect(window,&ownerRect);
        std::cout<<"MEASURED RESULT WIDTH "<<measuredWidth<<" OWNER WIDTH "<<(ownerRect.right-ownerRect.left)<<std::endl;
        check(dialogResult==401 && measuredWidth>0 && measuredWidth<ownerRect.right-ownerRect.left,"long diagnostics and six actions cannot stretch result window beyond main window");
        check(detailPreserved && detailWidth>0,"separate scrollable details preserve complete diagnostic text");
        std::cout<<"RESULT WINDOW WIDTH "<<measuredWidth<<" DETAILS WIDTH "<<detailWidth<<std::endl;
        DestroyWindow(window);
        std::cout<<"TOTAL PASS "<<passed<<std::endl;return 0;
    }catch(const Error& e){std::cerr<<utf8(e.text)<<std::endl;return 1;}
}
