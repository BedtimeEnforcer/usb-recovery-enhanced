#pragma once
#include "one_click.hpp"

static enhanced::OneClickResult lastAutomatic;
static void startAutomatic(enhanced::RunMode mode,const std::vector<enhanced::DiskTarget>& targets={});
struct UsbPicker {
    HWND dialog=nullptr,list=nullptr,hint=nullptr;
    std::vector<enhanced::DiskTarget> disks,selected;
    bool closed=false,accepted=false;
};
static void refreshPicker(UsbPicker& state) {
    std::vector<enhanced::DiskTarget> selected;
    for(size_t i=0;i<state.disks.size();++i)if(ListView_GetCheckState(state.list,int(i)))selected.push_back(state.disks[i]);
    state.disks=enhanced::removableTargets();ListView_DeleteAllItems(state.list);
    for(size_t i=0;i<state.disks.size();++i){const auto& disk=state.disks[i];S label=disk.root+L"    "+(disk.label.empty()?L"U 盘":disk.label);
        LVITEMW item{};item.mask=LVIF_TEXT;item.iItem=int(i);item.pszText=(LPWSTR)label.c_str();ListView_InsertItem(state.list,&item);
        for(const auto& prior:selected)if(same(prior.root,disk.root) && prior.serial==disk.serial)ListView_SetCheckState(state.list,int(i),TRUE);
    }
    SetWindowTextW(state.hint,state.disks.empty()?L"未检测到 U 盘，请插入后刷新。":L"勾选要处理的 U 盘，可多选。" );
    EnableWindow(GetDlgItem(state.dialog,2),FALSE);
    for(int i=0;i<ListView_GetItemCount(state.list);++i)if(ListView_GetCheckState(state.list,i))EnableWindow(GetDlgItem(state.dialog,2),TRUE);
}
static LRESULT CALLBACK usbPickerProc(HWND h,UINT m,WPARAM w,LPARAM l) {
    auto state=(UsbPicker*)GetWindowLongPtrW(h,GWLP_USERDATA);
    if(m==WM_NCCREATE){state=(UsbPicker*)((CREATESTRUCTW*)l)->lpCreateParams;SetWindowLongPtrW(h,GWLP_USERDATA,(LONG_PTR)state);}
    if(!state)return DefWindowProcW(h,m,w,l);
    if(m==WM_SIZE && state->list){int width=LOWORD(l),height=HIWORD(l);
        MoveWindow(state->hint,PX(20),PX(16),width-PX(40),PX(28),TRUE);
        MoveWindow(state->list,PX(20),PX(54),width-PX(40),height-PX(120),TRUE);
        ListView_SetColumnWidth(state->list,0,width-PX(66));
        MoveWindow(GetDlgItem(h,4),PX(20),height-PX(48),PX(82),PX(30),TRUE);
        MoveWindow(GetDlgItem(h,2),width-PX(240),height-PX(48),PX(130),PX(30),TRUE);
        MoveWindow(GetDlgItem(h,3),width-PX(98),height-PX(48),PX(78),PX(30),TRUE);return 0;}
    if(m==WM_NOTIFY && ((NMHDR*)l)->hwndFrom==state->list && ((NMHDR*)l)->code==LVN_ITEMCHANGED){
        bool any=false;for(int i=0;i<ListView_GetItemCount(state->list);++i)any=any || ListView_GetCheckState(state->list,i);
        EnableWindow(GetDlgItem(h,2),any);return 0;
    }
    if(m==WM_COMMAND){
        if(LOWORD(w)==4){try{refreshPicker(*state);}catch(const Error&){SetWindowTextW(state->hint,L"读取失败，请重新插入 U 盘后刷新。");}return 0;}
        if(LOWORD(w)==2){state->selected.clear();for(size_t i=0;i<state->disks.size();++i)if(ListView_GetCheckState(state->list,int(i)))state->selected.push_back(state->disks[i]);
            if(state->selected.empty())return 0;
            state->accepted=true;DestroyWindow(h);return 0;}
        if(LOWORD(w)==3 || LOWORD(w)==IDCANCEL){DestroyWindow(h);return 0;}
    }
    if(m==WM_CLOSE){DestroyWindow(h);return 0;}
    if(m==WM_DESTROY){state->closed=true;return 0;}
    return DefWindowProcW(h,m,w,l);
}
static bool chooseUsbTargets(UsbPicker& state) {
    WNDCLASSW wc{};wc.lpfnWndProc=usbPickerProc;wc.hInstance=GetModuleHandleW(nullptr);wc.lpszClassName=L"UsbOnlyPicker";
    wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);
    RECT owner{};GetWindowRect(window,&owner);
    state.dialog=CreateWindowW(wc.lpszClassName,L"U盘专杀 · 选择 U 盘",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,
        owner.left+PX(120),owner.top+PX(60),PX(560),PX(370),window,nullptr,wc.hInstance,&state);
    if(!state.dialog)fail(L"打开 U 盘选择窗口");
    state.hint=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,0,0,1,1,state.dialog,nullptr,wc.hInstance,nullptr);
    state.list=CreateWindowW(WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|LVS_REPORT|LVS_NOCOLUMNHEADER|LVS_SHOWSELALWAYS,
        0,0,1,1,state.dialog,(HMENU)1,wc.hInstance,nullptr);
    ListView_SetExtendedListViewStyle(state.list,LVS_EX_CHECKBOXES|LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
    LVCOLUMNW column{};column.mask=LVCF_WIDTH;column.cx=PX(480);ListView_InsertColumn(state.list,0,&column);
    for(auto button:std::vector<std::pair<int,S>>{{2,L"开始查杀并恢复"},{3,L"取消"},{4,L"刷新"}}) {
        HWND child=CreateWindowW(L"BUTTON",button.second.c_str(),WS_CHILD|WS_VISIBLE|WS_TABSTOP|(button.first==2?BS_DEFPUSHBUTTON:0),
            0,0,1,1,state.dialog,(HMENU)(INT_PTR)button.first,wc.hInstance,nullptr);SendMessageW(child,WM_SETFONT,(WPARAM)font,TRUE);
    }
    SendMessageW(state.hint,WM_SETFONT,(WPARAM)font,TRUE);SendMessageW(state.list,WM_SETFONT,(WPARAM)font,TRUE);refreshPicker(state);
    RECT client{};GetClientRect(state.dialog,&client);SendMessageW(state.dialog,WM_SIZE,0,MAKELPARAM(client.right,client.bottom));
    EnableWindow(window,FALSE);ShowWindow(state.dialog,SW_SHOW);MSG message;
    while(!state.closed && GetMessageW(&message,nullptr,0,0)>0)if(!IsDialogMessageW(state.dialog,&message)){TranslateMessage(&message);DispatchMessageW(&message);}
    EnableWindow(window,TRUE);SetForegroundWindow(window);return state.accepted;
}
static void startAutomatic(enhanced::RunMode mode,const std::vector<enhanced::DiskTarget>& selected) {
    if(busy)return;
    if(mode==enhanced::RunMode::Full && !admin()) {
        wchar_t exe[32768];DWORD n=GetModuleFileNameW(nullptr,exe,32768);if(!n || n>=32768)fail(L"读取程序位置");
        S args=L"--auto-full --origin-sid "+currentSid();
        SHELLEXECUTEINFOW info{};info.cbSize=sizeof(info);info.hwnd=window;info.lpVerb=L"runas";info.lpFile=exe;info.lpParameters=args.c_str();info.nShow=SW_SHOWNORMAL;
        if(!ShellExecuteExW(&info)){if(GetLastError()==ERROR_CANCELLED)SetWindowTextW(statusBox,L"已取消授权，尚未开始查杀");else fail(L"获取管理员权限");}
        else SetWindowTextW(statusBox,L"已打开管理员窗口，请在新窗口查看进度");
        return;
    }
    auto targets=mode==enhanced::RunMode::Full?enhanced::removableTargets():selected;
    if(mode==enhanced::RunMode::UsbOnly && targets.empty())return;
    stopRequested=false;SetWindowTextW(GetDlgItem(window,ID_STOP),L"停止");startScanProgress();
    run(L"正在扫描……",[mode,targets]{
        try{enhanced::runAutomatic(lastAutomatic,mode,targets,logLine,scanProgress,[]{return stopRequested.load();});}
        catch(const Error& e){++lastAutomatic.recoveryFailures;lastAutomatic.issues.push_back(e.text);logLine(e.text);}
        enhanced::summarizeAutomatic(lastAutomatic);
    },[]{
        auto report=enhanced::automaticReport(lastAutomatic);
        SetWindowTextW(statusBox,(report.headline+L" · 已隔离 "+num(lastAutomatic.isolated)+L" 项，恢复 "+num(lastAutomatic.restored)+L" 项").c_str());
        workflowDialog(lastAutomatic.mode==enhanced::RunMode::Full?L"全盘杀毒":L"U盘专杀",report.headline,report.content,{},report.details,report.warning);
    });
}
static void openUsbOnly() {
    if(busy)return;
    int answer=workflowDialog(L"U盘专杀",L"仅供未中病毒的电脑使用",L"建议使用“全盘杀毒”。",
        {{501,L"全盘杀毒（推荐）"},{502,L"继续 U盘专杀"}},L"",true);
    if(answer==501){startAutomatic(enhanced::RunMode::Full);return;}
    if(answer!=502)return;
    UsbPicker picker;if(chooseUsbTargets(picker))startAutomatic(enhanced::RunMode::UsbOnly,picker.selected);
}
