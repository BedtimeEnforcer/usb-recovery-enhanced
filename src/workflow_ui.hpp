#pragma once
#include <sddl.h>

static S currentSid() {
    HANDLE token=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))fail(L"读取当前用户");Handle handle(token);
    DWORD n=0;GetTokenInformation(token,TokenUser,nullptr,0,&n);std::vector<BYTE> bytes(n);
    if(!GetTokenInformation(token,TokenUser,bytes.data(),n,&n))fail(L"读取用户身份");
    LPWSTR sid=nullptr;if(!ConvertSidToStringSidW(((TOKEN_USER*)bytes.data())->User.Sid,&sid))fail(L"转换用户身份");S result=sid;LocalFree(sid);return result;
}
static bool needAdministrator() {
    if(admin())return true;
    if(msgBox(L"需要管理员权限",L"需要管理员权限才能查杀",L"点击“是”将打开系统授权窗口，然后重新检查当前电脑和 U 盘。",TDCBF_YES_BUTTON|TDCBF_NO_BUTTON,TD_INFORMATION_ICON)!=IDYES)return false;
    wchar_t exe[32768];DWORD n=GetModuleFileNameW(nullptr,exe,32768);if(!n || n>=32768)fail(L"读取程序位置");
    S args=L"--rescan --origin-sid "+currentSid();S root=selectedRoot();if(!root.empty())args+=L" --root "+root;
    SHELLEXECUTEINFOW info{};info.cbSize=sizeof(info);info.hwnd=window;info.lpVerb=L"runas";info.lpFile=exe;info.lpParameters=args.c_str();info.nShow=SW_SHOWNORMAL;
    if(!ShellExecuteExW(&info)){if(GetLastError()!=ERROR_CANCELLED)fail(L"打开管理员版本");return false;}
    // Keep the original window and its state; an alternate administrator may be rejected by SID.
    return false;
}
struct WorkflowDialogDetails { S title,text; };
static HRESULT CALLBACK workflowDialogCallback(HWND dialog,UINT notification,WPARAM button,LPARAM,LONG_PTR data) {
    if(notification==TDN_BUTTON_CLICKED && button==4090){
        const auto* details=(const WorkflowDialogDetails*)data;
        showTextReport(details->title,details->text,dialog);return S_FALSE;
    }
    return S_OK;
}
static int workflowDialog(const S& title,const S& headline,const S& content,const std::vector<std::pair<int,S>>& actions,const S& details=L"",bool warning=false) {
    std::vector<TASKDIALOG_BUTTON> buttons;for(const auto& a:actions)buttons.push_back({a.first,a.second.c_str()});
    if(!details.empty())buttons.push_back({4090,L"查看详情"});
    WorkflowDialogDetails extra{title+L" · 详情",details};
    TASKDIALOGCONFIG cfg{};cfg.cbSize=sizeof(cfg);cfg.hwndParent=window;cfg.pszWindowTitle=title.c_str();cfg.pszMainInstruction=headline.c_str();cfg.pszContent=content.c_str();
    cfg.pszMainIcon=warning?TD_WARNING_ICON:TD_INFORMATION_ICON;
    cfg.dwFlags=TDF_POSITION_RELATIVE_TO_WINDOW|TDF_ALLOW_DIALOG_CANCELLATION;
    if(!buttons.empty())cfg.dwFlags|=TDF_USE_COMMAND_LINKS;
    cfg.cxWidth=260; // Explicit dialog units; long diagnostics live in a separate scrollable window.
    cfg.dwCommonButtons=TDCBF_CLOSE_BUTTON;cfg.cButtons=UINT(buttons.size());cfg.pButtons=buttons.empty()?nullptr:buttons.data();
    cfg.pfCallback=workflowDialogCallback;cfg.lpCallbackData=(LONG_PTR)&extra;
    int clicked=IDCANCEL;HRESULT hr=TaskDialogIndirect(&cfg,&clicked,nullptr,nullptr);
    if(FAILED(hr))throw Error{L"无法打开结果窗口 ["+num((DWORD)hr)+L"]"};
    return clicked;
}
static void scanWorkflow(bool resume) {
    if(busy)return;
    S root=selectedRoot();stopRequested=false;SetWindowTextW(GetDlgItem(window,ID_STOP),L"停止检查");
    if(resume && (root.empty()!=workflow.scan.root.empty() || (!root.empty() && !workflow.scan.root.empty() && !same(root,workflow.scan.root))))resume=false;
    startScanProgress();
    run(L"正在检查……",[root,resume]{
        NativeFs native;
        if(!resume){
            auto prior=workflow.treatment;auto retries=workflow.retryRuns;
            workflow=enhanced::Workflow{};workflow.treatment=std::move(prior);workflow.retryRuns=std::move(retries);
            enhanced::initializeScan(workflow.scan,root,logLine);
        }
        enhanced::scanPage(workflow.scan,logLine,scanProgress,[]{return stopRequested.load();});
        if(!workflow.scan.cancelled){
            auto diagnostic=[](const S& line){workflow.diagnostics.push_back(line);logLine(line);};
            workflow.registryChecked=true;
            workflow.startups=namedStartupCandidates(diagnostic,&workflow.registryChecked);workflow.policies=noDrivesPolicies(diagnostic);
            if(!workflow.registryChecked)workflow.scan.criticalErrors.push_back(L"指定启动项未能读取，请以管理员身份补查。");
            // This is an independent inventory of executable references, not a claim of full persistence detection.
            scanProgress(L"正在核对服务与计划任务的关联",workflow.scan.checked);
            workflow.persistence=enhanced::serviceInventory(diagnostic,[]{return stopRequested.load();});auto tasks=enhanced::taskInventory(diagnostic,[]{return stopRequested.load();});
            workflow.persistence.insert(workflow.persistence.end(),tasks.begin(),tasks.end());enhanced::mutexDiagnostic(diagnostic);
            workflow.inventoryComplete=!stopRequested.load();if(!workflow.inventoryComplete){workflow.scan.cancelled=true;workflow.registryChecked=false;}
        }
        findings=workflow.scan.findings;startupFindings=workflow.startups;policyFindings=workflow.policies;
        lastScanDetails=enhanced::sessionScope(workflow.scan);for(const auto& d:workflow.diagnostics)lastScanDetails+=L"\r\n"+d;
    },[]{
        SetWindowTextW(GetDlgItem(window,ID_SCAN),(workflow.scan.pending() || !workflow.inventoryComplete)?L"继续检查":L"重新检查");
        size_t confirmed=0,possible=0;for(const auto& f:workflow.scan.findings)(f.confirmed?confirmed:possible)++;
        S title=workflow.scan.cancelled?L"检查已停止":workflow.scan.complete?L"检查结束":L"本轮检查结束，还有位置待检查";
        S body=confirmed?L"本次发现 "+num(confirmed)+L" 项病毒。":L"本次未发现已确认病毒。";
        if(possible)body+=L"\r\n另有 "+num(possible)+L" 项文件需要查看。";
        if(!workflow.startups.empty() || !workflow.policies.empty())body+=L"\r\n发现相关启动项或磁盘显示设置，可在处理列表确认。";
        size_t shown=0;for(const auto& f:workflow.scan.findings)if(f.confirmed && shown++<5)body+=L"\r\n"+f.path;
        if(!workflow.scan.criticalErrors.empty())body+=L"\r\n关键位置未检查完成，请查看详情并补查。";
        body+=L"\r\n未命中不代表整机无毒。";
        std::vector<std::pair<int,S>> actions;
        if(!workflow.scan.findings.empty() || !workflow.startups.empty() || !workflow.policies.empty())actions.push_back({401,confirmed?L"查杀 / 查看发现":L"查看发现"});
        if(workflow.scan.pending() || !workflow.inventoryComplete)actions.push_back({402,L"继续检查"});
        else if(!workflow.scan.criticalErrors.empty())actions.push_back({404,L"重新检查关键位置"});
        else if(!workflow.scan.root.empty())actions.push_back({403,L"恢复文件"});
        int chosen=workflowDialog(L"检查结果",title,body,actions,lastScanDetails,confirmed || possible || !workflow.scan.complete);
        if(chosen==401)reviewWorkflow();else if(chosen==402)scanWorkflow(true);else if(chosen==403)restoreWorkflow();else if(chosen==404)scanWorkflow(false);
    });
}
struct ReviewRow {
    int kind=0; // 0=file, 1=startup, 2=policy
    Finding file{};RegistrySnapshot registry{};bool eligible=false,selected=false;
};
struct ReviewWindow {
    HWND window=nullptr,list=nullptr,description=nullptr;std::vector<ReviewRow> rows;bool apply=false,closed=false,initializing=true;
};
static LRESULT CALLBACK reviewWindowProc(HWND h,UINT m,WPARAM w,LPARAM l) {
    auto state=(ReviewWindow*)GetWindowLongPtrW(h,GWLP_USERDATA);
    if(m==WM_NCCREATE){state=(ReviewWindow*)((CREATESTRUCTW*)l)->lpCreateParams;SetWindowLongPtrW(h,GWLP_USERDATA,(LONG_PTR)state);}
    if(!state)return DefWindowProcW(h,m,w,l);
    if(m==WM_SIZE){int width=LOWORD(l),height=HIWORD(l);
        MoveWindow(state->list,12,54,width-24,std::max(80,height-160),TRUE);
        MoveWindow(state->description,12,height-98,width-24,45,TRUE);
        MoveWindow(GetDlgItem(h,2),12,height-42,260,30,TRUE);MoveWindow(GetDlgItem(h,3),width-120,height-42,108,30,TRUE);return 0;}
    if(m==WM_NOTIFY && ((NMHDR*)l)->hwndFrom==state->list && !state->initializing){auto n=(NMLISTVIEW*)l;
        if(n->iItem>=0 && size_t(n->iItem)<state->rows.size()){
            auto& row=state->rows[n->iItem];
            if(n->hdr.code==LVN_ITEMCHANGING && (n->uChanged&LVIF_STATE) && !row.eligible && ((n->uNewState&LVIS_STATEIMAGEMASK)>>12)==2)return TRUE;
            if(n->hdr.code==LVN_ITEMCHANGED && (n->uNewState&LVIS_SELECTED)){
                S detail=row.kind==0?row.file.reason:row.kind==2?L"这项设置控制磁盘是否显示。自己或管理员设置的策略应保留。":L"仅凭启动项名称不能确定病毒。请核对启动内容；正常程序应保留。";
                SetWindowTextW(state->description,detail.c_str());}
            if(n->hdr.code==NM_DBLCLK){S detail=row.kind==0?enhanced::reviewFileText(row.file):registryLocation(row.registry)+L"\r\n"+registryValueText(row.registry);showTextReport(L"项目详情",detail);}
        }return 0;
    }
    if(m==WM_COMMAND){if(LOWORD(w)==2){for(size_t i=0;i<state->rows.size();++i)state->rows[i].selected=state->rows[i].eligible && ListView_GetCheckState(state->list,int(i));state->apply=true;DestroyWindow(h);return 0;}
        if(LOWORD(w)==3){DestroyWindow(h);return 0;}}
    if(m==WM_CLOSE){DestroyWindow(h);return 0;}
    if(m==WM_DESTROY){state->closed=true;return 0;}
    return DefWindowProcW(h,m,w,l);
}
static bool chooseTreatment(ReviewWindow& state) {
    WNDCLASSW wc{};wc.lpfnWndProc=reviewWindowProc;wc.hInstance=GetModuleHandleW(nullptr);wc.lpszClassName=L"UsbTreatmentList";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&wc);
    state.window=CreateWindowW(wc.lpszClassName,L"确认本次处理",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,PX(870),PX(500),window,nullptr,wc.hInstance,&state);
    if(!state.window)fail(L"打开处理列表");
    HWND label=CreateWindowW(L"STATIC",L"勾选要处理的项目；未勾选项目将保留。只提示的项目不提供隔离。双击可看详情。",WS_CHILD|WS_VISIBLE,12,12,PX(820),32,state.window,nullptr,wc.hInstance,nullptr);
    SendMessageW(label,WM_SETFONT,(WPARAM)font,TRUE);
    state.list=CreateWindowW(WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|WS_TABSTOP|LVS_REPORT|LVS_SINGLESEL,0,0,1,1,state.window,(HMENU)1,wc.hInstance,nullptr);
    ListView_SetExtendedListViewStyle(state.list,LVS_EX_CHECKBOXES|LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER);
    const wchar_t* headings[]={L"项目",L"判断 / 操作",L"所在位置 / 启动内容"};int widths[]={180,220,420};
    for(int i=0;i<3;++i){LVCOLUMNW col{};col.mask=LVCF_TEXT|LVCF_WIDTH;col.pszText=(LPWSTR)headings[i];col.cx=PX(widths[i]);ListView_InsertColumn(state.list,i,&col);}
    SendMessageW(state.list,WM_SETFONT,(WPARAM)font,TRUE);
    for(size_t i=0;i<state.rows.size();++i){auto& row=state.rows[i];S label=row.kind==0?name(row.file.path):row.kind==1?row.registry.name:L"恢复磁盘显示";
        S action=row.kind==0?(row.file.confirmed?L"已确认病毒 · 隔离":row.file.review==ReviewKind::KnownHash?L"已知恶意指纹 · 确认隔离":row.eligible?L"待确认 · 可备份隔离":L"线索 · 只提示"):L"设置 · 确认后备份移除";
        S path=row.kind==0?row.file.path:registryLocation(row.registry);
        LVITEMW item{};item.mask=LVIF_TEXT;item.iItem=int(i);item.pszText=(LPWSTR)label.c_str();ListView_InsertItem(state.list,&item);
        ListView_SetItemText(state.list,int(i),1,(LPWSTR)action.c_str());ListView_SetItemText(state.list,int(i),2,(LPWSTR)path.c_str());ListView_SetCheckState(state.list,int(i),row.selected);
    }
    state.description=CreateWindowW(L"STATIC",L"隔离会同时处理已验证的关联启动项，以及直接关联的服务 / 计划任务。相关配置会先备份。",WS_CHILD|WS_VISIBLE,0,0,1,1,state.window,nullptr,wc.hInstance,nullptr);
    SendMessageW(state.description,WM_SETFONT,(WPARAM)font,TRUE);
    HWND apply=CreateWindowW(L"BUTTON",L"处理勾选项，并保留其余项目",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,0,0,1,1,state.window,(HMENU)2,wc.hInstance,nullptr);
    HWND cancel=CreateWindowW(L"BUTTON",L"取消",WS_CHILD|WS_VISIBLE|WS_TABSTOP,0,0,1,1,state.window,(HMENU)3,wc.hInstance,nullptr);
    SendMessageW(apply,WM_SETFONT,(WPARAM)font,TRUE);SendMessageW(cancel,WM_SETFONT,(WPARAM)font,TRUE);
    state.initializing=false;RECT client;GetClientRect(state.window,&client);SendMessageW(state.window,WM_SIZE,0,MAKELPARAM(client.right,client.bottom));
    EnableWindow(window,FALSE);ShowWindow(state.window,SW_SHOW);MSG message;
    while(!state.closed && GetMessageW(&message,nullptr,0,0)>0){if(!IsDialogMessageW(state.window,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
    EnableWindow(window,TRUE);SetForegroundWindow(window);return state.apply;
}
static void reviewWorkflow() {
    if(busy)return;
    if(!workflow.scan.initialized){msgBox(L"处理发现",L"请先检查病毒",L"点击“开始检查”，发现病毒后即可查杀。");return;}
    ReviewWindow review;
    for(const auto& f:workflow.scan.findings)review.rows.push_back({0,f,{},f.confirmed || (enhanced::requiresDecision(f) && !f.digest.empty()),f.confirmed});
    for(const auto& r:workflow.startups)review.rows.push_back({1,{},r,true,false});
    for(const auto& r:workflow.policies)review.rows.push_back({2,{},r,true,false});
    if(review.rows.empty()){resultWorkflow();return;}
    if(!chooseTreatment(review))return;
    bool any=false;for(const auto& row:review.rows)any=any || row.selected;
    if(any && !needAdministrator())return;
    auto rows=review.rows;
    run(L"正在备份并处理……",[rows]{
        NativeFs native;Journal journal(data());
        for(const auto& row:rows){if(row.kind==0)enhanced::treatFinding(row.file,row.selected,workflow,journal,logLine);
            else enhanced::treatRegistry(row.registry,row.selected,row.kind==2,workflow,journal,logLine);}
        if(admin())enhanced::retryReferences(workflow,journal,logLine);
        enhanced::recheckTreatment(workflow,logLine);
        auto keepPending=[&](std::vector<RegistrySnapshot>& values,enhanced::ActionKind kind){values.erase(std::remove_if(values.begin(),values.end(),[&](const RegistrySnapshot& r){
            for(const auto& a:workflow.treatment.actions)if(a.kind==kind && a.target==registryLocation(r) && (a.status==enhanced::ActionStatus::Done || a.status==enhanced::ActionStatus::Kept))return true;
            return false;}),values.end());};
        keepPending(workflow.startups,enhanced::ActionKind::Startup);keepPending(workflow.policies,enhanced::ActionKind::Policy);findings=workflow.scan.findings;
    },[]{updateFolders();resultWorkflow();});
}
static void resultWorkflow() {
    if(busy)return;
    if(!workflow.scan.initialized){reviewWorkflow();return;}
    auto report=enhanced::treatmentReport(workflow);
    if(workflow.treatment.actions.empty()){report.headline=L"查看本次检查结果";report.content=L"发现 "+num(workflow.scan.findings.size())+L" 项文件、"+num(workflow.startups.size())+L" 个指定启动项和 "+num(workflow.policies.size())+L" 个磁盘显示设置。";}
    std::vector<std::pair<int,S>> actions;
    if(!workflow.scan.root.empty())actions.push_back({403,L"恢复隐藏文件到根目录"});
    actions.push_back({401,L"查看 / 处理发现"});actions.push_back({405,L"检查详情与善后"});
    if(workflow.scan.pending() || !workflow.inventoryComplete)actions.push_back({402,L"继续检查"});
    if(workflow.treatment.blocked())actions.push_back({406,admin()?L"重新检查 / 重试失败项":L"以管理员身份重试"});
    if(report.anyIsolated)actions.push_back({407,L"保存文件后重启"});
    int chosen=workflowDialog(L"处理结果",report.headline,report.content,actions,report.details,report.warning);
    if(chosen==401){if(workflow.scan.findings.empty() && workflow.startups.empty() && workflow.policies.empty())msgBox(L"处理列表",L"没有待确认项目",L"可以恢复文件，或查看处理结果。" );else reviewWorkflow();}
    else if(chosen==402)scanWorkflow(true);else if(chosen==403)restoreWorkflow();
    else if(chosen==405)showTextReport(L"检查详情与善后",lastScanDetails+L"\r\n\r\n"+aftercareChecklist());
    else if(chosen==406){if(!needAdministrator())return;
        run(L"重新核对失败项……",[]{NativeFs native;Journal j(data());enhanced::retryReferences(workflow,j,logLine);},[]{scanWorkflow(false);});}
    else if(chosen==407 && msgBox(L"重启复查",L"请先保存正在编辑的文件",L"现在重启电脑？重启后再次打开本程序检查电脑和 U 盘。",TDCBF_YES_BUTTON|TDCBF_NO_BUTTON)==IDYES)
        if(!rebootNow())msgBox(L"重启",L"未能自动重启",L"请从开始菜单重启电脑。");
}
static void restoreWorkflow() {
    if(busy)return;
    S root=selectedRoot();
    if(root.empty()){
        workflowDialog(L"恢复文件",L"请先扫描 U 盘",enhanced::usbScanRequiredText(),{},L"",true);return;
    }
    auto context=workflow.recovery();
    if(!enhanced::matchesRecoveryVolume(context,root,volume(root))){
        int answer=workflowDialog(L"恢复文件",L"请先扫描所选 U 盘",enhanced::usbScanRequiredText(),{{402,L"扫描所选 U 盘"}},L"",true);
        if(answer==402)scanWorkflow(false);
        return;
    }
    auto index=SendMessageW(folderBox,CB_GETCURSEL,0,0);
    if(index<0 || size_t(index)>=folders.size()){msgBox(L"恢复文件",L"未找到需要恢复的隐藏目录",L"请确认 U 盘已插入，并查看盘内文件是否已经位于根目录。");return;}
    try{auto context=workflow.recovery();enhanced::requireContext(context,root,volume(root));}
    catch(const Error& e){int answer=workflowDialog(L"恢复文件",L"暂不能恢复",e.text,{{401,L"查看 / 处理发现"},{402,L"继续检查"}},L"",true);
        if(answer==401)reviewWorkflow();else if(answer==402)scanWorkflow(workflow.scan.pending());return;}
    S container=folders[size_t(index)];
    run(L"正在生成恢复预览……",[root,container]{
        NativeFs native;enhanced::recheckTreatment(workflow,logLine,1,0);auto context=workflow.recovery();enhanced::requireContext(context,root,volume(root));
        pending=enhanced::prepareRecovery(workflow,root,container);
    },[]{
        S content=L"恢复到："+pending.root+L"\r\n将恢复 "+num(pending.items.size())+L" 项文件或文件夹；重名会保留双方。";
        if(!pending.skipped.empty())content+=L"\r\n另有 "+num(pending.skipped.size())+L" 项暂不恢复，保留原处。";
        S detail;for(const auto& m:pending.items)detail+=m.source+L" → "+m.dest+L"\r\n";for(const auto& s:pending.skipped)detail+=L"保留："+s+L"\r\n";
        if(pending.items.empty()){msgBox(L"恢复文件",L"没有可恢复的用户文件",content,TDCBF_OK_BUTTON,TD_INFORMATION_ICON,detail);offerDeleteEmpty(pending);return;}
        if(workflowDialog(L"恢复预览",L"确认恢复这些文件？",content,{{403,L"开始恢复"}},detail)!=403)return;
        Plan p=pending;
        run(L"正在恢复，请勿拔出 U 盘……",[p]{
            NativeFs native;enhanced::recheckTreatment(workflow,logLine,1,0);Journal journal(data());enhanced::executeRecovery(workflow,p,journal,logLine);
        },[p]{updateFolders();S content=L"已恢复 "+num(p.items.size())+L" 项文件或文件夹。";
            if(!p.skipped.empty())content+=L"\r\n另有 "+num(p.skipped.size())+L" 项保留原处。";
            content+=L"\r\n恢复成功不等于清毒。请保存文件并重启复查。";
            int answer=workflowDialog(L"恢复结果",p.skipped.empty()?L"文件恢复完成":L"文件已部分恢复",content,{{408,L"查看结果与下一步"}});
            offerDeleteEmpty(p);if(answer==408)resultWorkflow();});
    });
}
