#include "engine.hpp"
#include "ui_results.hpp"
#include <commctrl.h>
#include <commdlg.h>
#include <memory>
using namespace usb;
#ifdef USB_ENHANCED
#include "enhanced_engine.hpp"
namespace app = enhanced;
static std::vector<RegistrySnapshot> policyFindings;
static const wchar_t* const APP_TITLE = L"U 盘修复助手 · 加强版";
#else
namespace app = usb;
static const wchar_t* const APP_TITLE = L"U 盘修复助手";
#endif

#ifndef EM_SETBKGNDCOLOR
#define EM_SETBKGNDCOLOR (WM_USER + 67)
#endif

// ================= 配色（扁平风格） =================
static const COLORREF C_BG = RGB(245, 247, 250);       // 窗口背景
static const COLORREF C_CARD = RGB(255, 255, 255);     // 卡片底
static const COLORREF C_BORDER = RGB(229, 231, 235);   // 边框
static const COLORREF C_PRIMARY = RGB(37, 99, 235);    // 主色
static const COLORREF C_PRIMARY_P = RGB(30, 64, 175);  // 主色按下
static const COLORREF C_TEXT = RGB(17, 24, 39);        // 主文字
static const COLORREF C_SUB = RGB(107, 114, 128);      // 次要文字
static const COLORREF C_MUTED = RGB(156, 163, 175);    // 弱文字
static const COLORREF C_BTN2_TEXT = RGB(55, 65, 81);   // 次按钮文字
static const COLORREF C_BTN2_PRESS = RGB(243, 244, 246);
static const COLORREF C_DIS_BG = RGB(229, 231, 235);   // 禁用底
static const COLORREF C_DIS_TEXT = RGB(156, 163, 175); // 禁用文字
static const COLORREF C_GREEN = RGB(16, 185, 129);     // 状态点

// ===== DPI 缩放：96 dpi 为基准，高 DPI 下按比例放大，保持视觉比例一致 =====
static int g_dpi = 96;
static inline int PX(int v) { return MulDiv(v, g_dpi, 96); }

// ================= 全局状态 =================
HWND window, driveBox, folderBox, logBox, statusBox, progressBox, scanPathBox;
HFONT font, titleFont, smallFont, btnFont;
HICON appIcon, appIcon40, appIconSmall;
bool busy = false;
std::vector<S> roots, folders;
std::vector<Finding> findings;
Plan pending;
enum { ID_SCAN = 101, ID_CLEAN, ID_RESTORE, ID_REFRESH, ID_SAVE, ID_ABOUT, ID_DRIVE, ID_FOLDER, ID_RULES, ID_LOG_TOGGLE, ID_REVIEW = 113 };
static SRWLOCK scanLock = SRWLOCK_INIT;
static S scanPath;
static size_t scanChecked = 0;
static bool scanning = false;
static ULONGLONG scanStarted = 0;
static void scanProgress(const S& path, size_t checked) {
    AcquireSRWLockExclusive(&scanLock);
    scanPath = path; scanChecked = checked;
    ReleaseSRWLockExclusive(&scanLock);
}
static void renderScanProgress() {
    AcquireSRWLockShared(&scanLock);
    S path = scanPath; size_t checked = scanChecked;
    ReleaseSRWLockShared(&scanLock);
    auto seconds = (GetTickCount64() - scanStarted) / 1000;
    S text = L"正在检查 · 已检查 " + num(checked) + L" 个文件 · 用时 " + num(seconds / 60) + L" 分 " + num(seconds % 60) + L" 秒";
    SetWindowTextW(statusBox, text.c_str());
    SetWindowTextW(scanPathBox, (L"当前位置：" + path).c_str());
}
static void stopScanProgress() {
    KillTimer(window, 1);
    SendMessageW(progressBox, PBM_SETMARQUEE, FALSE, 0);
    ShowWindow(progressBox, SW_HIDE);
    ShowWindow(scanPathBox, SW_HIDE);
    scanning = false;
}
static void startScanProgress() {
    scanning = true; scanStarted = GetTickCount64();
    scanProgress(L"正在准备检查", 0);
    ShowWindow(progressBox, SW_SHOW);
    ShowWindow(scanPathBox, SW_SHOW);
    SendMessageW(progressBox, PBM_SETMARQUEE, TRUE, 40);
    SetTimer(window, 1, 200, nullptr);
    renderScanProgress();
}
const UINT LOG_MSG = WM_APP + 1, DONE_MSG = WM_APP + 2;

// 布局矩形：layout() 计算，paintAll() 使用，保证绘制与控件位置一致
static RECT rcIcon, rcTitle, rcSub, rcCard1, rcCard2, rcLbl1, rcLbl2, rcLogTitle, rcDot, rcStatus;
#ifdef USB_ENHANCED
static bool logExpanded = false;
static RECT rcSteps[3];
static HFONT cardFont;
#endif

struct Result { S error; std::function<void()> done; };

// ================= 绘制辅助 =================
static void fillRound(HDC dc, const RECT& rc, int rad, COLORREF fill, COLORREF border)
{
    HRGN rgn = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, rad * 2, rad * 2);
    SelectClipRgn(dc, rgn);
    HBRUSH b = CreateSolidBrush(fill);
    FillRect(dc, &rc, b);
    DeleteObject(b);
    SelectClipRgn(dc, nullptr);
    HPEN p = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ op = SelectObject(dc, p);
    HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, rc.left, rc.top, rc.right - 1, rc.bottom - 1, rad * 2, rad * 2);
    SelectObject(dc, op);
    SelectObject(dc, ob);
    DeleteObject(p);
    DeleteObject(rgn);
}

static void drawTextAt(HDC dc, const S& s, const RECT& rc, HFONT f, COLORREF c, UINT fmt)
{
    HGDIOBJ of = SelectObject(dc, f ? f : font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, c);
    RECT r = rc;
    DrawTextW(dc, s.c_str(), -1, &r, fmt);
    SelectObject(dc, of);
}

static bool isPrimaryButton(int id) {
#ifdef USB_ENHANCED
    return id == ID_SCAN;
#else
    return id == ID_SCAN || id == ID_CLEAN || id == ID_RESTORE;
#endif
}

static void paintAll(HDC dc, const RECT& client)
{
    HBRUSH bg = CreateSolidBrush(C_BG);
    FillRect(dc, &client, bg);
    DeleteObject(bg);

    fillRound(dc, rcCard1, PX(12), C_CARD, C_BORDER);
    fillRound(dc, rcCard2, PX(12), C_CARD, C_BORDER);

    if (appIcon40)
        DrawIconEx(dc, rcIcon.left, rcIcon.top, appIcon40, PX(40), PX(40), 0, nullptr, DI_NORMAL);

#ifdef USB_ENHANCED
    drawTextAt(dc, L"U 盘修复助手", rcTitle, titleFont, C_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    drawTextAt(dc, L"多类威胁检查 · 安全隔离 · 隐藏文件恢复", rcSub, smallFont, C_SUB, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    RECT badge{PX(270),PX(27),PX(336),PX(49)};
    fillRound(dc,badge,PX(6),RGB(229,239,255),RGB(229,239,255));
    drawTextAt(dc,L"加强版",badge,smallFont,C_PRIMARY,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    RECT heading{rcCard1.left+PX(20),rcCard1.top+PX(14),rcCard1.right-PX(20),rcCard1.top+PX(38)};
    drawTextAt(dc,L"检查范围",heading,cardFont,C_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT note=heading;note.left=rcCard1.left+PX(220);
    drawTextAt(dc,L"选择 U 盘时，会同时检查电脑",note,smallFont,C_SUB,DT_RIGHT|DT_VCENTER|DT_SINGLELINE);
    const wchar_t* titles[]={L"检查威胁",L"隔离确认项",L"恢复隐藏文件"};
    const wchar_t* descriptions[]={L"检查电脑与所选 U 盘\n只检查，不更改文件",L"仅处理已确认的威胁\n结果会逐项弹窗显示",L"预览后恢复，重名保留\n先清理电脑传播源"};
    for(int i=0;i<3;++i) {
        const RECT& card=rcSteps[i];fillRound(dc,card,PX(12),C_CARD,C_BORDER);
        RECT number{card.left+PX(18),card.top+PX(18),card.left+PX(50),card.top+PX(48)};
        fillRound(dc,number,PX(7),RGB(236,243,255),RGB(236,243,255));
        drawTextAt(dc,L"0"+num(i+1),number,btnFont,C_PRIMARY,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        RECT title{card.left+PX(62),card.top+PX(18),card.right-PX(14),card.top+PX(48)};
        drawTextAt(dc,titles[i],title,cardFont,C_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        RECT detail{card.left+PX(18),card.top+PX(57),card.right-PX(14),card.top+PX(96)};
        drawTextAt(dc,descriptions[i],detail,font,C_SUB,DT_LEFT|DT_TOP);
    }
    drawTextAt(dc,L"操作记录",rcLogTitle,font,C_TEXT,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
    RECT recordNote=rcLogTitle;recordNote.left+=PX(90);recordNote.right=rcCard2.right-PX(240);
    drawTextAt(dc,logExpanded?L"详细过程与跳过项":L"按需展开，结果会弹窗提示",recordNote,smallFont,C_MUTED,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
#else
    drawTextAt(dc, APP_TITLE, rcTitle, titleFont, C_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
#endif

    drawTextAt(dc, L"目标设备", rcLbl1, font, C_SUB, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    drawTextAt(dc, L"隐藏目录", rcLbl2, font, C_SUB, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
#ifndef USB_ENHANCED
    drawTextAt(dc, L"运行日志", rcLogTitle, smallFont, C_MUTED, DT_LEFT | DT_TOP | DT_SINGLELINE);
#endif

    // 状态圆点
    HBRUSH g = CreateSolidBrush(busy ? C_PRIMARY : C_GREEN);
    HGDIOBJ ob = SelectObject(dc, g);
    HGDIOBJ op = SelectObject(dc, GetStockObject(NULL_PEN));
    Ellipse(dc, rcDot.left, rcDot.top, rcDot.right, rcDot.bottom);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(g);
}

// 统一消息框：用 TaskDialog 排版（标题栏 + 粗体主指令 + 正文 + 图标 + 按钮），比 MessageBox 更整洁、层次分明。
// 老系统不支持 TaskDialog 时自动回退到 MessageBox。
static int msgBox(const S& title, const S& main, const S& content, TASKDIALOG_COMMON_BUTTON_FLAGS buttons = TDCBF_OK_BUTTON, PCWSTR icon = TD_INFORMATION_ICON, const S& details = L"")
{
    TASKDIALOGCONFIG cfg{};
    cfg.cbSize = sizeof(cfg);
    cfg.hwndParent = window;
    cfg.hInstance = GetModuleHandleW(nullptr);
    cfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
    cfg.dwCommonButtons = buttons;
    cfg.pszWindowTitle = title.c_str();
    cfg.pszMainInstruction = main.c_str();
    cfg.pszContent = content.c_str();
    if(!details.empty()) {
        cfg.pszExpandedInformation=details.c_str();
        cfg.pszExpandedControlText=L"查看善后与复查清单";
        cfg.pszCollapsedControlText=L"收起详细清单";
    }
    cfg.pszMainIcon = icon;
    int btn = 0;
    if (FAILED(TaskDialogIndirect(&cfg, &btn, nullptr, nullptr)))
        return MessageBoxW(window, content.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
    return btn;
}
// ================= 业务逻辑 =================
void logLine(const S& s) { PostMessageW(window, LOG_MSG, 0, (LPARAM)new S(s)); }
void append(const S& s) { int n = GetWindowTextLengthW(logBox); SendMessageW(logBox, EM_SETSEL, n, n); S line = s + L"\r\n"; SendMessageW(logBox, EM_REPLACESEL, FALSE, (LPARAM)line.c_str()); }
S controlText(HWND h) { int n = GetWindowTextLengthW(h); std::vector<wchar_t> b(n + 1); GetWindowTextW(h, b.data(), n + 1); return b.data(); }
S selectedRoot() { LRESULT i = SendMessageW(driveBox, CB_GETCURSEL, 0, 0); return i >= 0 && (size_t)i < roots.size() ? roots[i] : L""; }
void updateFolders()
{
    folders.clear();
    SendMessageW(folderBox, CB_RESETCONTENT, 0, 0);
    S root = selectedRoot();
    if (root.empty()) {
#ifdef USB_ENHANCED
        SendMessageW(folderBox,CB_ADDSTRING,0,(LPARAM)L"选择 U 盘后显示隐藏目录");
        SendMessageW(folderBox,CB_SETCURSEL,0,0);EnableWindow(folderBox,FALSE);
#endif
        return;
    }
    try {
#ifdef USB_ENHANCED
        folders = enhanced::recoveryFolders(root);
        for (const auto& p : folders) {
            S label = p.substr(root.size());
            if (name(p) == L"\uffff") label = L"特殊字符隐藏目录（U+FFFF）";
            SendMessageW(folderBox, CB_ADDSTRING, 0, (LPARAM)label.c_str());
        }
#else
        for (auto& e : list(root))
            if ((e.attrs & FILE_ATTRIBUTE_DIRECTORY) && !(e.attrs & FILE_ATTRIBUTE_REPARSE_POINT) && !systemName(e.path) && ((e.attrs & FILE_ATTRIBUTE_HIDDEN) || name(e.path) == L"\uffff")) {
                folders.push_back(e.path);
                S label = name(e.path) == L"\uffff" ? L"特殊字符隐藏目录（U+FFFF）" : name(e.path);
                SendMessageW(folderBox, CB_ADDSTRING, 0, (LPARAM)label.c_str());
            }
#endif
        if (!folders.empty()) SendMessageW(folderBox, CB_SETCURSEL, 0, 0);
#ifdef USB_ENHANCED
        if(folders.empty()) { SendMessageW(folderBox,CB_ADDSTRING,0,(LPARAM)L"未找到可恢复的隐藏目录");SendMessageW(folderBox,CB_SETCURSEL,0,0); }
        EnableWindow(folderBox,!folders.empty());
#endif
    } catch (const Error& e) { append(e.text); }
}
void updateDrives()
{
    roots = { L"" };
    SendMessageW(driveBox, CB_RESETCONTENT, 0, 0);
#ifdef USB_ENHANCED
    SendMessageW(driveBox, CB_ADDSTRING, 0, (LPARAM)L"仅检查电脑");
#else
    SendMessageW(driveBox, CB_ADDSTRING, 0, (LPARAM)L"只检查电脑（不检查 U 盘）");
#endif
    DWORD bits = GetLogicalDrives();
    for (int i = 0; i < 26; i++) if (bits & (1u << i)) {
        S root = L"A:\\"; root[0] += i;
        if (GetDriveTypeW(root.c_str()) != DRIVE_REMOVABLE) continue;
        wchar_t label[256];
        if (GetVolumeInformationW(root.c_str(), label, 256, nullptr, nullptr, nullptr, nullptr, 0)) {
            roots.push_back(root);
            S text = root + L"  " + label;
            SendMessageW(driveBox, CB_ADDSTRING, 0, (LPARAM)text.c_str());
        }
    }
    SendMessageW(driveBox, CB_SETCURSEL, 0, 0);
    updateFolders();
}
void enable(bool yes) {
    for (int id : { ID_SCAN, ID_CLEAN, ID_RESTORE, ID_REFRESH, ID_SAVE, ID_DRIVE, ID_FOLDER }) EnableWindow(GetDlgItem(window, id), yes);
#ifdef USB_ENHANCED
    if(yes)EnableWindow(folderBox,!folders.empty());
#endif
}
struct Work { std::function<void()> body, done; };
DWORD WINAPI worker(void* p)
{
    std::unique_ptr<Work> w((Work*)p);
    auto r = new Result;
    try { w->body(); r->done = w->done; }
    catch (const Error& e) { r->error = e.text; }
    catch (const std::exception& e) { r->error = L"操作异常：" + fromUtf8(e.what()); }
    catch (...) { r->error = L"未知错误，操作未完成"; }
    PostMessageW(window, DONE_MSG, 0, (LPARAM)r);
    return 0;
}
void run(const S& title, std::function<void()> body, std::function<void()> done = {})
{
    if (busy) return;
    busy = true; enable(false);
    SetWindowTextW(statusBox, title.c_str());
    auto w = new Work{ body, done };
    HANDLE h = CreateThread(nullptr, 0, worker, w, 0, nullptr);
    if (!h) { delete w; busy = false; stopScanProgress(); enable(true); fail(L"启动工作线程"); }
    CloseHandle(h);
}
// 实时枚举当前可移动磁盘，逐行“盘符 (卷标)”，供恢复前确认，避免误恢复其他磁盘。
S removableList()
{
    S out;
    DWORD bits = GetLogicalDrives();
    for (int i = 0; i < 26; i++) if (bits & (1u << i)) {
        S root = L"A:\\"; root[0] += i;
        if (GetDriveTypeW(root.c_str()) != DRIVE_REMOVABLE) continue;
        wchar_t label[256]; label[0] = 0;
        GetVolumeInformationW(root.c_str(), label, 256, nullptr, nullptr, nullptr, nullptr, 0);
        out += root + L" (" + (label[0] ? label : L"无卷标") + L")\r\n";
    }
    if (out.empty()) out = L"（当前未检测到可移动磁盘）\r\n";
    return out;
}
// 尝试立即重启：先获取 SE_SHUTDOWN_PRIVILEGE 再 ExitWindowsEx；无管理员权限等失败时返回 false，由调用方提示手动重启。
bool rebootNow()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid)) { CloseHandle(token); return false; }
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) || GetLastError() == ERROR_NOT_ALL_ASSIGNED) { CloseHandle(token); return false; }
    CloseHandle(token);
    return ExitWindowsEx(EWX_REBOOT, 0) != FALSE;
}
// 弹窗汇报隔离数量和仍需处理的事项；详细操作保留在日志中。
void showCleanResult(const std::vector<S>& collected)
{
    const auto result = cleanReport(collected);
    msgBox(L"查杀结果", result.headline, result.content, TDCBF_OK_BUTTON,
           result.warning ? TD_WARNING_ICON : TD_INFORMATION_ICON, result.details);
    if (result.anyIsolated) {
        if (msgBox(L"需要重启", L"请先保存文件，再重启复查", L"请保存正在编辑的文件。重启后，再打开本软件检查。\r\n是否立即重启电脑？", TDCBF_YES_BUTTON | TDCBF_NO_BUTTON, TD_INFORMATION_ICON) == IDYES) {
            if (!rebootNow()) msgBox(L"需要重启", L"重启失败", L"请手动重启电脑，然后再次检查确认。", TDCBF_OK_BUTTON, TD_ERROR_ICON);
        } else {
            msgBox(L"需要重启", L"请稍后手动重启", L"保存文件并重启电脑后，再打开本软件检查确认。", TDCBF_OK_BUTTON, TD_INFORMATION_ICON);
        }
    }
}
// 启动后主动弹出的使用说明：病毒简介、使用步骤、制作人三节，信息点一个不能少。
void showGuide()
{
    S text = L"【病毒简介】\r\n· 感染途径：点击带毒 U 盘里的伪装快捷方式，即会中招。\r\n· 易感机制：病毒把文件藏进 U+FFFF 字符隐藏目录，并放置与 U 盘卷标同名的诱饵快捷方式，劫持 shell32 图标伪装成文件夹。\r\n· 危害与行为：隐藏文件，并随 U 盘交叉感染其他电脑；联网后会劫持剪贴板，上传钱包密钥等敏感信息。\r\n\r\n【使用步骤】\r\n· 第一步：先点“杀毒”完成电脑查杀（选择“只检查电脑”→ 检查 → 杀毒）。\r\n· 确认电脑无毒后，再查杀 U 盘；否则 U 盘杀完后，会被电脑里残留的病毒立刻再次感染。\r\n· 然后恢复 U 盘隐藏文件。\r\n· 清理完成后重启电脑，再次检查确认。\r\n\r\n【制作人】\r\n李晓达——因机务段带毒电脑过多，U 盘反复感染，实在受不了了而开发本工具。";
    msgBox(L"使用说明", L"使用前请先读一遍", text, TDCBF_OK_BUTTON, TD_INFORMATION_ICON);
}
void startClean(const std::vector<Finding>& confirmed);  // 前向声明

void doScan()
{
    S root = selectedRoot();
    if (busy) return;
    startScanProgress();
    auto notices = std::make_shared<std::vector<S>>();
    run(L"正在检查，请稍候……", [root, notices] {
        findings.clear();
        findings = app::scan(root, [notices](const S& s) {
            if (scanNotice(s)) notices->push_back(s);
            logLine(s);
        }, scanProgress);
#ifdef USB_ENHANCED
        policyFindings = noDrivesPolicies([notices](const S& line){notices->push_back(line);logLine(line);});
        for(const auto& policy:policyFindings)logLine(L"需人工确认策略 | "+registryLocation(policy)+L" | "+registryValueText(policy));
#endif
        size_t yes = 0;
        for (auto& f : findings) { if (f.confirmed) yes++; logLine((f.confirmed ? L"已确认 | " : L"需核查 | ") + f.path + L" | " + f.reason); }
        logLine(L"确认命中 " + num(yes) + L" 项；需核查 " + num(findings.size() - yes) + L" 项。未命中不代表整机无毒。");
    }, [notices] {
        // 弹窗只展示命中结果；检查细节已写入日志。
        std::vector<Finding> confirmed;
        for (auto& f : findings) if (f.confirmed) confirmed.push_back(f);
        auto result = scanReport(findings, *notices);
        if (confirmed.empty()) {
            msgBox(L"检查完成", result.headline, result.content,
                   TDCBF_OK_BUTTON, result.warning ? TD_WARNING_ICON : TD_INFORMATION_ICON);
            return;
        }
        if (msgBox(L"检查完成", result.headline,
                   result.content,
                   TDCBF_YES_BUTTON | TDCBF_NO_BUTTON, TD_WARNING_ICON) != IDYES) return;
        if (!admin()) {
            msgBox(L"需要管理员权限", L"杀毒需要管理员权限",
                   L"请关闭程序，右键此 EXE，选择“以管理员身份运行”，再重新检查。",
                   TDCBF_OK_BUTTON, TD_ERROR_ICON);
            return;
        }
        startClean(confirmed);
    });
}

void startClean(const std::vector<Finding>& confirmed)
{
    auto collected = std::make_shared<std::vector<S>>();
    run(L"正在备份并清理……", [confirmed, collected] {
        app::clean(confirmed, [collected](const S& s) { collected->push_back(s); logLine(s); });
        findings.clear();
        logLine(L"请重新检查；电脑感染清理后还需重启复查。失败项见日志。");
    }, [collected] { showCleanResult(*collected); });
}

#ifdef USB_ENHANCED
static int reviewMenu() {
    TASKDIALOG_BUTTON buttons[]={{201,L"逐项核查文件"},{202,L"核查 NoDrives 隐藏磁盘策略"},{204,L"查看善后与复查清单"}};
    TASKDIALOGCONFIG cfg{};cfg.cbSize=sizeof(cfg);cfg.hwndParent=window;
    cfg.pszWindowTitle=L"人工核查";cfg.pszMainInstruction=L"选择要核查的项目";
    cfg.pszContent=L"只有逐项确认后才会备份处理；可疑线索不等于确诊病毒。";
    cfg.dwFlags=TDF_USE_COMMAND_LINKS|TDF_POSITION_RELATIVE_TO_WINDOW;
    cfg.dwCommonButtons=TDCBF_CANCEL_BUTTON;cfg.cButtons=sizeof(buttons)/sizeof(buttons[0]);cfg.pButtons=buttons;
    int button=IDCANCEL;TaskDialogIndirect(&cfg,&button,nullptr,nullptr);return button;
}
void doReview() {
    if(busy)return;
    int choice=reviewMenu();
    if(choice==204){msgBox(L"善后与复查",L"请逐项核对",aftercareChecklist());return;}
    if(choice==201) {
        std::vector<Finding> approved;
        for(const auto& f:findings)if(!f.confirmed) {
            bool eligible=f.review==ReviewKind::ResidualName && !f.digest.empty();
            const S body=enhanced::reviewFileText(f)+(eligible?L"\r\n\r\n仅按名称匹配，不能确定是病毒。确认属于异常残留后，是否备份隔离此文件？":L"\r\n\r\n此项仅供甄别，不会自动隔离，请用完整杀毒软件复核。");
            if(msgBox(L"逐项人工核查",eligible?L"是否隔离此残留候选？":L"需甄别文件",body,eligible?(TDCBF_YES_BUTTON|TDCBF_NO_BUTTON):TDCBF_OK_BUTTON,TD_WARNING_ICON)==IDYES)approved.push_back(f);
        }
        if(approved.empty())return;
        if(!admin()){msgBox(L"需要管理员权限",L"请以管理员身份运行",L"关闭程序，右键选择“以管理员身份运行”，重新检查后再确认。");return;}
        auto logs=std::make_shared<std::vector<S>>();
        run(L"正在处理人工确认文件……",[approved,logs]{
            Journal j(data());
            for(const auto& f:approved)try{enhanced::quarantineReviewed(f,true,j,[logs](const S& line){logs->push_back(line);logLine(line);});}
            catch(const Error& e){S line=L"清理失败："+f.path+L" — "+e.text;logs->push_back(line);logLine(line);}
        },[logs]{showCleanResult(*logs);});
    } else if(choice==202) {
        std::vector<RegistrySnapshot> approved;
        for(const auto& policy:policyFindings) {
            S body=registryLocation(policy)+L"\r\n"+registryValueText(policy)+L"\r\n\r\n若为用户或管理员自己设置的策略请保留。是否备份原值并删除此 NoDrives 值？";
            if(msgBox(L"隐藏磁盘策略",L"此策略不一定由病毒设置",body,TDCBF_YES_BUTTON|TDCBF_NO_BUTTON,TD_WARNING_ICON)==IDYES)approved.push_back(policy);
        }
        if(approved.empty()){msgBox(L"人工核查",L"未选择要删除的策略",L"请先检查；自己设置的策略应保留。");return;}
        if(!admin()){msgBox(L"需要管理员权限",L"请以管理员身份运行",L"涉及系统策略，请重新以管理员身份检查并确认。");return;}
        run(L"正在备份策略原值……",[approved]{Journal j(data());for(const auto& policy:approved)try{removeReviewedValue(policy,true,j,logLine);}catch(const Error& e){logLine(L"策略项清理失败："+registryLocation(policy)+L" — "+e.text);throw;}},[]{msgBox(L"人工核查结果",L"策略处理结束",L"所选策略已备份处理，请重新检查。此结果不代表整机已清毒。");});
    }
}
#endif
void doClean()
{
    std::vector<Finding> confirmed;
    for (auto& f : findings) if (f.confirmed) confirmed.push_back(f);
    if (confirmed.empty()) {
        msgBox(L"杀毒", L"请先检查病毒", L"点击“开始检查”，发现病毒后即可查杀。", TDCBF_OK_BUTTON, TD_INFORMATION_ICON);
        return;
    }
    const auto result = scanReport(confirmed, {});
    if (msgBox(L"杀毒", result.headline, result.content,
               TDCBF_YES_BUTTON | TDCBF_NO_BUTTON, TD_WARNING_ICON) != IDYES) return;
    if (!admin()) {
        msgBox(L"需要管理员权限", L"杀毒需要管理员权限",
               L"请关闭程序，右键此 EXE，选择“以管理员身份运行”，再重新检查。",
               TDCBF_OK_BUTTON, TD_ERROR_ICON);
        return;
    }
    startClean(confirmed);
}
void doRestore()
{
    S root = selectedRoot();
    LRESULT i = SendMessageW(folderBox, CB_GETCURSEL, 0, 0);
    if (root.empty() || i < 0 || (size_t)i >= folders.size()) {
        msgBox(L"恢复 U 盘", L"请先选择 U 盘和隐藏目录",
               L"固定磁盘和网络盘不在恢复范围内。", TDCBF_OK_BUTTON, TD_WARNING_ICON);
        return;
    }
    S container = folders[i];
    run(L"正在检查内容并生成恢复预览……", [root, container] { pending = app::plan(root, container); }, [container] {
        if (pending.items.empty()) {
            // 区分两种“空”：隐藏目录里只剩病毒文件，或确实没有可移动的用户文件。
            bool onlyVirus = false;
            try {
                for (auto& e : list(container)) {
                    if (e.attrs & FILE_ATTRIBUTE_DIRECTORY) continue;
                    if (suspicious(e.path) || (extension(e.path, L".lnk") && size(e.path) <= 1048576 && wormLink(e.path))) { onlyVirus = true; break; }
                }
            } catch (...) {}
            if (onlyVirus)
                msgBox(L"恢复 U 盘", L"隐藏目录里只有病毒文件",
                       L"没有可恢复的用户文件。\r\n请先点“2 杀毒”清除病毒，再重新检查。",
                       TDCBF_OK_BUTTON, TD_WARNING_ICON);
            else
                msgBox(L"恢复 U 盘", L"没有可恢复的内容",
                       L"隐藏目录为空，或只包含顶层快捷方式与同名可疑程序（按设计保留原处）。",
                       TDCBF_OK_BUTTON, TD_INFORMATION_ICON);
            return;
        }
        for (auto& m : pending.items) append(L"预览：" + m.source + L" → " + m.dest);
        S target = container + (name(container) == L"\uffff" ? L"（U+FFFF 字符隐藏目录）" : L"");
        S msg = L"当前检测到的可移动磁盘：\r\n" + removableList() + L"\r\n您选择恢复的是：" + target + L"\r\n\r\n将移动 " + num(pending.items.size()) + L" 个顶层项目至 " + pending.root + L"。\r\n重名自动改名，保留双方，不合并或覆盖。顶层快捷方式和可疑程序留在原处。\r\n\r\n完整预览已列入日志。恢复文件不等于清毒；请先处理电脑上的传播源。\r\n请确认选择无误？";
#ifdef USB_ENHANCED
        msg += L"\r\n加强版会额外保留顶层可执行文件、DLL 和脚本；含嵌套启动入口的目录停止恢复。";
#endif
        if (msgBox(L"确认恢复", L"请确认要恢复的磁盘", msg, TDCBF_YES_BUTTON | TDCBF_NO_BUTTON, TD_WARNING_ICON) == IDYES) {
            Plan p = pending;
            run(L"正在恢复，请勿拔出 U 盘……", [p] { Journal j(data()); app::recover(p, j, logLine); }, [] {
                updateFolders();
                msgBox(L"恢复完成", L"U 盘已恢复完成", L"建议重新检查 U 盘，确认没有残留病毒。", TDCBF_OK_BUTTON, TD_INFORMATION_ICON);
            });
        }
    });
}
void saveLog()
{
    wchar_t path[32768] = L"U盘修复助手-日志.txt";
    OPENFILENAMEW of{};
    of.lStructSize = sizeof(of);
    of.hwndOwner = window;
    of.lpstrFilter = L"文本日志 (*.txt)\0*.txt\0\0";
    of.lpstrFile = path;
    of.nMaxFile = 32768;
    of.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    of.lpstrDefExt = L"txt";
    if (GetSaveFileNameW(&of)) {
        // Explicit save-dialog approval permits replacing this chosen log only.
        Handle h(CreateFileW(xp(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (h.h == INVALID_HANDLE_VALUE) fail(L"保存日志");
        auto s = utf8(L"\ufeff" + controlText(logBox));
        write(h.h, s.data(), (DWORD)s.size());
    }
}
void about()
{
    S text = L"单文件、离线、无需 .NET 或外部 VC++ 运行库。\r\n面向 Win7 SP1（32/64 位）、Win10/11。\r\nWin7 与 Win10 已完成真实感染环境实测。\r\n\r\n电脑检查：进程映像、Run/RunOnce、常见落地目录顶层。\r\n不含全盘、服务、计划任务、其他用户和未知变种。\r\n恢复：移动所选隐藏目录内容至根目录；重名保留双方。\r\n日志与隔离：%LOCALAPPDATA%\\UsbRecovery。\r\n\r\n编译：GCC / MinGW-w64（MSVCRT）。\r\n第三方许可已嵌入 EXE，可用 --licenses <文件路径> 导出。\r\n程序未签名，不应关闭杀毒软件来运行。";
#ifdef USB_ENHANCED
    text = L"加强版 · 规则 " + S(enhanced::RULE_VERSION) + L"\r\n单文件、离线、无需 .NET 或外部 VC++ 运行库。\r\n编译目标 Win7 SP1 / Win10 / Win11（32 位程序）。\r\n本加强版尚未做虚拟机真实感染验收；原版已知样本曾在 Win7/Win10 验证。\r\n\r\n15 条精确指纹 + 原版精确 LNK + 7 类可疑组合。\r\n文件哈希上限 64 MiB，内容解析上限 1 MiB，遍历有上限。\r\n不覆盖压缩包内部、内存注入或全部驻留机制。\r\n\r\n查看“规则与处理方案”了解来源、步骤和范围。\r\n日志与隔离：%LOCALAPPDATA%\\UsbRecovery。\r\n程序未签名。第三方许可可用 --licenses <文件路径> 导出。";
#endif
    msgBox(L"说明与兼容性", APP_TITLE, text, TDCBF_OK_BUTTON, TD_INFORMATION_ICON);
}

#ifdef USB_ENHANCED
LRESULT CALLBACK rulesProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_SIZE) { MoveWindow(GetDlgItem(h, 1), 12, 12, std::max(1, int(LOWORD(l))-24), std::max(1, int(HIWORD(l))-24), TRUE); return 0; }
    return DefWindowProcW(h,m,w,l);
}
void showRules() {
    static HWND popup = nullptr;
    if (IsWindow(popup)) { ShowWindow(popup, SW_RESTORE); SetForegroundWindow(popup); return; }
    WNDCLASSW cls{}; cls.lpfnWndProc=rulesProc; cls.hInstance=GetModuleHandleW(nullptr);
    cls.lpszClassName=L"UsbEnhancedRules"; cls.hCursor=LoadCursorW(nullptr,IDC_ARROW); cls.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    RegisterClassW(&cls);
    popup=CreateWindowExW(0,cls.lpszClassName,L"加强版 · 规则与处理方案（可滚动、复制）",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,PX(880),PX(640),window,nullptr,cls.hInstance,nullptr);
    if(!popup)fail(L"打开规则与处理方案");
    S text=enhanced::rulesText();
    HWND edit=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,12,12,PX(830),PX(550),popup,(HMENU)1,cls.hInstance,nullptr);
    SendMessageW(edit,EM_SETLIMITTEXT,1024*1024,0); SendMessageW(edit,WM_SETFONT,(WPARAM)font,TRUE); SetWindowTextW(edit,text.c_str());
    RECT r;GetClientRect(popup,&r);MoveWindow(edit,12,12,r.right-24,r.bottom-24,TRUE);
    ShowWindow(popup,SW_SHOW);
}
#endif

// ================= 控件与布局 =================
HWND control(const wchar_t* cls, const wchar_t* text, DWORD style, int id, int x, int y, int w, int h)
{
    HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, window, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(c, WM_SETFONT, (WPARAM)font, TRUE);
    return c;
}

void createChildren()
{
    driveBox = control(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, ID_DRIVE, 120, 120, 300, 260);
    control(L"BUTTON", L"刷新盘符", WS_TABSTOP | BS_OWNERDRAW, ID_REFRESH, 432, 118, 96, 28);
    folderBox = control(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, ID_FOLDER, 120, 156, 520, 260);
    control(L"BUTTON", L"1  检查电脑", WS_TABSTOP | BS_OWNERDRAW, ID_SCAN, 44, 206, 150, 40);
    control(L"BUTTON", L"2  杀毒", WS_TABSTOP | BS_OWNERDRAW, ID_CLEAN, 206, 206, 150, 40);
    control(L"BUTTON", L"3  恢复 U 盘", WS_TABSTOP | BS_OWNERDRAW, ID_RESTORE, 368, 206, 150, 40);
    control(L"BUTTON", L"导出日志", WS_TABSTOP | BS_OWNERDRAW, ID_SAVE, 720, 206, 96, 40);
    control(L"BUTTON", L"说明", WS_TABSTOP | BS_OWNERDRAW, ID_ABOUT, 828, 206, 96, 40);
#ifdef USB_ENHANCED
    control(L"BUTTON", L"规则与处理方案", WS_TABSTOP | BS_OWNERDRAW, ID_RULES, 748, 132, 160, 30);
    control(L"BUTTON", L"展开记录", WS_TABSTOP | BS_OWNERDRAW, ID_LOG_TOGGLE, 748, 430, 88, 28);
    SetWindowTextW(GetDlgItem(window,ID_SCAN),L"开始检查");
    SetWindowTextW(GetDlgItem(window,ID_CLEAN),L"隔离确认项");
    SetWindowTextW(GetDlgItem(window,ID_RESTORE),L"预览并恢复");
#endif
    logBox = control(L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL | WS_TABSTOP | WS_BORDER, 0, 44, 340, 900, 400);
    SendMessageW(logBox, EM_SETLIMITTEXT, 8 * 1024 * 1024, 0);
    SendMessageW(logBox, EM_SETBKGNDCOLOR, 0, (LPARAM)C_CARD);
    SendMessageW(logBox, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(10, 10));
    progressBox = control(PROGRESS_CLASSW, L"", PBS_MARQUEE, 111, 0, 0, 1, 1);
    scanPathBox = control(L"STATIC", L"", SS_PATHELLIPSIS | SS_NOPREFIX, 112, 0, 0, 1, 1);
    ShowWindow(progressBox, SW_HIDE); ShowWindow(scanPathBox, SW_HIDE);
    statusBox = control(L"STATIC", L"就绪 · 检查不会修改被检查文件", 0, 0, 44, 700, 900, 24);
#ifdef USB_ENHANCED
    control(L"BUTTON",L"人工核查",BS_OWNERDRAW,ID_REVIEW,0,0,1,1);
    ShowWindow(logBox,SW_HIDE);
#endif
}

void layout()
{
    RECT r;
    GetClientRect(window, &r);
    const int W = r.right, H = r.bottom;
    const int M = PX(24), PAD = PX(20);

#ifdef USB_ENHANCED
    rcIcon={M,PX(24),M+PX(44),PX(68)};
    rcTitle={M+PX(58),PX(19),PX(262),PX(52)};
    rcSub={M+PX(58),PX(53),W-M,PX(76)};
    rcCard1={M,PX(96),W-M,PX(232)};
    const int fieldWidth=(W-2*M-PX(60))/2;
    rcLbl1={M+PAD,PX(146),M+PAD+fieldWidth,PX(170)};
    rcLbl2={M+PAD+fieldWidth+PX(20),PX(146),W-M-PAD,PX(170)};
    MoveWindow(driveBox,rcLbl1.left,PX(176),fieldWidth-PX(92),PX(240),TRUE);
    MoveWindow(GetDlgItem(window,ID_REFRESH),rcLbl1.left+fieldWidth-PX(82),PX(175),PX(82),PX(28),TRUE);
    MoveWindow(folderBox,rcLbl2.left,PX(176),fieldWidth,PX(240),TRUE);
    MoveWindow(GetDlgItem(window,ID_REVIEW),W-M-PX(334),PX(29),PX(92),PX(32),TRUE);
    MoveWindow(GetDlgItem(window,ID_RULES),W-M-PX(232),PX(29),PX(150),PX(32),TRUE);
    MoveWindow(GetDlgItem(window,ID_ABOUT),W-M-PX(72),PX(29),PX(72),PX(32),TRUE);
    const int stepWidth=(W-2*M-PX(24))/3;
    const int ids[]={ID_SCAN,ID_CLEAN,ID_RESTORE};
    for(int i=0;i<3;++i) {
        int x=M+i*(stepWidth+PX(12));
        rcSteps[i]={x,PX(248),x+stepWidth,PX(408)};
        MoveWindow(GetDlgItem(window,ids[i]),x+PX(18),PX(356),stepWidth-PX(36),PX(34),TRUE);
    }
    const int recordBottom=logExpanded?std::max(PX(480),std::min(H-PX(100),PX(660))):PX(474);
    rcCard2={M,PX(424),W-M,recordBottom};
    rcLogTitle={M+PAD,PX(435),W-M-PAD,PX(463)};
    MoveWindow(GetDlgItem(window,ID_LOG_TOGGLE),W-M-PAD-PX(88),PX(435),PX(88),PX(28),TRUE);
    MoveWindow(GetDlgItem(window,ID_SAVE),W-M-PAD-PX(186),PX(435),PX(88),PX(28),TRUE);
    MoveWindow(logBox,M+PAD,PX(480),W-2*M-2*PAD,std::max(PX(1),recordBottom-PX(494)),TRUE);
    ShowWindow(logBox,logExpanded?SW_SHOW:SW_HIDE);
    MoveWindow(statusBox,M+PX(18),H-PX(78),W-2*M-PX(18),PX(24),TRUE);
    MoveWindow(scanPathBox,M,H-PX(52),W-2*M,PX(22),TRUE);
    MoveWindow(progressBox,M,H-PX(24),W-2*M,PX(8),TRUE);
    rcDot={M,H-PX(71),M+PX(7),H-PX(64)};
    InvalidateRect(window,nullptr,FALSE);
    return;
#endif

    rcIcon = { M, M + PX(6), M + PX(40), M + PX(46) };
    rcTitle = { M + PX(56), M + PX(6), W - M, M + PX(46) };

    rcCard1 = { M, PX(72), W - M, PX(72) + PX(180) };
    rcCard2 = { M, PX(268), W - M, H - PX(100) };

    rcLbl1 = { M + PAD, PX(92), M + PAD + PX(72), PX(118) };
    rcLbl2 = { M + PAD, PX(130), M + PAD + PX(72), PX(156) };
    rcLogTitle = { M + PAD, PX(268) + PX(16), M + PAD + PX(120), PX(268) + PX(34) };
    rcDot = { M, H - PX(34), M + PX(8), H - PX(26) };
    rcStatus = { M + PX(18), H - PX(40), W - M, H - PX(12) };

    const int bx = M + PAD, by = PX(182);
    MoveWindow(driveBox, bx + PX(78), PX(94), PX(300), PX(260), TRUE);
    MoveWindow(GetDlgItem(window, ID_REFRESH), bx + PX(390), PX(94), PX(96), PX(28), TRUE);
    MoveWindow(folderBox, bx + PX(78), PX(132), PX(520), PX(260), TRUE);
#ifdef USB_ENHANCED
    MoveWindow(GetDlgItem(window, ID_RULES), W - M - PAD - PX(150), PX(132), PX(150), PX(30), TRUE);
#endif
    MoveWindow(GetDlgItem(window, ID_SCAN), bx, by, PX(150), PX(40), TRUE);
    MoveWindow(GetDlgItem(window, ID_CLEAN), bx + PX(162), by, PX(150), PX(40), TRUE);
    MoveWindow(GetDlgItem(window, ID_RESTORE), bx + PX(324), by, PX(150), PX(40), TRUE);
    MoveWindow(GetDlgItem(window, ID_SAVE), W - M - PAD - PX(96) - PX(108), by, PX(96), PX(40), TRUE);
    MoveWindow(GetDlgItem(window, ID_ABOUT), W - M - PAD - PX(96), by, PX(96), PX(40), TRUE);
    MoveWindow(logBox, bx, PX(316), W - 2 * M - 2 * PAD, H - PX(100) - PX(316) - PX(20), TRUE);
    MoveWindow(statusBox, M + PX(18), H - PX(78), W - 2 * M - PX(30), PX(24), TRUE);
    MoveWindow(scanPathBox,M,H-PX(52),W-2*M,PX(22),TRUE);
    MoveWindow(progressBox,M,H-PX(24),W-2*M,PX(8),TRUE);
    rcDot={M,H-PX(71),M+PX(7),H-PX(64)};

    InvalidateRect(window, nullptr, FALSE);
}

// ================= 窗口过程 =================
LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    try {
        switch (m) {
        case WM_CREATE: {
            window = h;
            font = CreateFontW(-PX(13), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");
            titleFont = CreateFontW(-PX(22), 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");
            smallFont = CreateFontW(-PX(11), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");
            btnFont = CreateFontW(-PX(13), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei");
#ifdef USB_ENHANCED
            cardFont=CreateFontW(-PX(15),0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Microsoft YaHei");
#endif
            createChildren();
            updateDrives();
            append(L"先检查，再清理；未知变种与同名可疑文件不自动删除。");
            append(L"恢复会预览移动范围，重名自动改名；文件恢复成功不等于电脑已经清毒。");
            layout();
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(h, &ps);
            RECT r;
            GetClientRect(h, &r);
            HDC mem = CreateCompatibleDC(dc);
            HBITMAP bmp = CreateCompatibleBitmap(dc, r.right, r.bottom);
            HGDIOBJ old = SelectObject(mem, bmp);
            paintAll(mem, r);
            BitBlt(dc, 0, 0, r.right, r.bottom, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(h, &ps);
            return 0;
        }
        case WM_DRAWITEM: {
            DRAWITEMSTRUCT* di = (DRAWITEMSTRUCT*)l;
            if (di->CtlType != ODT_BUTTON) break;
            int id = (int)di->CtlID;
            const bool primary = isPrimaryButton(id);
            const bool disabled = (di->itemState & ODS_DISABLED) != 0;
            const bool pressed = (di->itemState & ODS_SELECTED) != 0;
            COLORREF bg, fg;
            if (primary) {
                bg = disabled ? C_DIS_BG : (pressed ? C_PRIMARY_P : C_PRIMARY);
                fg = disabled ? C_DIS_TEXT : RGB(255, 255, 255);
            } else {
                bg = disabled ? C_DIS_BG : (pressed ? C_BTN2_PRESS : C_CARD);
                fg = disabled ? C_DIS_TEXT : C_BTN2_TEXT;
            }
#ifdef USB_ENHANCED
            HBRUSH buttonBase=CreateSolidBrush((id==ID_RULES || id==ID_ABOUT)?C_BG:C_CARD);
            FillRect(di->hDC,&di->rcItem,buttonBase);DeleteObject(buttonBase);
#endif
            fillRound(di->hDC, di->rcItem, PX(8), bg, primary ? bg : C_BORDER);
            S text = controlText(di->hwndItem);
            drawTextAt(di->hDC, text, di->rcItem, btnFont, fg, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            if(di->itemState&ODS_FOCUS) { RECT focus=di->rcItem;InflateRect(&focus,-PX(4),-PX(4));DrawFocusRect(di->hDC,&focus); }
            return TRUE;
        }
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)w;
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, C_SUB);
#ifdef USB_ENHANCED
            if((HWND)l==logBox) { static HBRUSH paper=CreateSolidBrush(C_CARD);SetBkColor(dc,C_CARD);return (LRESULT)paper; }
#endif
            static HBRUSH bgBrush = CreateSolidBrush(C_BG);
            return (LRESULT)bgBrush;
        }
        case WM_TIMER:
            if (w == 1 && scanning) renderScanProgress();
            return 0;
        case WM_SIZE:
            layout();
            return 0;
        case WM_GETMINMAXINFO:
#ifdef USB_ENHANCED
            ((MINMAXINFO*)l)->ptMinTrackSize={PX(820),PX(610)};
#else
            ((MINMAXINFO*)l)->ptMinTrackSize = { PX(860), PX(640) };
#endif
            return 0;
        case WM_COMMAND:
            if (LOWORD(w) == ID_ABOUT) { about(); return 0; }
#ifdef USB_ENHANCED
            if (LOWORD(w) == ID_REVIEW) { doReview(); return 0; }
            if (LOWORD(w) == ID_RULES) { showRules(); return 0; }
            if (LOWORD(w) == ID_LOG_TOGGLE) {
                logExpanded=!logExpanded;
                SetWindowTextW(GetDlgItem(window,ID_LOG_TOGGLE),logExpanded?L"收起记录":L"展开记录");
                RECT bounds;GetWindowRect(window,&bounds);
                MONITORINFO monitor{};monitor.cbSize=sizeof(monitor);GetMonitorInfoW(MonitorFromWindow(window,MONITOR_DEFAULTTONEAREST),&monitor);
                int height=std::max<int>(PX(610),bounds.bottom-bounds.top+(logExpanded?PX(168):-PX(168)));
                height=std::min<int>(height,monitor.rcWork.bottom-monitor.rcWork.top);
                SetWindowPos(window,nullptr,bounds.left,std::min(bounds.top,monitor.rcWork.bottom-height),bounds.right-bounds.left,height,SWP_NOZORDER|SWP_NOACTIVATE);
                layout();return 0;
            }
#endif
            if (busy) return 0;
            switch (LOWORD(w)) {
            case ID_DRIVE: if (HIWORD(w) == CBN_SELCHANGE) updateFolders(); break;
            case ID_REFRESH: updateDrives(); break;
            case ID_SCAN: doScan(); break;
            case ID_CLEAN: doClean(); break;
            case ID_RESTORE: doRestore(); break;
            case ID_SAVE: saveLog(); break;
            }
            return 0;
        case LOG_MSG: {
            std::unique_ptr<S> s((S*)l);
            append(*s);
            return 0;
        }
        case DONE_MSG: {
            std::unique_ptr<Result> r((Result*)l);
            const bool wasScanning = scanning;
            if (wasScanning) { renderScanProgress(); stopScanProgress(); }
            busy = false;
            enable(true);
            SetWindowTextW(statusBox, r->error.empty() ? L"操作结束，请查看失败项和跳过项" : L"操作未完成");
#ifdef USB_ENHANCED
            SetWindowTextW(statusBox,r->error.empty()?L"操作结束 · 结果已汇报，可按需展开操作记录":L"操作未完成 · 请查看提示和操作记录");
#endif
            if (wasScanning && r->error.empty()) {
                SetWindowTextW(statusBox, (L"检查结束 · 共检查 " + num(scanChecked) + L" 个文件 · 用时 " + num((GetTickCount64()-scanStarted)/1000) + L" 秒").c_str());
            }
            if (!r->error.empty()) {
                append(L"操作停止：" + r->error);
                msgBox(L"未完成", L"操作没有全部完成", r->error, TDCBF_OK_BUTTON, TD_WARNING_ICON);
            } else if (r->done) r->done();
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        case WM_CLOSE:
            if (busy) { msgBox(L"提示", L"操作正在进行", L"请等待当前操作结束后再关闭。", TDCBF_OK_BUTTON, TD_INFORMATION_ICON); return 0; }
            DestroyWindow(h);
            return 0;
        case WM_DESTROY:
            DeleteObject(font); DeleteObject(titleFont); DeleteObject(smallFont); DeleteObject(btnFont);
#ifdef USB_ENHANCED
            DeleteObject(cardFont);
#endif
            PostQuitMessage(0);
            return 0;
        }
    } catch (const Error& e) {
        msgBox(L"操作未完成", L"出现错误，操作未完成", e.text, TDCBF_OK_BUTTON, TD_WARNING_ICON);
    } catch (...) {
        msgBox(L"错误", L"操作异常，未能完成", L"请重试；若反复出现，请截图反馈。", TDCBF_OK_BUTTON, TD_ERROR_ICON);
    }
    return DefWindowProcW(h, m, w, l);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    SetErrorMode(SEM_FAILCRITICALERRORS);
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
#ifdef USB_ENHANCED
    if (argc == 3 && S(argv[1]) == L"--rules") {
        try { textFile(argv[2], L"\ufeff" + enhanced::rulesText()); LocalFree(argv); return 0; }
        catch (...) { LocalFree(argv); return 1; }
    }
#endif
    if (argc == 3 && S(argv[1]) == L"--licenses") {
        try {
            auto res = FindResourceW(instance, MAKEINTRESOURCEW(201), RT_RCDATA);
            if (!res) throw Error{ L"许可资源缺失" };
            auto ptr = LockResource(LoadResource(instance, res));
            Handle out(CreateFileW(xp(argv[2]).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (out.h == INVALID_HANDLE_VALUE) fail(L"导出许可");
            write(out.h, ptr, SizeofResource(instance, res));
            LocalFree(argv);
            return 0;
        } catch (...) {
            LocalFree(argv);
            return 1;
        }
    }
    LocalFree(argv);

    HDC screen = GetDC(nullptr);
    g_dpi = GetDeviceCaps(screen, LOGPIXELSX);
    ReleaseDC(nullptr, screen);
    if (g_dpi < 96) g_dpi = 96;
#ifdef USB_ENHANCED
    RECT available{};
    if(SystemParametersInfoW(SPI_GETWORKAREA,0,&available,0)) {
        const int fit=std::min((available.right-available.left-24)*96/900,(available.bottom-available.top-24)*96/630);
        g_dpi=std::max(96,std::min(g_dpi,fit));
    }
#endif

    appIcon = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
    appIcon40 = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, PX(40) * 2, PX(40) * 2, LR_SHARED);
    if (!appIcon40) appIcon40 = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, 64, 64, LR_SHARED);
    appIconSmall = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, LR_SHARED);

    INITCOMMONCONTROLSEX cc{ sizeof(cc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&cc);
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = proc;
    wc.hInstance = instance;
    wc.lpszClassName = L"UsbRecoveryNative";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = appIcon ? appIcon : LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = appIconSmall;
    wc.hbrBackground = nullptr;
    RegisterClassExW(&wc);
#ifdef USB_ENHANCED
    RECT work{0,0,GetSystemMetrics(SM_CXSCREEN),GetSystemMetrics(SM_CYSCREEN)};SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);
    int width=PX(900),height=PX(630);
    HWND h=CreateWindowExW(0,wc.lpszClassName,APP_TITLE,WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,work.left+std::max<int>(0,(work.right-work.left-width)/2),work.top+std::max<int>(0,(work.bottom-work.top-height)/2),width,height,nullptr,nullptr,instance,nullptr);
#else
    HWND h = CreateWindowExW(0, wc.lpszClassName, APP_TITLE, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, PX(980), PX(760), nullptr, nullptr, instance, nullptr);
#endif
    if (!h) return 1;
    ShowWindow(h, show);
    UpdateWindow(h);
    showGuide();
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(h, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    }
    return (int)msg.wParam;
}
