#include "ui_results.hpp"
#include <iostream>
using namespace usb;

int main() {
    int passed = 0;
    auto check = [&](bool ok, const char* message) {
        if (!ok) { std::cerr << "FAIL " << message << std::endl; return false; }
        ++passed;
        std::cout << "PASS " << message << std::endl;
        return true;
    };
    auto contains = [](const S& s, const S& part) { return s.find(part) != S::npos; };
    auto scan = scanReport({}, {});
    if (!check(!scan.warning && scan.headline == L"本次未发现病毒" && scan.content.empty(), "empty scan is concise")) return 1;
    Finding unknown{L"E:\\DrvMgr.exe", L"", L"同名但哈希未知，不自动删除", false, false};
    scan = scanReport({unknown}, {});
    if (!check(scan.warning && contains(scan.content, L"1 项可疑文件") && !contains(scan.content, L"是否现在查杀"), "unknown files are not offered for automatic cleanup")) return 1;
    Finding confirmed{L"E:\\bad.exe", HASH, L"哈希命中", true, false};
    const S notice = L"未读取目录：E:\\blocked — 拒绝访问";
    scan = scanReport({confirmed, unknown}, {notice});
    if (!check(scan.warning && scan.headline == L"本次命中 1 项" && contains(scan.content, confirmed.path) && contains(scan.content, L"是否现在查杀？") && !contains(scan.content, unknown.path) && !contains(scan.content, notice), "confirmation lists only confirmed files without diagnostic noise")) return 1;
    scan = scanReport({}, std::vector<S>(20, notice));
    if (!check(!scan.warning && scan.content.empty(), "access notices stay out of the popup")) return 1;
    if (!check(scanNotice(notice), "access notices remain available for logging")) return 1;
    auto clean = cleanReport({L"已结束确认命中的进程：123", L"已隔离：C:\\bad.exe"});
    if (!check(!clean.warning && clean.anyIsolated && clean.headline == L"已隔离 1 项" && clean.content.empty(), "successful cleanup reports the isolated count")) return 1;
    const S startup = L"启动项移除失败（已跳过，不影响文件隔离）：BadRun — 启动项已变化，请重新检查";
    clean = cleanReport({startup, L"已隔离：C:\\bad.exe", L"已隔离：E:\\a.lnk", L"已隔离：E:\\b.exe"});
    if (!check(clean.warning && clean.anyIsolated && clean.headline == L"已隔离 3 项" && contains(clean.content, L"开机启动项未清除") && !contains(clean.content, startup), "screenshot scenario separates isolation success from startup failure")) return 1;
    clean = cleanReport({startup, L"清理失败：C:\\bad.exe — 文件已变化"});
    if (!check(clean.warning && !clean.anyIsolated && contains(clean.content, L"C:\\bad.exe") && contains(clean.content, L"开机启动项未清除") && !contains(clean.content, L"文件已变化"), "failed file stays visible with technical details in logs")) return 1;
    clean = cleanReport({L"已隔离：C:\\first.exe", L"清理失败：E:\\second.exe — 拒绝访问"});
    if (!check(clean.warning && clean.anyIsolated && clean.headline == L"已隔离 1 项" && contains(clean.content, L"1 项未能清除") && contains(clean.content, L"E:\\second.exe"), "partial cleanup identifies the remaining file")) return 1;
    clean = cleanReport({L"处置待复核：Family — technical instructions", L"已隔离：C:\\bad.dll"});
    if (!check(clean.warning && clean.anyIsolated && contains(clean.content, L"完整杀毒软件") && !contains(clean.content, L"technical"), "remaining cleanup guidance is plain language")) return 1;
    clean = cleanReport({startup});
    if (!check(clean.warning && !clean.anyIsolated && contains(clean.content, L"开机启动项未清除"), "startup failure without file results remains visible")) return 1;
    clean = cleanReport({});
    if (!check(clean.warning && !clean.anyIsolated && clean.headline == L"本次未能清除病毒", "empty cleanup never claims success")) return 1;
    clean = cleanReport({L"启动项移除失败：fixture — 启动项内容已变化，请重新检查", L"已隔离：C:\\bad.exe"});
    if (!check(clean.warning && contains(clean.content,L"内容在检查后发生了变化") && !contains(clean.content,L"管理员"), "changed startup asks to rescan rather than elevate")) return 1;
    clean = cleanReport({L"启动项移除失败：fixture — 权限不足，无法打开启动项 [5]", L"已隔离：C:\\bad.exe"});
    if (!check(clean.warning && contains(clean.content,L"以管理员身份运行") && contains(clean.content,L"若仍失败"), "access denied provides elevation and fallback guidance")) return 1;
    std::cout << "TOTAL PASS " << passed << std::endl;
    return 0;
}
