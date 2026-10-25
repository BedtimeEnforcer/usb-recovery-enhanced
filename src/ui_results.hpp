#pragma once
#include "engine.hpp"

namespace usb {
struct UiReport {
    S headline, content;
    bool warning = false, anyIsolated = false;
};

inline bool scanNotice(const S& line) {
    // 仅排除已知的正常进度；保留原样转发的目录访问异常，避免遗漏。
    if (line.empty() || line.rfind(L"检查电脑进程映像、", 0) == 0 ||
        line.rfind(L"检查所选 U 盘：", 0) == 0 ||
        line.rfind(L"加强版规则 ", 0) == 0 || line.rfind(L"加强版检查结束", 0) == 0 ||
        line.rfind(L"无法读取路径的进程数：0（", 0) == 0 ||
        (line.rfind(L"跳过 ", 0) == 0 && line.find(L"个确认不存在的文件") != S::npos)) return false;
    return true;
}

inline UiReport scanReport(const std::vector<Finding>& findings, const std::vector<S>& /*notices*/) {
    UiReport r;
    size_t confirmed = 0, unknown = 0;
    for (const auto& f : findings) {
        if (f.confirmed) ++confirmed;
        else ++unknown;
    }
    r.warning = confirmed > 0 || unknown > 0;
    r.headline = confirmed ? L"本次命中 " + num(confirmed) + L" 项" : L"本次未发现病毒";
    if (confirmed) {
        r.content = L"命中的病毒文件如下：";
        size_t shown = 0;
        for (const auto& f : findings) if (f.confirmed && shown < 8) {
            r.content += L"\r\n" + f.path;
            ++shown;
        }
        if (confirmed > shown) r.content += L"\r\n其余 " + num(confirmed - shown) + L" 项见日志。";
        r.content += L"\r\n\r\n是否现在查杀？";
    } else if (unknown) {
        r.content = L"发现 " + num(unknown) + L" 项可疑文件，尚不能确定是病毒，详情见日志。";
    }
    return r;
}

inline UiReport cleanReport(const std::vector<S>& collected) {
    UiReport r;
    size_t isolated = 0;
    bool startupFailed = false, startupDenied = false, startupChanged = false, startupOther = false, review = false;
    std::vector<S> failed;
    const S done = L"已隔离：", fail = L"清理失败：";
    for (const auto& line : collected) {
        if (line.rfind(L"启动项移除失败", 0) == 0) {
            startupFailed = true;
            if (line.find(L"权限不足") != S::npos || line.find(L"[5]") != S::npos) startupDenied = true;
            else if (line.find(L"内容已变化") != S::npos) startupChanged = true;
            else startupOther = true;
        }
        else if (line.rfind(L"处置待复核：", 0) == 0) review = true;
        else if (line.rfind(done, 0) == 0) ++isolated;
        else if (line.rfind(fail, 0) == 0) {
            S rest = line.substr(fail.size());
            failed.push_back(rest.substr(0, rest.find(L" — ")));
        }
    }
    r.anyIsolated = isolated > 0;
    r.warning = startupFailed || review || !failed.empty() || !isolated;
    r.headline = isolated ? L"已隔离 " + num(isolated) + L" 项" : L"本次未能清除病毒";
    if (!failed.empty()) {
        r.content = L"以下 " + num(failed.size()) + L" 项未能清除：";
        for (size_t i = 0; i < std::min<size_t>(failed.size(), 8); ++i) r.content += L"\r\n" + failed[i];
        if (failed.size() > 8) r.content += L"\r\n其余 " + num(failed.size() - 8) + L" 项见日志。";
    } else if (!isolated) {
        r.content = L"请重新检查后再试。";
    }
    auto append = [&](const S& text) {
        if (!r.content.empty()) r.content += L"\r\n\r\n";
        r.content += text;
    };
    if (startupFailed) append(L"还有开机启动项未清除。");
    if (startupChanged) append(L"原因：启动项内容在检查后发生了变化。请重新检查并查杀。");
    if (startupDenied) append(L"原因：Windows 拒绝访问。请右键程序，选择“以管理员身份运行”后重试；若仍失败，请用完整杀毒软件处理。");
    if (startupOther) append(L"原因：读取或移除启动项时出错，具体错误见日志。请重新检查后重试。");
    if (review) append(L"还需用完整杀毒软件检查其他残留。");
    if (r.warning) append(L"详细记录见日志。");
    return r;
}
} // namespace usb
