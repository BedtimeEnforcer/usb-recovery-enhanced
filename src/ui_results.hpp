#pragma once
#include "engine.hpp"

namespace usb {
struct UiReport {
    S headline, content, details;
    bool warning = false, anyIsolated = false;
};

inline S aftercareChecklist() {
    return L"【重启与复活复查】\r\n保存文件后重启，再检查电脑和所选 U 盘；核对病毒进程是否重新出现、已隔离文件是否重现。若重现，保留日志并使用更新的完整杀毒软件复查驻留。\r\n\r\n"
           L"【网络善后（手动）】\r\n1. 检查路由器 UPnP 端口映射表，核实后删除陌生映射。\r\n2. 若感染期间联网，在网关/防火墙连接记录中核查 45.141.233.6、94.26.90.235。P2P 节点无法靠封禁少数 IP 完整覆盖，封 IP 只是辅助。本工具不自动改路由器或防火墙。\r\n\r\n"
           L"【剪贴板与账户核对】\r\n感染期间如有加密货币转账，逐笔核对收款地址是否被剪贴板地址替换。感染期间输入过的密码、助记词应视为可能泄露：在干净设备更换密码，创建新钱包/新助记词并安全迁移资产，不再使用旧助记词。\r\n\r\n"
           L"【隔离区】\r\n%LOCALAPPDATA%\\UsbRecovery 内的 .quarantine 是明文备份，并未加密。不要运行或公开分发，妥善保管并交由安全软件处理。\r\n\r\n"
           L"尚未进行加强版虚拟机真实感染验收。未命中不代表整机无毒；恢复成功不等于清毒。";
}
inline bool scanNotice(const S& line) {
    // 仅排除已知的正常进度；保留原样转发的目录访问异常，避免遗漏。
    if (line.empty() || line.rfind(L"检查电脑进程映像、", 0) == 0 ||
        line.rfind(L"检查所选 U 盘：", 0) == 0 ||
        line.rfind(L"加强版规则 ", 0) == 0 || line.rfind(L"加强版检查结束", 0) == 0 ||
        line.rfind(L"无法读取路径的进程数：0（", 0) == 0 ||
        (line.rfind(L"跳过 ", 0) == 0 && line.find(L"个确认不存在的文件") != S::npos)) return false;
    return true;
}

inline UiReport scanReport(const std::vector<Finding>& findings, const std::vector<S>& notices) {
    UiReport r;
    size_t confirmed = 0, unknown = 0;
    r.details=L"未命中不代表整机无毒。\r\n以下为本次范围和未检查记录：";
    for(const auto& notice:notices)r.details+=L"\r\n"+notice;
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
    size_t isolated = 0, registryRemoved = 0;
    bool revived=false;
    bool startupFailed = false, startupDenied = false, startupChanged = false, startupOther = false, review = false;
    std::vector<S> failed, startupFailures;
    const S done = L"已隔离：", fail = L"清理失败：";
    for (const auto& line : collected) {
        if (line.rfind(L"启动项移除失败", 0) == 0) {
            startupFailed = true;
            startupFailures.push_back(line);
            if (line.find(L"权限不足") != S::npos || line.find(L"[5]") != S::npos) startupDenied = true;
            else if (line.find(L"内容已变化") != S::npos) startupChanged = true;
            else startupOther = true;
        }
        else if (line.rfind(L"复查发现",0)==0) revived=true;
        else if (line.rfind(L"处置待复核：", 0) == 0) review = true;
        else if (line.rfind(L"已移除人工确认注册表项：", 0) == 0) ++registryRemoved;
        else if (line.rfind(done, 0) == 0) ++isolated;
        else if (line.rfind(fail, 0) == 0) {
            S rest = line.substr(fail.size());
            failed.push_back(rest.substr(0, rest.find(L" — ")));
        }
    }
    r.details = aftercareChecklist();
    r.anyIsolated = isolated > 0;
    r.warning = revived || startupFailed || review || !failed.empty() || (!isolated && !registryRemoved);
    r.headline = isolated ? L"已隔离 " + num(isolated) + L" 项" : (registryRemoved ? L"已移除 " + num(registryRemoved) + L" 项注册表值" : L"本次未能清除病毒");
    if(startupFailed)r.headline+=L"；还有启动项未清除";
    if (!failed.empty()) {
        r.content = L"以下 " + num(failed.size()) + L" 项未能清除：";
        for (size_t i = 0; i < std::min<size_t>(failed.size(), 8); ++i) r.content += L"\r\n" + failed[i];
        if (failed.size() > 8) r.content += L"\r\n其余 " + num(failed.size() - 8) + L" 项见日志。";
    } else if (!isolated && !registryRemoved) {
        r.content = L"请重新检查后再试。";
    }
    auto append = [&](const S& text) {
        if (!r.content.empty()) r.content += L"\r\n\r\n";
        r.content += text;
    };
    if(startupFailed) {
        S priority=L"启动项未清除，请重启后复查：";
        for(const auto& failure:startupFailures)priority+=L"\r\n"+failure;
        if(!r.content.empty())priority+=L"\r\n\r\n"+r.content;
        r.content=priority;
    }
    if (startupChanged) append(L"原因：启动项内容在检查后发生了变化。请重新检查并查杀。");
    if (startupDenied) append(L"原因：Windows 拒绝访问。请右键程序，选择“以管理员身份运行”后重试；若仍失败，请用完整杀毒软件处理。");
    if (startupOther) append(L"原因：读取或移除启动项时出错，具体错误见日志。请重新检查后重试。");
    if(revived)append(L"复查发现文件或进程仍在或重新出现，请重启后复查，保留日志并用完整杀毒软件处理。");
    if (review) append(L"还需用完整杀毒软件检查其他残留。");
    if (r.warning) append(L"详细记录见日志。");
    return r;
}
} // namespace usb
