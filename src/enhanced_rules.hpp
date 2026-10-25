#pragma once
#include "engine.hpp"

namespace enhanced {
using namespace usb;
const wchar_t* const RULE_VERSION = L"2026.10.25.2";
struct HashRule { S digest, family, source, solution; uint64_t expectedSize=0; };
inline const std::vector<HashRule>& rules() {
    static const S mandiant = L"https://cloud.google.com/blog/topics/threat-intelligence/infected-usb-steal-secrets";
    static const S plugx = L"https://unit42.paloaltonetworks.com/plugx-variants-in-usbs/";
    static const S robin = L"https://www.zscaler.com/blogs/security-research/tracking-updates-raspberry-robin";
    static const S dllAdvice = L"隔离命中文件后，仍需用更新的杀毒软件复查内存、DLL 侧载宿主、计划任务和服务；不要按名称删除正常宿主。";
    static const std::vector<HashRule> table = {
        {HASH, L"Phorpiex（原版已验证样本）", L"项目 Win7/Win10 隔离实测记录", L"结束精确命中进程、备份移除直接关联 Run/RunOnce、校验隔离；重启后检查电脑及 U 盘。",85504},
        {L"8088B1B1FABD07798934ED3349EDC468062B166D5413E59E78216E69E7BA58AB", L"SOGU", mandiant, dllAdvice},
        {L"89558B4190ABCDC1A2353EDA591901DF3BB8856758F366291DF85C5345837448", L"FROZENHILL（USB 传播组件）", mandiant, dllAdvice},
        {L"8A968A91C78916A0BB32955CBEDC71A79B06A21789CAB8B05A037C8F2105E0AA", L"ZIPZAG（SNOWYDRIVE 投递组件）", mandiant, dllAdvice},
        {L"964C380BC6FFE313E548336C9DFAABBD01A5519E8635ADDE42EEDB7E1187C0B3", L"SNOWYDRIVE", mandiant, dllAdvice},
        {L"8EC37DAC2BEAA494DCEFEC62F0BF4AE30A6CE44B27A588169D8F0476BBC94115", L"PlugX USB 变种", plugx, dllAdvice},
        {L"E72E49DC1D95EFABC2C12C46DF373173F2E20DAB715CAF58B1BE9CA41EC0E172", L"PlugX USB 变种", plugx, dllAdvice},
        {L"0E9071714A4AF0BE1F96CFFC3B0E58520B827D9E58297CB0E02D97551ECA3799", L"PlugX USB 变种", plugx, dllAdvice},
        {L"39280139735145BA6F0918B684AB664A3DE7F93B1E3EBCDD071A5300486B8D20", L"PlugX USB 变种", plugx, dllAdvice},
        {L"41A0407371124BCAD7CAB56227078CCD635BA6E6B4374B973754AF96B7F58119", L"PlugX USB 变种", plugx, dllAdvice},
        {L"02AA5B52137410DE7CC26747F26E07B65C936D019EE2E1AFAE268A00E78A1F7F", L"PlugX USB 变种", plugx, dllAdvice},
        {L"2A07877CB53404888E1B6F81BB07A35BC804DAA1439317BCCDE9C498A521644C", L"PlugX USB 变种", plugx, dllAdvice},
        {L"5D98D1193FCBB2479668A24697023829FC9DC1F7D31833C3C42B8380EF859FF1", L"PlugX USB 变种", plugx, dllAdvice},
        {L"5B0476043DA365BE5325260F1F0811EA81C018A8ACC9CEE4CD46CB7348C06FC6", L"Raspberry Robin DLL", robin, dllAdvice},
        {L"05C6F53118D363EE80989EF37CAD85EE1C35B0E22D5DCEBD8A6D6A396A94CB65", L"Raspberry Robin DLL", robin, dllAdvice}
    };
    return table;
}
inline const HashRule* matchDigest(const S& digest, const std::vector<HashRule>& table = rules()) {
    if (digest.size() != 64) return nullptr;
    const S d = lower(digest);
    for (const auto& rule : table) if (lower(rule.digest) == d) return &rule;
    return nullptr;
}
inline bool ruleSizeMatches(const HashRule& rule,uint64_t actual) {return rule.expectedSize!=0 && rule.expectedSize==actual;}
inline S rulesText() {
    S text = L"U 盘修复助手 · 加强版\r\n规则版本：" + S(RULE_VERSION) + L"\r\n\r\n";
    text += L"内置 15 条 SHA-256 精确指纹（包含原版 1 条），另有原版精确 LNK 规则及 7 类可疑组合检查。\r\n";
    text += L"只有已登记大小且大小/SHA-256 同时匹配的规则、或原版特定 LNK 支持确认后隔离。其余 14 条公开 SHA-256 未登记大小，仅提示复核。组合特征仅提示需核查，不能据此确定家族或保证已处理所有驻留。尚未进行加强版虚拟机真实感染验收。\r\n\r\n";
    text += L"【检查与处置范围】\r\n电脑默认：Windows 和当前用户目录顶层、进程映像、Run/RunOnce 绝对本地引用；递归 Temp、Roaming/Local/Startup、ProgramData、Public。可选扩展检查 Windows 子目录、当前用户桌面/文档/下载和 Program Files；结果显示本次模式、未检查位置和访问限制。\r\n";
    text += L"U 盘：仅所选可移动卷，有界递归。不读取网络引用、重解析目录、系统回收站和系统卷信息；本机递归和所选 U 盘各最多 200000 项、深度 128。哈希文件上限 64 MiB；内容/LNK 解析上限 1 MiB；超限与访问失败会报告。压缩包内部、其他用户和内存注入不在覆盖范围。\r\n";
    text += L"精确命中：复核规则及当前哈希；只终止映像路径和哈希均匹配的恶意进程；备份移除明确引用该文件的 Run/RunOnce；校验备份后隔离。不会因启动项出现 wscript/rundll32 等系统程序名就终止或隔离它。\r\n";
    text += L"DLL/内存/侧载：不会凭进程名称结束正常程序，不自动清理服务或计划任务；报告后仍需查杀软件复核，重启再检查。隔离失败保留错误记录。\r\n";
    text += L"恢复：支持根目录隐藏容器和 .Trashes 下一级数字目录；跳过顶层可执行文件/脚本/快捷方式，拒绝含此类嵌套入口的目录。保留重名双方。先检查所选 U 盘，未处理已确认项必须先隔离；递归恢复可见属性；仅提供已复核为空的 U+FFFF 文件夹删除确认。恢复成功不等于清毒。\r\n\r\n";
    text += L"人工核查：tbtnds.dat/tbtcmds.dat 名称残留、可疑路径同名 EXE、cmd 诱饵变体逐项确认；Temp 纯数字 EXE 和其他组合线索只提示。Windows Settings 启动值与 NoDrives 策略须逐项确认、备份原值后处理；自设策略应保留。\r\n隔离区是明文备份，并非加密容器。网络、剪贴板和重启复查步骤见人工核查中的善后清单。\r\n\r\n";
    text += L"【组合特征与处理方案】\r\n";
    text += L"1. Bondat 风格：LNK 引用 .Trashes 中的 JS/JSE；先复查电脑启动文件夹/脚本，再核查 .Trashes 下数字目录中的原文件。正常 macOS .Trashes 本身不判毒。\r\n来源：https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Worm%3AJS%2FBondat\r\n";
    text += L"2. PlugX 风格：LNK 同时出现 U+00A0、RECYCLER.BIN 和载荷/侧载程序引用；保留 Unicode 路径，核查侧载 DLL 和计划任务。正常 x32dbg、Dism 等程序不能按名称删除。\r\n来源：https://unit42.paloaltonetworks.com/plugx-variants-in-usbs/\r\n";
    text += L"3. Raspberry Robin 风格：LNK 通过 msiexec 引用 HTTP(S)，或 cmd/type 管道；核查 RunOnce 引用的真实载荷，复查内存及后续投递。正常远程安装链接也可能触发提示。\r\n来源：https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/\r\n";
    text += L"4. 脚本型 USB 传播组合：脚本同时包含驱动器枚举、隐藏属性、快捷方式创建及驻留写入相关词；仅静态线索，不执行脚本，也不按家族定性。\r\n参考：https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/worm.wsf.dunihi.nlj\r\n";
    text += L"5. Autorun 脚本入口：仅在 [autorun] 的启动键引用脚本/脚本宿主时提示；单独存在 autorun.inf、图标或普通安装入口不算命中。核查被引用脚本，关闭自动运行，并用更新的杀毒软件复查电脑。\r\n";
    text += L"6. 双扩展名伪装：文档/图片扩展名后接 EXE/SCR/COM；需核查来源，不能仅凭文件名隔离。\r\n";
    text += L"7. FROZENHILL 内容线索：有效 PE 同时包含报告中的 6 个配置字段字符串；这是自建的较宽松线索，非完整 YARA 规则，仅供核查。\r\n来源：https://cloud.google.com/blog/topics/threat-intelligence/infected-usb-steal-secrets\r\n\r\n";
    text += L"【精确指纹及逐项方案】\r\n";
    for (const auto& rule : rules()) text += rule.family + L"\r\nSHA-256：" + rule.digest + L"\r\n登记大小："+(rule.expectedSize?num(rule.expectedSize)+L" 字节":L"未核实；仅提示，不自动隔离")+L"\r\n来源：" + rule.source + L"\r\n方案：" + rule.solution + L"\r\n\r\n";
    text += L"规则来源为公开报告中的指标及独立实现的静态检查；本程序不下载、执行或上传病毒样本。离线规则包随版本编译更新。";
    return text;
}
} // namespace enhanced
