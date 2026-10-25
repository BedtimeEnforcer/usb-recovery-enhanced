# U 盘修复助手 · 加强版

本仓库仅发布加强版。免安装程序和便携 ZIP 请在 [Releases](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/releases/latest) 下载。

> **危险测试资料**：另提供[真实病毒测试样本](samples/README.md)，仅供隔离环境中的静态检测验证，请勿运行。样本不包含在普通程序下载包中。

制作人：**李晓达**。因机务段带毒电脑过多、U 盘反复感染而开发本工具。

检查时显示流动进度条、当前文件/目录、已检查文件数及耗时；结果弹窗只显示必要的处理结果，详细过程保留在日志中。

界面使用“检查范围 + 三个操作步骤”的紧凑布局。操作记录默认收起，按需展开后也只占较小区域；检查、隔离和恢复均有结果弹窗，导出日志和规则方案保留独立入口。

支持目标为 Win7 SP1、Win10、Win11，32 位单文件、离线、免安装、无需 .NET 或额外 VC++ 运行库。**尚未进行加强版的虚拟机真实感染验收**。原版单一样本的 Win7/Win10 实测不能代替新增规则的实测。

## 检测与处置

| 内容 | 数量与来源 | 处理方式 |
|---|---|---|
| 原版样本 | 1 条 SHA-256、1 条特定 LNK 规则 | 确认后复核、备份隔离；处理精确关联进程和 Run/RunOnce |
| PlugX USB 变种 | Unit 42 的 8 条 SHA-256 | 精确命中支持隔离，侧载宿主及其他驻留仍需复核 |
| SOGU、FROZENHILL、ZIPZAG、SNOWYDRIVE | Mandiant 的 4 条 SHA-256 | 精确命中支持隔离，并显示后续方案 |
| Raspberry Robin DLL | Zscaler 的 2 条 SHA-256 | 精确命中支持隔离，并核查 Run/RunOnce 关联引用 |
| 7 类组合线索 | Bondat/PlugX/Raspberry Robin 风格 LNK、USB 传播脚本、Autorun 脚本入口、双扩展名伪装、FROZENHILL 配置字段组合 | 仅提示需核查，不据此自动隔离或确定家族 |

用 `tests/verify-public-rules.ps1` 可将新增 14 条哈希与当前原始报告逐条核对。只访问报告网页，不下载病毒。

## 使用步骤

1. 先选择“只检查电脑”检查传播源；有确认项时，以管理员身份检查并清理。
2. 选择 U 盘再检查，确认命中项可经确认隔离；需核查项先看原因。
3. 点“规则与处理方案”，可滚动、选择、复制完整规则、来源、限制和逐项方案。同目录 `规则与处理方案.txt` 是离线副本。
4. 先处理电脑传播源，再选择隐藏目录生成恢复预览。支持根目录容器和 Bondat 常见的 `.Trashes\数字目录`；重名保留双方。
5. 重启后再次检查电脑和 U 盘；遇到 DLL/侧载/内存线索，再用更新的完整杀毒软件复查。

## 覆盖范围和限制

- 电脑：原版常见目录顶层、进程映像、Run/RunOnce；增加当前用户 Roaming、Local、Temp、启动目录及 ProgramData、Public 的有界递归。
- 启动命令只提取 Windows 参数中明确的绝对本地路径，支持引号和 rundll32 的载荷/导出名。不解释 cmd/PowerShell，不跟随 UNC 或映射网络盘；相对、间接、编码及其他复杂语法可能漏检。
- 本机递归和所选 U 盘各有 200000 项预算，深度上限 128。跳过重解析路径、系统回收站、系统卷信息和隔离目录。访问失败及超限记录在日志中。
- 文件哈希上限 64 MiB，文本/LNK 解析上限 1 MiB。哈希不限文件名和扩展名；不解压缩或检查压缩包内部。
- 仅精确指纹和原版特定 LNK 可确认后隔离。未知组合、正常快捷方式、普通 Autorun 安装入口以及单独的 `.Trashes` 目录不自动清理。
- 只按精确映像路径和哈希终止进程，不按 wscript、rundll32、Dism、x32dbg 等名称终止系统程序或正常宿主。不自动处理计划任务、服务、注入内存或其他用户。
- 恢复跳过顶层可执行文件、DLL、脚本、安装包和快捷方式；嵌套目录含这些入口时停止。其他未知数据仍可能有风险，恢复成功不等于清毒。
- 隔离与记录沿用 `%LOCALAPPDATA%\UsbRecovery` 及原版的锁定复核、备份校验、日志落盘机制。隔离文件不是加密容器。

## 构建和测试

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-enhanced.ps1 -ToolchainBin C:\Tools\w64devkit\bin -Tests
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\verify-public-rules.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\ui-results-smoke.ps1 -Exe .\dist\U盘修复助手-加强版.exe -Enhanced
```

需要 Windows 和 MinGW-w64 工具链（g++、windres、objdump）。可用 `-ToolchainBin` 指定工具链目录，或通过 `USB_TOOLCHAIN_BIN` 环境变量/PATH 查找。构建始终启用 `USB_ENHANCED`，输出到 `dist/`，也可用 `-OutputDirectory` 指定其他目录。规则表在 `src/enhanced_rules.hpp`，规则随构建更新，不加载来源不明的外部规则。

回归测试使用无害临时文件；新家族处置使用临时测试指纹和模拟宿主操作，不执行病毒或终止真实恶意进程；注册表测试仅使用临时创建的独立测试键，结束后移除。实际窗口检查不执行真实查杀和重启。

当前验证：18 项基础引擎测试、14 项结果汇总测试、57 项加强版测试、7 项进度界面测试，共 96 项通过。进度界面测试使用无害文件模拟慢速扫描。

当前发布程序未做数字签名；启动提示和杀毒软件检测结果需区分，签名状态不等于病毒检测结果。

## 公开依据

- [Unit 42：PlugX USB 变种及样本指标](https://unit42.paloaltonetworks.com/plugx-variants-in-usbs/)
- [Mandiant：SOGU、SNOWYDRIVE 与相关组件](https://cloud.google.com/blog/topics/threat-intelligence/infected-usb-steal-secrets)
- [Zscaler：Raspberry Robin DLL 指纹](https://www.zscaler.com/blogs/security-research/tracking-updates-raspberry-robin)
- [Microsoft：Raspberry Robin 传播与驻留](https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/)
- [Microsoft：Bondat 的 .Trashes 和脚本传播](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Worm%3AJS%2FBondat)
- [Trend Micro：DUNIHI 脚本型可移动介质传播](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/worm.wsf.dunihi.nlj)

组合检查由本项目独立实现。FROZENHILL 字段组合只是较宽松的自建线索，未集成完整 YARA 引擎，也不等同于报告中的完整规则。精确指纹仅覆盖列出的样本，不能代表家族全部变种。
