# U 盘修复助手 · 加强版

本仓库仅发布加强版。免安装程序和便携 ZIP 请在 [Releases](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/releases/latest) 下载。

> **测试样本说明**：本仓库不再公开提供真实病毒测试样本，检测指纹见 [samples/README.md](samples/README.md)。样本不包含在普通程序下载包中；确需隔离研究请通过 Issues 联系维护者私下沟通。

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

1. 先选择“只检查电脑”检查传播源；有确认项时，以管理员身份检查并清理；扩展检查可补查系统子目录、桌面/文档/下载和 Program Files，耗时较长。
2. 选择 U 盘再检查，确认命中项可经确认隔离；需核查项点击“人工核查”，逐项查看路径、大小、指纹、创建时间及原始注册表值，只有明确同意的受支持候选才会备份处理。
3. 点“规则与处理方案”，可滚动、选择、复制完整规则、来源、限制和逐项方案。同目录 `规则与处理方案.txt` 是离线副本。
4. 先检查电脑和所选 U 盘、完成已确认项隔离，再选择隐藏目录生成恢复预览。没有检查所选盘、或仍有 confirmed 项时会拦截恢复。支持根目录容器和 Bondat 常见的 `.Trashes\数字目录`；重名保留双方。
5. 重启后再次检查电脑和 U 盘；遇到 DLL/侧载/内存线索，再用更新的完整杀毒软件复查。

## 覆盖范围和限制

- 默认主机范围：Windows 和当前用户目录顶层、运行进程映像、Run/RunOnce 明确引用文件；有界递归 Temp、Roaming、Local、启动目录、ProgramData、Public。
- 可选扩展范围：Windows 子目录（含 System32/SysWOW64）、当前用户目录（含桌面/文档/下载）及 Program Files。始终不覆盖其他用户、其他未选磁盘、网络盘、压缩包内部及内存/全部驻留。每次结果可展开实际范围和未检查位置，不能把完成提示当作未列位置已检查。
- 启动命令只提取 Windows 参数中明确的绝对本地路径，支持引号和 rundll32 的载荷/导出名。不解释 cmd/PowerShell，不跟随 UNC 或映射网络盘；相对、间接、编码及其他复杂语法可能漏检；指定值名 Windows Settings 另行列为人工核查候选，即使目标已不存在也会显示。
- 本机递归和所选 U 盘各有 200000 项预算，深度上限 128。跳过重解析路径、系统回收站、系统卷信息和隔离目录。访问失败及超限记录在日志中。
- 文件哈希上限 64 MiB，文本/LNK 解析上限 1 MiB。哈希不限文件名和扩展名；不解压缩或检查压缩包内部。
- 精确指纹和原版特定 cmd 目标 LNK 可进入确认项隔离。dat 名称残留、可疑路径同名 EXE、cmd 诱饵变体属于人工核查轨，必须逐项确认并重新校验文件；不会当作已确诊病毒。Temp 纯数字 EXE、未知组合、脚本、Autorun 和正常快捷方式不自动隔离。
- 只按精确映像路径和哈希终止进程，不按 wscript、rundll32、Dism、x32dbg 等名称终止系统程序或正常宿主。不自动处理计划任务、服务、注入内存或其他用户。
- 恢复跳过顶层可执行文件、DLL、脚本、安装包和快捷方式；嵌套目录含这些入口时停止。其他未知数据仍可能有风险，恢复成功不等于清毒。
- 隔离与记录沿用 `%LOCALAPPDATA%\UsbRecovery` 及原版的锁定复核、备份校验、日志落盘机制。隔离文件不是加密容器：`.quarantine` 保存明文原始字节，请勿运行、公开或上传分发，应妥善保管并交给安全软件处理。

## 构建和测试

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-enhanced.ps1 -ToolchainBin C:\Tools\w64devkit\bin -Tests
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\verify-public-rules.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\ui-results-smoke.ps1 -Exe .\dist\U盘修复助手-加强版.exe -Enhanced
```

需要 Windows 和 MinGW-w64 工具链（g++、windres、objdump）。可用 `-ToolchainBin` 指定工具链目录，或通过 `USB_TOOLCHAIN_BIN` 环境变量/PATH 查找。构建始终启用 `USB_ENHANCED`，输出到 `dist/`，也可用 `-OutputDirectory` 指定其他目录。规则表在 `src/enhanced_rules.hpp`，规则随构建更新，不加载来源不明的外部规则。

回归测试使用无害临时文件；新家族处置使用临时测试指纹和模拟宿主操作，不执行病毒或终止真实恶意进程；注册表测试仅使用临时创建的独立测试键，结束后移除。实际窗口检查不执行真实查杀和重启。

本次改动的实际测试结果和逐条硬约束自查见 [改动与验收记录](docs/IMPLEMENTATION.md)。原有 96 个用例全部保留；文本预期与快捷方式构造器随需求更新，新增测试使用无害文件、模拟进程动作和一次性注册表键。没有执行病毒。

当前发布程序未做数字签名；启动提示和杀毒软件检测结果需区分，签名状态不等于病毒检测结果。

## 善后检查

- 在“人工核查”打开完整清单：重启后复查文件/进程是否重现；核对路由器 UPnP 陌生端口映射；曾联网的主机在网关/防火墙记录里核查 `45.141.233.6`、`94.26.90.235`。P2P 节点无法靠少数 IP 封禁覆盖，封 IP 仅为辅助，工具不自动更改网络规则。
- 感染期间做过加密货币转账，应逐笔核对收款地址；输入过的密码、助记词应视为可能泄露，在干净设备更换密码并使用新助记词钱包迁移资产。
- NoDrives 可能是用户或管理员自己的策略，默认保留，逐项展示原值后才允许备份移除。
- 恢复成功不等于清毒；恢复后只会对经两次空检查的 U+FFFF 空容器提供删除确认，非空容器保留。

## 公开依据

- [Unit 42：PlugX USB 变种及样本指标](https://unit42.paloaltonetworks.com/plugx-variants-in-usbs/)
- [Mandiant：SOGU、SNOWYDRIVE 与相关组件](https://cloud.google.com/blog/topics/threat-intelligence/infected-usb-steal-secrets)
- [Zscaler：Raspberry Robin DLL 指纹](https://www.zscaler.com/blogs/security-research/tracking-updates-raspberry-robin)
- [Microsoft：Raspberry Robin 传播与驻留](https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/)
- [Microsoft：Bondat 的 .Trashes 和脚本传播](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Worm%3AJS%2FBondat)
- [Trend Micro：DUNIHI 脚本型可移动介质传播](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/worm.wsf.dunihi.nlj)

组合检查由本项目独立实现。FROZENHILL 字段组合只是较宽松的自建线索，未集成完整 YARA 引擎，也不等同于报告中的完整规则。精确指纹仅覆盖列出的样本，不能代表家族全部变种。
