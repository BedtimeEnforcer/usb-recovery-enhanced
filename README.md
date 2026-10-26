# U 盘修复助手 · 加强版

v0.6.2 修复隐藏容器中程序文件和完整软件目录未恢复的问题：查杀完成后不再按扩展名筛选，恢复剩余内容到 U 盘根目录，并处理嵌套隐藏容器。见 [恢复修复与验证记录](docs/HOTFIX-0.6.2.md)。

本仓库仅发布加强版。免安装程序和便携 ZIP 请在 [Releases](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/releases/latest) 下载。

> **测试样本说明**：本仓库不再公开提供真实病毒测试样本，检测指纹见 [samples/README.md](samples/README.md)。样本不包含在普通程序下载包中；确需隔离研究请通过 Issues 联系维护者私下沟通。

制作人李晓达，U盘经常被机务段病毒电脑感染，实在受不了，做了此工具，请传给需要的人。

检查时显示流动进度条、当前文件/目录、已检查文件数及耗时；结果弹窗只显示必要的处理结果，详细过程保留在日志中。

主界面不再选择盘符或隐藏目录，也不再要求分别点击清理与恢复。U盘专杀先提示适用条件，再打开带复选框的 U 盘列表。结果只给出数量和必要提醒；完成详情列出已清理和已恢复项目，操作日志可单独查看。

支持目标为 Win7 SP1、Win10、Win11，32 位单文件、离线、免安装、无需 .NET 或额外 VC++ 运行库。**尚未进行加强版的虚拟机真实感染验收**。原版单一样本的 Win7/Win10 实测不能代替新增规则的实测。

## 检测与处置

| 内容 | 数量与来源 | 处理方式 |
|---|---|---|
| 原版样本 | 1 条 SHA-256、1 条特定 LNK 规则 | 复核、备份隔离；全盘模式处理精确关联进程和 Run/RunOnce |
| PlugX USB 变种 | Unit 42 的 8 条 SHA-256 | 精确指纹命中并复核后隔离；侧载宿主及其他驻留仍需复核 |
| SOGU、FROZENHILL、ZIPZAG、SNOWYDRIVE | Mandiant 的 4 条 SHA-256 | 精确指纹命中并复核后隔离 |
| Raspberry Robin DLL | Zscaler 的 2 条 SHA-256 | 精确指纹命中并复核后隔离；全盘模式处理明确关联的启动入口 |
| 7 类组合线索 | Bondat/PlugX/Raspberry Robin 风格 LNK、USB 传播脚本、Autorun 脚本入口、双扩展名伪装、FROZENHILL 配置字段组合 | 仅提示需核查，不据此自动隔离或确定家族 |

用 `tests/verify-public-rules.ps1` 可将新增 14 条哈希与当前原始报告逐条核对。只访问报告网页，不下载病毒。

## 使用步骤

- **全盘杀毒**：电脑已中毒或无法确定时使用。点击后按需获取管理员权限，扫描本机固定磁盘和启动时接入的全部可移动 U 盘，自动清理已知病毒，再恢复 U 盘隐藏文件。
- **U盘专杀**：仅供未中病毒的电脑使用。提示“建议使用全盘杀毒”后，勾选一个或多个 U 盘，点击“开始查杀并恢复”。不扫描电脑目录，不枚举或清理电脑进程、注册表、服务、计划任务。
- 操作期间可停止；当前安全操作结束后停止后续处理。再次点击模式会重新扫描。内部达到批次上限时自动继续，无需反复点击。
- U盘专杀结束提醒：若重新插入 U 盘仍出现快捷方式，说明电脑已中病毒，请使用全盘杀毒。
- 结果有未完成项时查看操作记录。未知文件保留，不会为了完成恢复而跳过已知病毒、卷身份或清理失败检查。

## 覆盖范围和限制

- 全盘模式：运行进程、Run/RunOnce 明确引用、常见落地位置、本机全部固定磁盘和已接入的可移动 U 盘。U盘专杀：仅勾选的可移动 U 盘。设备选择后记录卷身份，更换盘或拔出后拒绝继续恢复。
- 目录分组轮转，每轮最多 200000 项；自动接续下一轮，保留枚举位置。深度 128，SHA-256 文件上限 64 MiB，文本/LNK 解析上限 1 MiB。哈希不限文件名或扩展名，同一路径在同轮会话只检查一次。
- 跳过重解析路径、系统回收站、系统卷信息和隔离目录。不覆盖网络路径、压缩包内部和内存注入；U盘专杀不覆盖电脑或未选盘。读取失败和跳过原因只保留在操作记录；“遍历结束”不等于所有文件成功读取。停止请求在枚举项与哈希数据块之间响应，底层设备 I/O 阻塞时不保证立即结束。
- 原版登记大小为 85,504 字节。大小与 SHA-256 同时匹配或原版精确诱饵 LNK 才默认进入确认隔离；其余 14 条公开指纹仍没有虚构大小；用户启动一键查杀后，对精确 SHA-256 命中项重新核验扫描时大小、哈希、创建时间，再备份隔离。
- dat 名称残留、可疑位置同名程序和 cmd 诱饵变体自动保留并报告；相关高风险未解决时暂停恢复。Temp 数字 EXE、未知脚本、Autorun 等不能仅凭线索删除。
- 全盘模式下，进程只按映像完整路径与当前哈希匹配处理。检查服务/计划任务中的明确绝对路径引用：对已知病毒文件的直接关联项，备份当前配置、核验快照后停用；不删除服务或任务，不按正常宿主名称结束进程。共享宿主服务和复杂间接命令不自动处理，失败保留在恢复门禁中。
- 清理后进行 3 次有时限的观察：U盘专杀仅检查文件是否重现；全盘模式还检查进程和关联 Run 引用。观察到一次重现便保留失败，不能因随后消失而覆盖。不是常驻监控，也不能证明内存或所有驻留已清除。
- 恢复引擎要求有效卷身份、已结束的扫描和结构化处理状态；不能仅绕过 UI 直接恢复。U 盘相关高可疑文件未处理时暂停恢复。U+FFFF / .Trashes 数字容器中的安全数据移至根目录；普通隐藏文件夹原位显示、保留结构，根目录普通隐藏文件恢复可见。重名保留双方，非空容器不删除；空 U+FFFF 容器经复核后非递归删除。
- 隔离与日志位于 `%LOCALAPPDATA%\UsbRecovery`。先锁定复核、备份落盘及校验，再删源文件；`.quarantine` 保存明文原始字节，不是加密容器，请勿运行、公开分发或上传。

## 构建和测试

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-enhanced.ps1 -ToolchainBin C:\Tools\w64devkit\bin -Tests
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\verify-public-rules.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\ui-two-modes-smoke.ps1 -Exe .\dist\U盘修复助手-加强版.exe
```

需要 Windows 和 MinGW-w64 工具链（g++、windres、objdump）。可用 `-ToolchainBin` 指定工具链目录，或通过 `USB_TOOLCHAIN_BIN` 环境变量/PATH 查找。构建始终启用 `USB_ENHANCED`，输出到 `dist/`，也可用 `-OutputDirectory` 指定其他目录。规则表在 `src/enhanced_rules.hpp`，规则随构建更新，不加载来源不明的外部规则。

回归测试使用无害临时文件；新家族处置使用临时测试指纹和模拟宿主操作，不执行病毒或终止真实恶意进程；注册表测试仅使用临时创建的独立测试键，结束后移除。实际窗口检查不执行真实查杀和重启。

v0.5.0 的逐套测试输出和覆盖边界见 [本轮实现与交付](docs/FINAL-0.5.0.md) 及 `docs/verification/v0.5.0/`。原有测试继续保留，文本预期随确认的新流程调整；新检查覆盖可继续扫描、停止、统一处理状态、保留决定、恢复引擎门禁、部分恢复与实际处理列表。测试数量按实际断言调用累计，不能当作真实感染场景数量。

当前发布程序未做数字签名；启动提示和杀毒软件检测结果需区分，签名状态不等于病毒检测结果。

## 善后检查

- 清理并重启后，复查文件/进程是否重现；核对路由器 UPnP 陌生端口映射；曾联网的主机在网关/防火墙记录里核查 `45.141.233.6`、`94.26.90.235`。P2P 节点无法靠少数 IP 封禁覆盖，封 IP 仅为辅助，工具不自动更改网络规则。
- 感染期间做过加密货币转账，应逐笔核对收款地址；输入过的密码、助记词应视为可能泄露，在干净设备更换密码并使用新助记词钱包迁移资产。
- NoDrives 可能是用户或管理员自己的策略，一键流程保留，不自动改动。
- 恢复成功不等于清毒；恢复后只删除经复核为空的 U+FFFF 容器，非空容器保留。

## 公开依据

- [Unit 42：PlugX USB 变种及样本指标](https://unit42.paloaltonetworks.com/plugx-variants-in-usbs/)
- [Mandiant：SOGU、SNOWYDRIVE 与相关组件](https://cloud.google.com/blog/topics/threat-intelligence/infected-usb-steal-secrets)
- [Zscaler：Raspberry Robin DLL 指纹](https://www.zscaler.com/blogs/security-research/tracking-updates-raspberry-robin)
- [Microsoft：Raspberry Robin 传播与驻留](https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/)
- [Microsoft：Bondat 的 .Trashes 和脚本传播](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Worm%3AJS%2FBondat)
- [Trend Micro：DUNIHI 脚本型可移动介质传播](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/worm.wsf.dunihi.nlj)

组合检查由本项目独立实现。FROZENHILL 字段组合只是较宽松的自建线索，未集成完整 YARA 引擎，也不等同于报告中的完整规则。精确指纹仅覆盖列出的样本，不能代表家族全部变种。
