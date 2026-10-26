# U 盘修复助手 · 加强版

v0.5.1 修复只扫描电脑后恢复 U 盘的空路径错误，提供明确的恢复入口并限制结果窗口宽度。见 [修复与验证记录](docs/HOTFIX-0.5.1.md)。

本仓库仅发布加强版。免安装程序和便携 ZIP 请在 [Releases](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/releases/latest) 下载。

> **测试样本说明**：本仓库不再公开提供真实病毒测试样本，检测指纹见 [samples/README.md](samples/README.md)。样本不包含在普通程序下载包中；确需隔离研究请通过 Issues 联系维护者私下沟通。

制作人：**李晓达**。因机务段带毒电脑过多、U 盘反复感染而开发本工具。

检查时显示流动进度条、当前文件/目录、已检查文件数及耗时；结果弹窗只显示必要的处理结果，详细过程保留在日志中。

v0.5.0 使用“检查 → 查杀与修复 → 恢复文件”的流程。病毒文件、指定启动项和磁盘显示设置在同一列表确认；处理结果与后续入口集中显示，详细日志默认收起。

支持目标为 Win7 SP1、Win10、Win11，32 位单文件、离线、免安装、无需 .NET 或额外 VC++ 运行库。**尚未进行加强版的虚拟机真实感染验收**。原版单一样本的 Win7/Win10 实测不能代替新增规则的实测。

## 检测与处置

| 内容 | 数量与来源 | 处理方式 |
|---|---|---|
| 原版样本 | 1 条 SHA-256、1 条特定 LNK 规则 | 确认后复核、备份隔离；处理精确关联进程和 Run/RunOnce |
| PlugX USB 变种 | Unit 42 的 8 条 SHA-256 | 大小未登记，命中后可明确勾选并复核隔离；侧载宿主及其他驻留仍需复核 |
| SOGU、FROZENHILL、ZIPZAG、SNOWYDRIVE | Mandiant 的 4 条 SHA-256 | 大小未登记，命中后可明确勾选并复核隔离 |
| Raspberry Robin DLL | Zscaler 的 2 条 SHA-256 | 大小未登记，命中后可明确勾选隔离，并核查明确关联的启动入口 |
| 7 类组合线索 | Bondat/PlugX/Raspberry Robin 风格 LNK、USB 传播脚本、Autorun 脚本入口、双扩展名伪装、FROZENHILL 配置字段组合 | 仅提示需核查，不据此自动隔离或确定家族 |

用 `tests/verify-public-rules.ps1` 可将新增 14 条哈希与当前原始报告逐条核对。只访问报告网页，不下载病毒。

## 使用步骤

1. 选择 U 盘，点击“开始检查”；程序同时检查电脑。只检查电脑时选择“仅检查电脑”。
2. 进度显示当前路径、数量、读取字节和耗时。可停止；本次程序未关闭时，“继续检查”保留枚举位置与已检查路径。达到本轮上限也可继续，不从头重扫。
3. 在“查杀与修复”统一列表勾选处理项。已确认病毒默认勾选；可疑项默认保留；纯数字 EXE 等低证据线索不能勾选隔离。未勾选的决定会记录，不能把“保留”显示成“已清除”。
4. 没有管理员权限时可打开系统授权窗口，管理员版本重新扫描和确认。若改用了另一 Windows 账户，新进程拒绝接管，保留原窗口及原用户对象。
5. 处理传播源后，选择隐藏目录预览并恢复。已知病毒、关联清理失败、重现以及关键范围未检查完会阻止恢复；需要确认的高可疑项不能被静默忽略。含嵌套程序的目录保留原处，其他符合条件的项目可恢复。重名保留双方。
6. 文件恢复后，保存正在编辑的文件并重启，再打开程序复查电脑与 U 盘。真实感染验收由用户在隔离虚拟机进行。

## 覆盖范围和限制

- 推荐范围：运行进程映像、Run/RunOnce 明确本地引用、Temp、AppData、启动目录、ProgramData、Public、Windows 子目录、当前用户目录（含桌面/文档/下载）和 Program Files，以及所选 U 盘。
- 目录分组轮转，电脑与 U 盘每轮各最多 200000 项；继续检查保留当前位置。深度 128，SHA-256 文件上限 64 MiB，文本/LNK 解析上限 1 MiB。哈希不限文件名或扩展名，同一路径在同轮会话只检查一次。
- 跳过重解析路径、系统回收站、系统卷信息和隔离目录。不覆盖其他用户、未选磁盘、网络路径、压缩包内部和内存注入。读取失败和跳过原因在详情及日志；“遍历结束”不等于所有文件成功读取。停止请求在枚举项与哈希数据块之间响应，底层设备 I/O 阻塞时不保证立即结束。
- 原版登记大小为 85,504 字节。大小与 SHA-256 同时匹配或原版精确诱饵 LNK 才默认进入确认隔离；其余 14 条公开指纹仍没有虚构大小，走单独的已知指纹人工确认隔离路径。
- dat 名称残留、可疑位置同名程序和 cmd 诱饵变体必须明确选择、重新核验大小/哈希/创建时间才处理。Temp 数字 EXE、未知脚本、Autorun 等不能仅凭线索删除。
- 进程只按映像完整路径与当前哈希匹配处理。检查服务/计划任务中的明确绝对路径引用：对用户选择隔离文件的直接关联项，备份当前配置、核验快照后停用；不删除服务或任务，不按正常宿主名称结束进程。共享宿主服务和复杂间接命令不自动处理，失败保留在恢复门禁中。
- 清理后进行 3 次有时限的文件/进程观察，并检查关联 Run 引用是否仍存在或重现。观察到一次重现便保留失败，不能因随后消失而覆盖。不是常驻监控，也不能证明内存或所有驻留已清除。
- 恢复引擎要求有效卷身份、关键范围检查结果和结构化处理状态；不能仅绕过 UI 直接恢复。用户保留的相关可疑文件在恢复前再次核验。只恢复符合条件的项目，非空容器不删除；空 U+FFFF 容器仍单独确认，并由非递归目录删除操作处理。
- 隔离与日志位于 `%LOCALAPPDATA%\UsbRecovery`。先锁定复核、备份落盘及校验，再删源文件；`.quarantine` 保存明文原始字节，不是加密容器，请勿运行、公开分发或上传。

## 构建和测试

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-enhanced.ps1 -ToolchainBin C:\Tools\w64devkit\bin -Tests
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\verify-public-rules.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\ui-results-smoke.ps1 -Exe .\dist\U盘修复助手-加强版.exe -Enhanced
```

需要 Windows 和 MinGW-w64 工具链（g++、windres、objdump）。可用 `-ToolchainBin` 指定工具链目录，或通过 `USB_TOOLCHAIN_BIN` 环境变量/PATH 查找。构建始终启用 `USB_ENHANCED`，输出到 `dist/`，也可用 `-OutputDirectory` 指定其他目录。规则表在 `src/enhanced_rules.hpp`，规则随构建更新，不加载来源不明的外部规则。

回归测试使用无害临时文件；新家族处置使用临时测试指纹和模拟宿主操作，不执行病毒或终止真实恶意进程；注册表测试仅使用临时创建的独立测试键，结束后移除。实际窗口检查不执行真实查杀和重启。

v0.5.0 的逐套测试输出和覆盖边界见 [本轮实现与交付](docs/FINAL-0.5.0.md) 及 `docs/verification/v0.5.0/`。原有测试继续保留，文本预期随确认的新流程调整；新检查覆盖可继续扫描、停止、统一处理状态、保留决定、恢复引擎门禁、部分恢复与实际处理列表。测试数量按实际断言调用累计，不能当作真实感染场景数量。

当前发布程序未做数字签名；启动提示和杀毒软件检测结果需区分，签名状态不等于病毒检测结果。

## 善后检查

- 在“处理结果 → 检查详情与善后”打开完整清单：重启后复查文件/进程是否重现；核对路由器 UPnP 陌生端口映射；曾联网的主机在网关/防火墙记录里核查 `45.141.233.6`、`94.26.90.235`。P2P 节点无法靠少数 IP 封禁覆盖，封 IP 仅为辅助，工具不自动更改网络规则。
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
