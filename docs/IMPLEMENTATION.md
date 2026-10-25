# 改动与验收记录

以用户提供的《给 Codex 的改动任务书》为验收依据。配套 ANALYSIS.md 与 REVIEW-usb-recovery-enhanced.md 未随文件提供，未将其中未提供的内容视为已独立核实。

## 任务 1：残留、策略、数字 Temp 文件与善后

- `src/engine.hpp`：为 Finding 增加人工核查类别、文件大小和创建时间，原 confirmed 隔离门禁保持独立。
- `src/enhanced_engine.hpp`：`Scanner::inspect` 提示两个 dat 名称与 Temp 数字 EXE；`quarantineReviewed` 仅在逐项同意、哈希/大小/创建时间复核后备份隔离残留候选。
- `src/review_registry.hpp`：`noDrivesPolicies` 读取两根键和两视图；`removeReviewedValue` 逐项确认、备份完整类型/原始字节、比较当前快照后删除。
- `src/main.cpp`：新增“人工核查”入口；完成窗口可展开查看善后清单。
- `src/ui_results.hpp`：网络、剪贴板转账、账户凭据和重启复活检查清单；明确隔离备份未加密。
- 冲突处理：仅文件名不足以确诊；遵循全局约束 2，不把两个 dat 名称赋予 confirmed。它们显示为残留候选，必须用户逐项确认，不进入自动清理。
- 验证：`remediation-tests` 新增 13 项无害/临时注册表测试通过，主程序语法检查通过。没有修改真实策略或运行病毒。

## 任务 2：启动项双轨与失败置顶

- `review_registry.hpp::namedStartupCandidates`：独立列出两根键、Run/RunOnce、两视图中的确切 Windows Settings 值，不依赖目标文件存在或命令能解析为绝对路径；复用 runs 枚举。
- `cleanReviewedStartup`：必须显式确认，比较原值并备份后删除；失败保留完整根键、键路径、视图、值名和原因。
- `enhanced_engine.hpp::removeReferences` 和基础清理日志保留精确引用轨，补全错误位置。
- `main.cpp::doReview`：新增启动项人工确认入口；HKLM 等处理保留管理员门禁。
- `ui_results.hpp::cleanReport`：启动项失败在正文第一项，标题说明仍有启动项未清除，并要求重启后复查。
- 验证：`remediation-tests` 累计 19 项通过（本任务新增 6 项），涵盖直接引用、孤儿值、间接引用、拒绝访问模拟；只操作一次性测试键。

## 任务 3：可选扩展检查与实际范围

- `enhanced_engine.hpp::ScanOptions/scopeDescription/scanTrees`：默认保留原有范围；可选扩展 Windows、当前用户目录和 Program Files，使用同一个主机 200000 项预算，U 盘仍有独立预算。未扫描根目录、访问失败和超限记录保留。
- `main.cpp`：新增扩展检查复选框；扫描结果可展开“范围与未检查位置”。
- `ui_results.hpp::scanReport`：保留实际扫描范围、盲区、访问失败，未命中不代表整机无毒。
- 不默认扩大的原因：此前本机扫描已经累计读取十余 GiB，直接扩大默认范围会使耗时进一步增加。选择扩展检查时明确提示较慢。
- 验证：`remediation-tests` 累计 23 项通过，本任务新增 4 项，含 System32 模拟目录里的无害自定义指纹命中及预算耗尽记录。

## 任务 4：恢复门禁、递归可见属性与空容器收尾

- `enhanced_engine.hpp::requireRecoveryReady` 与 `main.cpp::doRestore`：要求成功检查当前所选 U 盘，并拦截仍未处理的 confirmed 项；隔离成功才从当前 Finding 中移除，失败项保留。
- `makeTreeVisible`：移动后的用户目录和文件递归清除 HIDDEN/SYSTEM，保留其他属性，记录变更，继续遵守深度/项数及拒绝链接的约束。
- `canDeleteEmptyContainer/deleteEmptyContainer`：仅允许当前卷的根目录 U+FFFF 空容器，单独确认并再次检查；通过目录句柄的 FileDispositionInfo 删除，Windows 在出现子项时原子拒绝。没有递归删除，也没有 RemoveDirectory 调用。
- `main.cpp::offerDeleteEmpty`：仅空容器显示“删除空的 U+FFFF 文件夹”确认按钮；结果保留“恢复成功不等于清毒”。
- 验证：`remediation-tests` 累计 35 项通过，本任务新增 12 项，含未处理项门禁、嵌套属性、无确认不删、新出现用户文件拒绝删、空容器删除、嵌套程序拒绝恢复。

## 任务 5：cmd 目标与变体诱饵快捷方式

- `engine.hpp::parseStaticLink/commandTarget/wormLink/variantWormLink`：静态读取 LinkInfo、StringData 和有界环境变量目标块；原版确认要求 cmd.exe/%comspec% 目标和原始精确参数。带附加参数、盘符等变体仅列为高可疑。
- `enhanced_engine.hpp::Scanner::inspect/quarantineReviewed`：快捷方式变体逐项确认后，重新验证目标、命令模式、大小、创建时间及哈希，才允许备份隔离；原 cleanOne 规则复核不放宽。
- `main.cpp::doReview`：允许逐项核查此类快捷方式。
- 更新旧测试的无害快捷方式构造器，增加真实目标字段，以适配新增目标检查；没有移除原测试用例。
- 验证：新增原版/变体/盘符前缀/非 cmd/普通快捷方式及人工确认隔离测试，`remediation-tests` 累计 41 项通过。

## 任务 6：可疑名称与落地路径、清理后复查

- `enhanced_engine.hpp::highRiskLocation/highRiskOnHost/Scanner::inspect`：已知可疑名称在 Windows、AppData、Temp 或所选 U 盘隐藏目录时列为高可疑；正常配置范围外同名文件仍仅为普通提示。
- `quarantineReviewed`：仅逐项确认后，复核路径条件、文件大小/哈希/创建时间，按精确路径和当前哈希结束对应进程并隔离。自动 cleanOne 不接受这些候选的伪造 confirmed。
- `postCleanReview`：清理后单次快照检查原文件路径和运行进程路径，仍存在/重现时警告；完成清单明确要求重启复查，不宣称已验证看门狗循环。
- 人工隔离也做单次重现复查；原文件重现时不从待处理 confirmed 中移除。
- 验证：`remediation-tests` 累计 49 项通过，本任务新增 8 项；进程动作使用 mock，没有运行病毒或终止真实进程。

## 任务 7：病毒简介证据边界

- `ui_text.hpp::usageGuideText`：准确描述剪贴板地址替换，提示感染期间输入的密码、助记词可能泄露；建议干净设备更换密码、新助记词钱包与资产迁移，不再作未证实的密钥外传断言。
- `main.cpp::showGuide`：使用统一的可测试简介文本，保留危害、查杀步骤、制作人及开发缘由。
- `ui-results-smoke.ps1` 和 `remediation-tests` 增加对应文本验证；主程序语法检查通过，最终构建会运行全部测试。

## 任务 8：范围、用语与可查看详情

- 结果正文保留“未命中不代表整机无毒”；非零未检查/访问限制不再给出无警告的结果，具体原因收在可展开详情和日志，避免把每条错误堆进弹窗正文。
- “人工核查”增加可滚动的范围/未检查报告和善后清单；文件核查支持取消整次操作，不会迫使用户遍历所有候选。
- 规则、程序说明、README 对齐默认/扩展范围和预算，明确尚未进行加强版虚拟机真实感染验收、恢复成功不等于清毒；没有发布样本链接或密码。
- 原有结果测试保留 14 个用例，调整预期以验证新的范围警告、失败置顶和谨慎用语；没有删除测试以凑通过数。
- 主程序语法检查通过；完整实际测试结果由任务 9 记录。


## 任务 9：实际构建、回归与交付

- 实际执行 `build-enhanced.ps1 -ToolchainBin <现有 MinGW-w64 工具链 bin> -Tests`，不是引用旧计数。
- 最终结果：18 项基础引擎 + 14 项结果汇总 + 57 项加强版 + 64 项新增修复测试 + 11 项实际进度/核查界面测试，**164/164 通过**。原有 96 个用例全部保留；新增 64 项修复测试与 4 项界面测试。
- `ui-results-smoke.ps1 -Enhanced` 对最终 EXE 的首页必阅、无确认项提示、折叠/展开记录、规则窗口和正常退出检查通过，并查看了实际截图。
- 所有测试使用无害文件、临时测试指纹、精确路径动作 mock 和一次性注册表测试键，没有执行病毒、终止真实恶意进程、修改真实用户策略或重启机器。
- 最终版本 0.4.0；规则版本 2026.10.25.2。没有数字签名。
- 审查发现的额外门禁修正：扫描卷序列号与恢复时一致；恢复前复查最近隔离路径；目录枚举在预算 + 1 哨兵处停止；主机耗尽预算不会跳过独立 U 盘扫描；启动值名直接查询不依赖 Run 命令解析；超限记录不会被大量访问失败淹没。
- 规则大小边界：原版样本登记 85,504 字节；其余 14 条公开 SHA-256 在现有资料中未登记可核实大小，改为仅提示复核，不自动隔离。无害测试规则提供明确大小来验证完整处置路径。没有为满足测试而猜造真实样本大小。

## 全局硬性约束 1–7 提交前自查

| 约束 | 状态 | 代码与测试证据 |
|---|---|---|
| 1. 非空 U+FFFF 不得删除 | 已遵守（数据保护；顺序冲突按任务 4 处理） | [src/enhanced_engine.hpp:456](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/enhanced_engine.hpp#L456)；P0-4 新用户文件出现拒绝删除测试；未使用递归删除调用 |
| 2. 自动隔离只接受登记大小 + SHA-256 或原版精确 cmd 诱饵 | 已遵守 | [src/enhanced_engine.hpp:333](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/enhanced_engine.hpp#L333)、[src/enhanced_rules.hpp:38](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/enhanced_rules.hpp#L38)；伪造 confirmed 和缺少登记大小的回归测试 |
| 3. 恢复跳过顶层程序、拒绝嵌套可疑入口、重名保留及过期拒绝 | 已遵守 | [src/enhanced_engine.hpp:413](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/enhanced_engine.hpp#L413)；原有恢复回归用例 + P0-4 嵌套拒绝测试 |
| 4. 备份失败不继续删，删除失败恢复原属性 | 已遵守 | [src/engine.hpp:147](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/engine.hpp#L147)；该函数与审读基线逐字一致；原有备份校验/源文件保留测试；新增注册表备份写失败保留原值测试 |
| 5. 有界扫描、跳过规则与可查看限制 | 已遵守 | [src/enhanced_engine.hpp:202](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/enhanced_engine.hpp#L202)、[src/enhanced_engine.hpp:217](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/enhanced_engine.hpp#L217)、[src/ui_results.hpp:27](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/ui_results.hpp#L27)；主机预算耗尽不占用 U 盘预算，超限在多条访问失败后仍显示 |
| 6. 不重新公开样本/链接/密码 | 已遵守 | 仅保留原指纹的 samples/README.md 与已撤样本的 SECURITY.md 原文；当前受控文件无旧样本下载链接；发布包按白名单组成并逐项检查 |
| 7. 验收状态、实际范围与谨慎措辞 | 已遵守 | [src/ui_results.hpp:10](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/ui_results.hpp#L10)、[src/enhanced_engine.hpp:236](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/enhanced_engine.hpp#L236)、[src/enhanced_rules.hpp:42](https://github.com/BedtimeEnforcer/usb-recovery-enhanced/blob/main/src/enhanced_rules.hpp#L42)；README 保留尚未验收声明 |

## 明确未完成的验收

**尚未进行加强版虚拟机真实感染验收。** 没有验证真实变种、看门狗持续复活、内存注入、全部计划任务/服务或网络侧清理。不能据此宣称已经完整清除 Phorpiex/Twizt 或全部残留。

任务书中的冲突按全局硬性约束执行：仅 dat 文件名匹配不当作确诊；只有逐项人工同意并重新校验后才处理候选。配套静态分析报告未提供，未声称对其未提供的内容进行了独立复核。

## 任务书顺序冲突的执行解释

全局条款 1 写了先恢复用户文件、再删病毒；任务 4 同时要求未隔离已确认项时拦截恢复。这两个字面顺序相互冲突。本次采用任务 4 的强制门禁：**先结束精确匹配进程并校验备份隔离确认项，再恢复用户文件，最后仅在再次校验为空并单独确认后删除空容器**。

这一解释保持“不删除非空 U+FFFF 容器”和“防止传播源未处理时恢复”的共同数据保护目的；没有把两个互斥顺序说成同时满足。
