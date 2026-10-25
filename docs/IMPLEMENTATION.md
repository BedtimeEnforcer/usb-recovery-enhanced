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
