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
