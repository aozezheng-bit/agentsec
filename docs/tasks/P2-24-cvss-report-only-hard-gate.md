# P2-24：CVSS Report-only Hard Gate

- 状态：已完成（源码开发）
- 日期：2026-08-24
- 依赖：P2-17、P2-18、P2-20、P2-21、P2-22、P2-23

## 完成标准

- [x] 使用 CVSS `effective_score` 评估 Gate；
- [x] 支持 High `>= 7.0`；
- [x] 支持 Critical `>= 9.0`；
- [x] Critical 只报告最强匹配，不重复生成 High；
- [x] 增加 `CvssHardGateMatch`；
- [x] 增加 `CvssHardGateAssessment`；
- [x] 增加 `Finding.cvss_hard_gate`；
- [x] 增加 `Assessment Summary.cvss_hard_gate_matches`；
- [x] 增加 Text/JSON 报告展示；
- [x] `agentsec scan` 在 CVSS enrichment 后自动评估；
- [x] 保持 AgentSec score / Severity / generic hard_gate 独立；
- [x] 保持 report-only，不改变 CLI 退出码；
- [x] 增加 Schema、测试和 ADR。

## 不在本任务范围

```text
CVSS CI Blocking
--fail-on
生产 Hard Gate enforcement
策略文件、豁免、审批
运行时漏洞验证
实际可利用性证明
```
