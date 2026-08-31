# P2-20：Technical Score（Agentic Risk Track）

- 状态：完成
- 日期：2026-08-24
- 依赖：P2-17、P2-18、P2-19

> 说明：仓库历史中已有一个同名 P2-20：CVSS v4.0 Local Base Calculator。
> 本任务是原始 Phase 2 评分路线中的 Agentic Technical Score，使用独立的
> `TECHNICAL_SCORE_MODEL_VERSION=0.1.0`，不修改既有 CVSS Adapter。

## 目标

将 P2-18 Agentic Factor Vector、P2-19 Threat/Mitigation Vector 以及可选的
CVSS Base Assessment 转换成一个具有完整中间值和证据边界的 Technical Score。

## 公式

```text
contribution_i = round_1(10 × factor_value_i × weight_i × mitigation_multiplier_i)
agentic_score = round_1(sum(contribution_i))
technical_score = round_1(max(agentic_score, cvss_base_score))
```

没有 CVSS Base 时，Technical Score 等于 Agentic Score。

权重是版本化 AgentSec Policy，不是 NIST/CVSS 标准权重。CVSS Base 只作为独立
High-Water Mark，不与 Agentic Score 求平均。

## 产出

```text
src/agentsec/risk/technical_score.py
src/agentsec/risk/__init__.py
src/agentsec/versioning.py
tests/test_technical_score.py
docs/decisions/0050-agentic-technical-score.md
```

## 输出

格式：

```text
agentsec-technical-score / 0.1.0
```

输出包括：

- Agentic Score；
- 可选 CVSS Base Score；
- Technical Score；
- Severity；
- 十项 Factor Contribution；
- Weight；
- Mitigation multiplier；
- Threat State；
- Mitigation State；
- Confidence counts；
- Manifest SHA-256；
- Model Versions；
- Mapping Basis。

## 验收标准

- [x] 十项 Factor 都产生可审计 Contribution；
- [x] 权重总和为 1.0；
- [x] Factor Value 和 Mitigation multiplier 进入公式；
- [x] CVSS Base 可选并作为 High-Water Mark；
- [x] CVSS 不与 Agentic Score 平均；
- [x] Score 和 Severity 可重复；
- [x] Factor/Threat Manifest Hash 绑定；
- [x] JSON 输出不包含原始 Source Value；
- [x] Unknown 不被当作安全或有效降分；
- [x] 不修改现有 Finding、CVSS Adapter、Hard Gate 或 CI 行为。

## 未包含内容

```text
P2-21 Drift Score
P2-22 Governance Score
P2-23 Overall Score / Hard Gate
P2-24 Scoring Replay
```
