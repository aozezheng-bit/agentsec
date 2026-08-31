# P2-23：Overall Score 和 Hard Gate（Agentic Risk Track）

- 状态：完成
- 日期：2026-08-25
- 依赖：P2-15、P2-20、P2-21、P2-22

> 说明：本任务实现 Agentic Risk Track 的 Overall Score 和统一 Report-only Floor。
> 不修改已有 Phase 1 Finding Hard Gate、CVSS Report-only Gate、Capability Shadow Gate
> 或 P2-15B CI Policy 原型。

## 目标

统一 Technical、Drift 和 Governance Score，并用独立、不可稀释的 qualified
Hard Gate Floor 生成最终 Overall Score。

## 公式

```text
base_overall_score = max(technical, drift, governance)
hard_gate_floor = strongest qualified deterministic Gate floor
overall_score = max(base_overall_score, hard_gate_floor or 0.0)
```

## 产出

```text
src/agentsec/risk/overall_score.py
src/agentsec/risk/__init__.py
src/agentsec/versioning.py
tests/test_overall_score.py
docs/decisions/0053-agentic-overall-score-hard-gate.md
```

## Hard Gate 合同

```text
qualification = accepted
deterministic = true
confidence ∈ {A, B, C}
mode = report_only
blocks = false
```

`D` Confidence 和 LLM Evidence 不能设置 Overall Floor。

## 输出

格式：

```text
agentsec-overall-score / 0.1.0
```

包含：

- Technical Score；
- Drift Score；
- Governance Score；
- Base Overall Score；
- High-Water Source；
- Qualified Gate Matches；
- Strongest Floor；
- Overall Score；
- Severity；
- Model Versions；
- Manifest SHA-256；
- Mapping Basis。

## 验收标准

- [x] 三个 Component Score 使用 High-Water Mark，不求平均；
- [x] High/Critical Floor 独立应用；
- [x] 多 Gate 命中取最强 Floor；
- [x] D Confidence Gate 被拒绝；
- [x] Gate Qualification 必须是 accepted；
- [x] 重复 Gate ID 被拒绝；
- [x] Technical/Drift/Governance Manifest 和 Agent 绑定；
- [x] Overall Score 与 Severity 一致；
- [x] JSON 输出不包含原始 Source Value；
- [x] `blocks=false`，不修改 CLI 退出行为。

## 未包含内容

```text
P2-24 Scoring Replay
P2-26 --fail-on
P2-27 Organization Policy
P2-28 Waiver Enforcement
生产 CI Blocking
```
