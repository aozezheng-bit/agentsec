# RISK-08C：Directional Risk Drift / Stable Finding Delta

- 日期：2026-09-04
- 状态：本地实现完成；未提交、未推送、未重建 Candidate
- 前置任务：RISK-05、RISK-08A、RISK-08B
- 决策：`docs/decisions/0123-directional-risk-drift-stable-finding-delta.md`

## 目标

分离“内容发生变化”和“风险向上变化”。普通文案、人格、公开读取或 Evidence 重定位可以
产生 Drift，但不得自动增加风险分。

## 已交付

### Stable Finding Delta

`HomiDriftFindingDelta` 新增 `finding_id`，比较 Map 从：

```text
rule_id → Finding
```

改为：

```text
finding_id → Finding
```

同一 Rule 多次命中不会被覆盖。Delta 类型：

```text
added / increased / changed / unchanged / decreased / resolved
```

### Directional Context Risk Drift

新增：

```text
added_finding_ids
increased_finding_ids
decreased_finding_ids
resolved_finding_ids
non_directional_finding_ids
risky_added_context_ids
control_weakening_count
control_strengthening_count
```

正向 Drift Score 只消费新增/上升风险、风险相关控制削弱、Residual Risk 上升和被 Finding
引用的新增 Context。

### Homi Drift / Risk 输出

Homi Drift `0.4.0`：

```text
risk_direction
increased_finding_ids
decreased_finding_ids
resolved_finding_ids
control_weakening_count
control_strengthening_count
```

Unified Risk `0.5.0` 输出相同方向证据，并继续保留 Potential、Residual、Posture、Confidence
和 Snapshot/Context 绑定。

## 验收场景

- 相同 Finding ID 分数上升 → `increased`；
- 同一 Rule 两个 Finding，其中一个解除 → 两条 Delta 均保留；
- 无风险 Context 字段变化 → `direction=unknown`、`drift_score=0.0`；
- 风险解除 → `direction=decreased`、`drift_score=0.0`；
- 风险相关审批/控制削弱 → `direction=increased`；
- 无变化 → `direction=unchanged`、`drift_score=0.0`；
- scenario-03 文案变化不再产生 0.75 风险漂移。

## 边界

- RISK-08C 不补充 scheduled mailbox、autonomous send 或 approval-removal 识别规则；
- RISK-09/10 旧 `HOMI-COMB-*` 真值仍需 RISK-09A 重校准；
- 不执行 Workspace，不调用 LLM，不阻断 CI。

## 验证结果

```text
Homi + Context Score + Runtime Homi + Provenance/Versioning: 150 passed
RISK-08C core suites: 45 passed
Affected-module Mypy: passed
Affected-file Ruff check: passed
Affected-file Ruff format: passed
Context Score / Snapshot / Drift / Risk JSON contracts: valid
git diff --check: passed
```

RISK-09/10 回放从原先 7 个失败减少到 6 个：scenario-03 无风险文案变化已从
`drift_risk_score=0.75` 修复为 `0.0`。剩余失败属于 scheduled mailbox、autonomous send、
approval removal 和旧 `HOMI-COMB-*` 真值校准范围。
