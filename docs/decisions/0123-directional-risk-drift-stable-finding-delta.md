# ADR-0123：Directional Risk Drift 与 Stable Finding Delta

- 日期：2026-09-04
- 状态：Accepted（本地候选；未提交、未发布）
- 任务：RISK-08C

## 背景

旧 Drift 存在两个量化缺陷：

1. Homi Finding Delta 使用 `rule_id` 构建 Map，同一规则命中多个目标时后项覆盖前项；
2. RISK-05 对所有 Modified/Added Operation Context 加固定正分，导致无风险文案或 Evidence
   变化也产生 `drift_risk_score=0.75`。

该行为把“发生变化”错误等同于“风险上升”，不符合 AgentSec 按操作目的、影响和控制判断
风险的原则。

## 决策

### 1. Finding Delta 身份

Homi Finding Delta 必须使用稳定 `finding_id`，`rule_id` 仅作为分类字段。

```text
before[finding_id] ↔ after[finding_id]
```

生命周期：

```text
added
increased
changed
unchanged
decreased
resolved
```

同一 Rule 的多个 Finding 必须全部保留。

### 2. Context Finding 语义关联

RISK-05 使用以下语义键关联前后 Finding：

```text
(rule_id, context_ids)
```

原因：Evidence 变化可能改变 Finding ID，但同一 Rule 和 Operation Context 仍表达同一风险
模式。关联后比较 Residual Risk：

- 当前键新增 → `added_finding_ids`；
- 相同键分数上升 → `increased_finding_ids`；
- 相同键分数下降 → `decreased_finding_ids`；
- 基线键消失 → `resolved_finding_ids`；
- 分数不变但 Evidence/Finding ID 变化 → `non_directional_finding_ids`。

### 3. 正向 Drift Score

只有下列证据产生正向 Drift Score：

```text
max(0, residual_risk_delta)
+ 1.50 × added_finding_count
+ 1.00 × increased_finding_count
+ 0.75 × risk-relevant control_weakening_count
+ 0.25 × risky_added_context_count
```

上限 10.0，使用 High-water Mark 风险口径，不通过平均稀释严重 Finding。RISK-09A
回放校准进一步增加约束：正向 Drift Score 不得超过当前 Residual Risk Score，避免新增
Finding 的解释性加项把 High 当前风险错误放大成 Critical 漂移风险。

`risky_added_context_count` 仅统计被 Risk Finding 引用的新增 Context。普通公开读取、人格、
文案或无风险 Context 新增不加分。

### 4. 控制变化

只在 Risk Finding 引用的 Operation Context 上统计控制变化：

- `present → absent/unknown`：Control Weakening；
- `absent/unknown → present`：Control Strengthening；
- Authorization 从确认/Policy Allowed/Approval Required 降为 Unknown/Missing：Weakening；
- 反向变化：Strengthening。

### 5. Direction

优先级：

```text
新增/上升风险或控制削弱 → increased
否则风险下降/解除或控制增强 → decreased
否则只有 Context/Evidence 非方向变化 → unknown
否则 → unchanged
```

`decreased`、`resolved`、`unknown` 和 `unchanged` 的正向 Drift Score 均为 0。

## 输出

RISK-05、Homi Drift 和 Unified Risk 增加：

```text
risk_direction / direction
increased_finding_ids
decreased_finding_ids
resolved_finding_ids
control_weakening_count
control_strengthening_count
```

RISK-05 额外保留：

```text
added_finding_ids
non_directional_finding_ids
risky_added_context_ids
```

## 安全边界

- Direction 是确定性静态风险变化，不是运行时攻击证明；
- Unknown 不等于高风险或安全；
- Risk decrease 不抵消其他新增高风险 Finding；
- LLM 不参与 Direction、Score、Policy 或 CI；
- 所有输出继续 report-only、runtime-unverified、non-blocking。

## 版本影响

```text
Context Risk Score Model/Report  0.1.0 → 0.2.0
Homi Drift Report                0.3.0 → 0.4.0
Homi Risk Report                 0.4.0 → 0.5.0
```
