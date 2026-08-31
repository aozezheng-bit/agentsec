# ADR-0053：Agentic Overall Score 和 Hard Gate 0.1.0

- Status: Accepted
- Date: 2026-08-25
- Task: P2-23（Agentic Risk Track）
- Overall Score Model: `0.1.0`
- Technical Score Model: `0.1.0`
- Drift Score Model: `0.1.0`
- Governance Score Model: `0.1.0`

## Context

P2-20、P2-21 和 P2-22 分别输出 Technical、Drift 和 Governance Risk。P2-23
需要产生一个最终 Overall Score，同时确保 Critical/High Hard Gate 不会被其他较低
分数平均稀释。

现有 Phase 1 Finding Hard Gate、CVSS Report-only Gate 和 Capability Shadow/Report-only
Gate 都有独立用途。P2-23 不修改这些既有合同，而是定义 Agentic Risk Track 的统一
Overall Score 和 qualified deterministic Gate floor 输入。

## Decision

### 1. Base Overall Score

Technical、Drift、Governance 不做平均：

```text
base_overall_score
= max(
    technical_score,
    drift_score,
    governance_score
  )
```

输出同时记录 High-Water 来源：

```text
technical
drift
governance
tie
```

### 2. Qualified Hard Gate match

只有满足以下要求的 Gate Match 才能设置 Overall Floor：

```text
Gate ID 合法
确定性来源
qualification = accepted
Evidence Confidence = A / B / C
Evidence ID 非空、稳定、可审计
report_only
blocks = false
```

`D` Confidence 不能设置 Overall Hard Gate Floor。LLM 不是允许的 Gate Source，不能
触发或授权 Hard Gate。

允许的 Gate Source：

```text
capability
cvss
policy
```

这里的 `policy` 仅表示确定性、版本化的 Policy Gate Evidence；不表示 P2-23 已经启用
CI Enforcement。

### 3. Strongest floor

```text
High floor     = 7.0
Critical floor = 9.0
```

多个 Gate 同时命中时取最强 Floor：

```text
hard_gate_floor = max(all matched floors)
```

### 4. Final Overall Score

```text
overall_score
= max(
    base_overall_score,
    hard_gate_floor_score or 0.0
  )
```

因此 Critical Gate 永远不能被 Technical、Drift 或 Governance 的较低分数稀释。

### 5. Enforcement boundary

P2-23 仍然：

```text
mode = report_only
blocks = false
```

P2-23 不修改 CLI 退出码，不直接驱动 `capability enforce`，不启用 `--fail-on`。
CI Policy Enforcement 仍需要显式 Policy、有效 Waiver、Coverage 和后续发布评审。

## Security boundaries

- 不执行扫描项目、脚本、Skill、Hook、MCP 或命令；
- 不访问运行时 Tool/OAuth/Permission；
- LLM 不能成为 Gate Authority；
- D Confidence 不能设置 Gate Floor；
- Governance 或 Approval 不能消除 Critical Floor；
- Gate Match 必须由调用方提供已验证、已 Qualification 的确定性证据；
- Overall Score 不声称 Runtime Exploitability；
- P2-23 不阻断 CI。

## Consequences

### Positive

- Technical、Drift、Governance 中任一高风险维度不会被平均稀释；
- Critical/High Floor 与数值聚合相互独立；
- Gate Source、Qualification、Confidence 和 Evidence 可审计；
- 后续 P2-24 可以对完整评分链路进行确定性回放；
- 后续 Policy Enforcement 可以消费 Overall Score，但不能反向修改评分结果。

### Limitations

- 当前 Gate Match 由可信调用方提供，尚未统一连接所有 Gate Registry；
- P2-23 不执行 Waiver 判断；
- P2-23 不启用 CI Blocking；
- Overall Score 与 Floor 需要在 P2-24、P2-30 和 P2-31 中继续校准与验证。
