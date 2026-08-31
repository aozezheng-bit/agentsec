# ADR-0050：Agentic Technical Score 0.1.0

- Status: Accepted
- Date: 2026-08-24
- Task: P2-20（Agentic Risk Track）
- Technical Score Model: `0.1.0`
- Agentic Factor Model: `0.1.0`
- Threat/Mitigation Model: `0.1.0`

## Context

P2-18 固定了十项 Agentic Factor，P2-19 固定了静态 Threat Signal 和保守的
Mitigation multiplier。P2-20 需要把这些中间结果转换为可回放的 Technical Score，
并保留所有中间值。

仓库中另有 CVSS v4.0 Local Base Calculator 也使用历史任务号 P2-20。为避免覆盖
已有 `CVSS_ADAPTER_VERSION=0.2.0` 和 CVSS Calculator 语义，本 ADR 将本任务显式
命名为 **P2-20 Agentic Risk Track Technical Score**，使用独立的
`TECHNICAL_SCORE_MODEL_VERSION=0.1.0`。

## Decision

### 1. Factor weights

权重是 AgentSec Policy，不是 NIST 或 CVSS 标准权重：

| Factor | Weight |
|---|---:|
| instruction_override | 0.05 |
| code_execution | 0.15 |
| secret_access | 0.15 |
| external_network | 0.15 |
| production_access | 0.15 |
| persistent_memory | 0.08 |
| subagent_delegation | 0.07 |
| external_identity | 0.07 |
| autonomous_action | 0.08 |
| approval_bypass | 0.05 |
| **Total** | **1.00** |

### 2. Factor contribution

每项贡献为：

```text
contribution_i
= round_1(10 × factor_value_i × weight_i × mitigation_multiplier_i)
```

其中：

```text
factor_value ∈ {0.0, 0.5, 1.0}
mitigation_multiplier ∈ [0.9, 1.0]
```

Evidence Confidence 不作为降分乘数。Unknown Factor 的 `0.5` 会保留为中间值，
并在 Confidence/Unknown 字段中显式报告。

### 3. Agentic Score

```text
agentic_score = round_1(sum(all factor contributions))
```

### 4. Optional CVSS high-water mark

如果提供已验证的 `CvssBaseAssessment`：

```text
technical_score = round_1(max(agentic_score, cvss_base_score))
```

不将 Agentic Score 与 CVSS Base Score 做平均，避免较高的 CVSS 或 Agentic 风险
被另一个较低分数稀释。

如果没有 CVSS：

```text
technical_score = agentic_score
```

### 5. Severity

Technical Score 只使用既有 AgentSec/CVSS qualitative severity 映射：

```text
0.0       → none
0.1–3.9   → low
4.0–6.9   → medium
7.0–8.9   → high
9.0–10.0  → critical
```

Technical Score 不替代 Finding Severity、Hard Gate 或 Evidence Confidence。

## Security boundaries

- Technical Score 不是 CVSS 标准计算公式；
- 静态 Mitigation Declaration 最多产生 0.9 multiplier；
- Unknown Threat 不得获得 Mitigation reduction；
- 不执行扫描项目、脚本、Skill、Hook、MCP 或命令；
- 不访问运行时 Tool/OAuth/Permission；
- LLM 不参与计算；
- Technical Score 不启用 CI Blocking；
- Critical Finding 的 Hard Gate 不能由 Technical Score 平均逻辑稀释。

## Consequences

### Positive

- 所有中间贡献可回溯；
- CVSS 作为独立高水位输入，不会被 Agentic Score 平均稀释；
- Factor、Threat、Mitigation、Confidence 和 Severity 保持独立；
- 后续 Drift、Governance、Overall Score 可消费稳定的 Technical Score。

### Limitations

- 权重需要在 P2-24 通过评分回放和试点数据校准；
- 当前未计算 Drift Score、Governance Score 和 Overall Score；
- Technical Score 不能证明运行时可达或实际可利用；
- 生产阻断仍由后续 Policy/Hard Gate 任务负责。
