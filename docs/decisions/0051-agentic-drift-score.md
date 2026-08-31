# ADR-0051：Agentic Capability Drift Score 0.1.0

- Status: Accepted
- Date: 2026-08-24
- Task: P2-21（Agentic Risk Track）
- Drift Score Model: `0.1.0`
- Capability Diff Schema: `0.1.0`
- Technical Score Model: `0.1.0`

## Context

P2-13 已提供 Capability Diff 和 Change Impact。Technical Score 表达当前静态能力
暴露，Drift Score 需要表达相对可信基线的变化风险。变化风险不能只按文件修改数量
计算，还需要保留：

```text
变化维度
变化类型
变化字段
变化来源
审批状态
部署范围
Baseline Trust
Coverage 完整性
```

Phase 2 当前没有签名 Baseline、统一审批系统或运行时部署证明，因此这些上下文必须
显式输入，不能由扫描器猜测。

## Decision

### 1. Change contribution

Capability Diff 的每项变化按照以下 AgentSec policy points 计算：

| Dimension | Base points |
|---|---:|
| Tool | 1.5 |
| Permission | 2.5 |
| Control | 2.0 |
| Runtime Identity | 2.5 |
| Relationship | 1.5 |
| Unknown | 1.5 |

Change type multiplier：

```text
added    = 1.0
modified = 0.8
removed  = 0.0
```

敏感字段（effect、action、scope、resource、state、availability、side_effects、
environment、privileged、authentication、target、kind）使用 `1.0` 字段系数；
无法判断具体影响的普通 modified 字段使用 `0.5`。

### 2. Direction

如果存在 P2-13 Change Impact Report，优先使用其 direction：

```text
increased_exposure → increased
reduced_exposure   → decreased
neutral            → decreased
mixed/uncertain    → uncertain
```

没有 Impact Report 时的保守默认：

- 新增 Permission/Tool/Runtime Identity/Relationship：`increased`；
- 新增 Control/Unknown：`uncertain`；
- 删除 Control：`increased`；
- 其他删除：`decreased`；
- 所有无法判断方向的 Modified：`uncertain`。

### 3. Gross Change Score

```text
contribution
= round_1(
    dimension_points
    × change_type_multiplier
    × field_multiplier
    × direction_multiplier
  )

direction_multiplier:
  increased = 1.0
  uncertain = 0.6
  decreased = 0.0

gross_change_score
= min(10.0, sum(contributions) + profile_change_score)
```

Coverage Profile 变为 `incomplete` 时增加 3.0 Profile Score；其他 Profile Change
增加 0.5。

### 4. Context multipliers

上下文只允许有限调整，不得把技术变化抹掉：

| Context | Values |
|---|---|
| Change Source | unknown 1.0；local/release/CI 0.95；reviewed 0.9；external 1.0 |
| Approval | unknown/rejected/expired 1.0；not_required 0.95；approved 0.9 |
| Deployment | unknown/production/external 1.0；staging 0.8；development/test 0.6；local 0.5 |
| Baseline Trust | unknown 1.0；hash_only 0.95；signed_attested 0.9 |

```text
context_multiplier = source × approval × deployment × baseline
```

`approved` 必须提供有界 `approval_reference`。审批只表示治理上下文，不证明运行时
权限已收敛。

### 5. Final Drift Score

```text
drift_score
= max(
    round_1(gross_change_score × context_multiplier),
    5.0 if Coverage is incomplete else 0.0
  )
```

不完整 Coverage 不能产生干净的低分结果。

## Security boundaries

- Drift Score 是 AgentSec policy metric，不是 NIST/CVSS 原生公式；
- 不复制 Capability Before/After 原始值；
- 只保留 Source Locator、Field、Line 和 Source SHA-256；
- 不执行扫描项目、脚本、Skill、Hook、MCP 或命令；
- 不访问运行时 Tool/OAuth/Permission；
- 审批、部署范围和 Baseline Trust 不等于 Runtime Attestation；
- Drift Score 不启用 Hard Gate 或 CI Blocking；
- Critical Finding 仍由独立 Hard Gate 保护，不能由 Drift 平均分稀释。

## Consequences

### Positive

- 变化数量、变化类型、变化维度和方向均可回溯；
- Control 新增不会被默认误判为风险增加；
- Control 删除会被保守识别为增加暴露；
- Unknown 和不完整 Coverage 不会被当成安全；
- 后续 Overall Score 可以独立消费 Drift Score。

### Limitations

- 未提供 Impact Report 时，Modified 变化的方向只能保守标记为 uncertain；
- 当前上下文需要调用方显式提供；
- 签名 Baseline 和真实审批系统尚未接入；
- Drift Score 尚未与最终 Overall Score、CI Policy 或 Hard Gate 集成。
