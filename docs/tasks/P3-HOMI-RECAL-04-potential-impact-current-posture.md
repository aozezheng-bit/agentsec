# P3-HOMI-RECAL-04：潜在影响分与当前安全态势分

- 日期：2026-09-03
- 状态：本地实现完成；Homi 端复核待发布审批
- 目标：修复“静态 Finding 的 8.0 被误读为 Agent 当前已经高危”的展示问题。

## 字段契约

| 字段 | 含义 | 静态 Homi 当前行为 |
|---|---|---|
| `potential_impact_score` | 根据现有 NIST likelihood × impact 矩阵和 AgentSec 0～10 映射得到的潜在影响 | 可以是 0～10，例如 8.0 |
| `raw_potential_impact_score` | 校准前所有原始组合 Finding 的最高潜在影响，保留审计参考 | 可以高于校准后分数 |
| `potential_impact_level` | 潜在影响的定性等级 | 由现有确定性风险映射产生 |
| `operationality` | `template` / `latent` / `active` / `runtime_attested` | 当前由 Operationality Sidecar 提供 |
| `current_posture` | 当前态势的证据状态 | 静态时为 `template_only`、`latent_unverified` 或 `active_unverified` |
| `current_posture_score` | 已确认的当前运行时暴露分 | 没有运行时证明时为 `null` |
| `runtime_verified` | 是否存在运行时证明 | 固定为 `false` |

## 设计原则

1. 不修改现有 Severity 和潜在影响映射；
2. 不用任意折扣系数把 8.0 “打折”为另一个未经依据的风险分；
3. 没有运行时 Attestation 时，不伪造当前安全态势分；
4. `null` 表示“当前态势尚未建立”，不是“安全”；
5. `active` 只说明静态声明明确，不等于真实权限已启用；
6. `runtime_attested` 才允许把潜在影响分复制为当前态势分；
7. Critical/High 潜在影响不因当前态势未验证而被静默删除，仍需报告并解释边界。

## 兼容性方案

为保证已冻结的 Homi Pilot `0.2.0` 报告和 P2 外部证据可以字节级回放，
本任务新增独立 Sidecar：

```text
homi-posture.json
```

该 Sidecar 绑定 `homi-pilot-report.json` 的 SHA-256，并携带每个组合 Finding
的潜在影响、Evidence Confidence、Operationality、当前态势和当前态势分。
因此旧报告无需重写，新的 Homi 报告目录仍然能够完整表达新口径。

`potential_impact_score` 采用校准后仍保留的 Finding 计算；
`raw_potential_impact_score` 单独保留原始扫描最高值。对于纯初始化模板，
模板校准可以使校准后分数为 `0.0`，同时不删除原始 Finding 的审计信息。

## 静态报告示例

```json
{
  "raw_potential_impact_score": 8.0,
  "potential_impact_score": 0.0,
  "current_posture": "not_established",
  "current_posture_score": null,
  "runtime_verified": false
}
```

这里展示的是报告级 Posture；具体 Finding 的 `operationality`、潜在影响等级和
证据可信度位于 `findings[]`。纯模板 Finding 被校准抑制后，报告级校准分为 `0.0`，
但 `raw_potential_impact_score` 仍保留为审计参考。

人类报告应解释为：

> 潜在影响较高，但当前只有静态证据；当前安全态势尚未建立，不能据此断言
> Agent 已经具备可达的高风险运行时能力。

## 本地验证

```text
Homi + 历史回放 + 指纹 + Operationality + Posture 定向测试：82 passed
```

P3-HOMI-RECAL-05 将基于该分层重新校准 `HOMI-COMB-003` 和
`HOMI-COMB-004` 的触发条件。
