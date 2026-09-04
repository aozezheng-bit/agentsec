# RISK-05：Context Risk Quantification

- **日期**：2026-09-03
- **状态**：本地实现完成；Homi 端发布仍需单独审批
- **前置任务**：RISK-01 Operation Context、RISK-02 Evidence State、RISK-03 Context Extraction、RISK-04 Context-aware Rules

## 目标

RISK-05 将 RISK-04 的上下文风险 Finding 转换为可审计的量化结果，同时严格区分：

1. **Potential Impact**：如果该风险模式真实发生，静态上下文所表达的潜在影响；
2. **Residual Risk**：结合显式授权和控制覆盖后的保守剩余风险；
3. **Current Posture**：当前运行时暴露是否被证明；
4. **Risk Drift**：相对显式基线的风险上升或下降。

RISK-05 不把能力数量、人格、长期记忆、公开网页读取或网络能力本身作为高风险输入。

## 量化口径

### 1. Potential Impact

对每一个 RISK-04 风险 Finding：

```text
risk_level = NIST likelihood × impact matrix
potential_finding_score = AgentSec representative(risk_level)

potential_impact_score = max(potential_finding_score)
```

沿用既有映射：

| NIST 风险级别 | AgentSec 代表分 |
|---|---:|
| Very Low | 0.0 |
| Low | 2.0 |
| Moderate | 5.5 |
| High | 8.0 |
| Very High | 9.5 |

采用 high-water mark，不对多个风险进行平均，避免严重 Finding 被低风险项稀释。

RISK-04 的 `coverage` Finding 不参与 Potential Impact 计算。

### 2. Residual Risk

Residual Risk 只允许由 Operation Context 中明确存在的授权和控制进行有限调整。控制覆盖分为：

| 控制覆盖 | 条件 | 系数 |
|---|---|---:|
| `none` | 没有明确的授权或有效控制 | 1.00 |
| `partial` | 至少存在一个明确控制或授权 | 0.85 |
| `strong` | 存在明确授权，且至少有三个有效控制 | 0.70 |

```text
residual_finding_score
= round(potential_finding_score × control_factor, 2)

residual_risk_score
= max(residual_finding_score)
```

这里的系数是 AgentSec 当前的确定性策略参数，不是 NIST、CVSS 或损失概率公式。后续必须使用真实评审数据继续校准，不能将其对外解释为发生概率或金额损失。

使用 high-water mark 的原因是：一个严重且缺少控制的 Finding 不能因为其他 Finding 控制良好而被平均掩盖。

### 3. Current Posture

静态 Operation Context 不证明 Tool、OAuth、Permission、Scheduler 或操作可达性，因此：

- 有静态风险 Finding 时，默认 `latent_unverified`；
- 没有风险 Finding 时，默认 `not_established`；
- `current_posture_score` 在静态输入下始终为 `null`；
- 只有未来独立的 Runtime Attestation 合约，才可以引入 `runtime_attested`。

RISK-05 不通过默认值伪造运行时态势分。

### 4. Risk Drift

只有同时提供当前和基线的 `OperationContextSet + ContextRiskReport`，才计算 Drift：

- 新增风险 Finding：`added_finding_ids`；
- 基线存在、当前消失的风险 Finding：`resolved_finding_ids`；
- 新增、删除或修改的操作上下文分别记录；
- 当前残余风险高于基线或新增 Finding 时，方向为 `increased`；
- 风险 Finding 消失且残余风险下降时，方向为 `decreased`；
- 只有上下文变化但无法确认风险方向时，方向为 `unknown`；
- 没有变化时，方向为 `unchanged`。

当前策略的上升漂移分为：

```text
drift_score = min(
  10.0,
  max(0, current_residual - baseline_residual)
  + 1.5 × added_finding_count
  + 0.75 × upward_modified_context_count
  + 0.25 × added_context_count
)
```

风险下降不会被计为正向风险漂移；下降信息保留在 `direction` 和 `resolved_finding_ids` 中。

没有基线时，`drift` 和 `drift_score` 为 `null`，不是 0 分。

## 产物

新增：

```text
homi-risk-score.json
schemas/risk/context-risk-score.schema.json
```

`homi-risk-score.json` 同时绑定：

- `homi-operation-context.json` 的规范化 SHA-256；
- `homi-context-risk.json` 的规范化 SHA-256。

Bundle 会拒绝拼接来源不一致的风险评分 Sidecar。

## CLI 使用

```bash
agentsec homi report /path/to/homi-workspace \
  --output-dir /tmp/agentsec-homi-report \
  --language zh \
  --force
```

将生成 `homi-risk-score.json`。

需要比较变更前后的风险漂移时，先保留上一轮报告目录，再传入：

```bash
agentsec homi report /path/to/homi-workspace \
  --output-dir /tmp/agentsec-homi-report-current \
  --baseline-dir /tmp/agentsec-homi-report-baseline \
  --language zh \
  --force
```

`--baseline-dir` 必须包含同一版本生成的 `homi-operation-context.json` 和
`homi-context-risk.json`。缺少显式基线时，风险漂移为 `null`，不会被误报为 0。

```bash
agentsec homi bundle \
  --pilot /tmp/agentsec-homi-report/homi-pilot-report.json \
  --format html \
  --language zh \
  --output /tmp/agentsec-homi-report/homi-security-report.html \
  --force
```

联合 HTML 增加“风险量化 / Risk Quantification”区块，展示：

- 潜在影响分；
- 残余风险分；
- 当前态势；
- 风险漂移；
- 当前态势分为空的原因。

## 安全边界

- 所有结果为 report-only；
- `runtime_verified=false`；
- `policy_authority=false`；
- `ci_blocked=false`；
- 不修改 Agent 文件；
- 不改变 RISK-04 Finding；
- 不调用 LLM；
- 不执行扫描目标代码、Hook、Skill、MCP 或 Scheduler；
- 不把 Confidence 当作 Severity；
- 不将 Potential Impact 当作当前运行时暴露；
- 不使用能力数量或人格文本直接计算风险。

## 验证

RISK-05 测试覆盖：

- 公开网页读取得到 0 风险分；
- 严重敏感外传的 Potential/Residual 分；
- 显式控制带来的有限 Residual 调整；
- Coverage 不完整时保留 provisional 限制；
- 无基线时 Drift 为 `null`；
- 新增风险时 Drift 为 increased；
- 风险解除时 Drift 为 decreased 且不产生正向漂移分；
- 上下文和 RISK-04 SHA-256 绑定；
- authority 字段固定；
- Schema 可以导出。

## 后续校准

RISK-05 的控制系数和 Drift 参数需要使用人工标注、真实变更样本和运行时 Attestation 继续校准。校准不得改变以下原则：

1. 严重 Finding 不能被平均稀释；
2. Unknown 不能自动等于高风险或安全；
3. 静态证据不能伪造当前态势分；
4. LLM 不能进入评分、策略、Hard Gate 或 CI 决策链路。
