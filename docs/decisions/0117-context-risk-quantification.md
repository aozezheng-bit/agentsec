# ADR-0117：Context Risk Quantification

- **状态**：Accepted for AgentSec 0.4.x source development
- **日期**：2026-09-03
- **任务**：RISK-05

## 背景

RISK-04 已将静态 Agent 文件转换为带证据的 Operation Context 风险模式，但只有定性 Finding，不能直接支撑“潜在影响、剩余风险、风险变化”的统一报告。另一方面，静态声明不证明运行时权限或可达性，不能把静态潜在影响直接呈现为当前暴露。

## 决策

新增 `DeterministicContextRiskScoreEngine`，只接受：

- `OperationContextSet`；
- 与该 Context Set 绑定的 `ContextRiskReport`；
- 可选的、同样显式提供的基线 Context/Risk 报告。

### Potential Impact

沿用已有 NIST SP 800-30 likelihood-impact matrix 和 AgentSec 0～10 representative mapping，按 Finding 取 high-water mark，不做 Finding 间平均。

### Residual Risk

使用有限、透明、可回放的控制覆盖系数：

- none = 1.00；
- partial = 0.85；
- strong = 0.70。

系数是 AgentSec 当前 policy parameter，不宣称为 NIST/CVSS 原生公式、损失概率或实证频率。严重 Finding 仍按 high-water mark 聚合。

### Current Posture

静态输入默认 `latent_unverified`（有风险 Finding）或 `not_established`（无风险 Finding），`current_posture_score` 固定为 `null`。Runtime Attestation 未接入前，禁止声称当前态势分已经建立。

### Risk Drift

无显式基线时 Drift 为 `null`。有基线时记录新增/解决 Finding、上下文新增/删除/修改和残余风险变化。风险上升才产生正向 Drift Score，风险下降通过方向和解决列表表达。

## 安全边界

- RISK-05 仍然是 report-only；
- 不授予权限，不认证 Agent，不阻断 CI；
- 不执行目标代码、Hook、Skill、MCP 或 Scheduler；
- 不调用 LLM；
- 不把能力、人格、长期记忆、公开网页读取直接作为风险分；
- 不把 Potential Impact 当成当前运行时暴露；
- Unknown 是 provisional/coverage 状态，不自动升级为风险。

## 绑定与可追溯性

`ContextRiskScoreReport` 的 `source_context_sha256` 必须匹配 Operation Context，`source_risk_report_sha256` 必须匹配 RISK-04 报告的规范化内容。Homi Bundle 同时校验两个绑定，防止混合不同快照的 Sidecar。

## 备选方案

1. **沿用能力数量直接打分**：拒绝，无法表达操作目的和影响。
2. **把静态分数打折后当作当前暴露**：拒绝，混淆 potential impact 和 current posture。
3. **无基线时 Drift=0**：拒绝，0 容易被误读为没有变化证据；无基线应为 `null`。
4. **平均所有 Finding**：拒绝，会稀释 Critical/High 风险。
5. **让 LLM 直接决定分数**：拒绝，不可复现且越权。

## 后续影响

- 新增 `homi-risk-score.json` 和 `context-risk-score.schema.json`；
- RISK-05 的系数和 Drift 参数需要真实案例、人审和运行时证据继续校准；
- 后续 Runtime Attestation 可以在独立合约下扩展 `current_posture_score`，但不能通过修改静态输入伪造该字段。
