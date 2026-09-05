# ADR-0124：Context-aware Corpus 与 Rule Recalibration

- 日期：2026-09-05
- 状态：Accepted（本地实现；未提交、未推送、未重建 Candidate）
- 任务：RISK-09A

## 背景

RISK-08C 将 Unified Risk 权威来源迁移到 Operation Context，但 RISK-09 固定语料仍以
`HOMI-COMB-*` 声明组合规则作为真值。结果出现两类问题：

1. 定时邮箱读取、自动外发、无限期保存完整对话和审批移除没有形成足够精确的 Operation
   Context；
2. 控制文件修改被静态声明直接放大为 `9.5 critical`，新增 Finding 的 Drift 加项又可能
   超过当前 Residual Risk。

旧组合规则可以保留为声明信号，但不能继续充当权威 Risk Finding。

## 决策

### 1. Operation Context 扩展

Homi 提取器新增或加强四类确定性上下文：

```text
homi.mailbox.scheduled-read
homi.external-message.send
homi.memory.persist
homi.approval-policy.disable
```

判定必须同时保留 Action、Target、Data、Trigger、Purpose、Authorization、Control 和静态
Evidence。能力、人格或普通长期记忆声明不能单独触发风险。

### 2. Rule Pack 0.2.0

新增：

```text
CTX-RISK-007  Unbounded Sensitive Retention
CTX-RISK-008  Autonomous External Side Effect
```

`CTX-RISK-007` 只匹配个人/敏感数据、无限期保留、缺少 Retention 与 Consent Control 的组合；
有界非敏感偏好仍为 0 分。

`CTX-RISK-008` 只匹配外部 Send/Write、Autonomous/Proactive/Scheduled Trigger、缺少明确审批
的组合；互联网读取和主动人格本身仍为 0 分。

### 3. Static Severity 校准

定时读取个人邮箱：`8.0 high`。静态声明没有 Runtime Attestation，不升级为 Critical。

控制文件修改或审批策略移除：`CTX-RISK-003` 与 `CTX-RISK-006` 共同解释，High-water Mark
为 `8.0 high`。生产系统或不可逆操作仍可达到 Critical。

自动外发但内容敏感度 Unknown：`5.5 medium`，同时保留 Coverage Unknown；若后续证明传输
Secret/Credential，可由 `CTX-RISK-001/004` 升级。

### 4. Drift Score 上界

RISK-08C 方向加项继续用于解释新增 Finding、控制削弱和风险上下文，但最终正向 Drift
Score 增加上界：

```text
drift_score <= current residual_risk_score
```

避免当前风险为 High 时，仅因“新增”解释项被放大成 Critical。

### 5. 语料真值迁移

RISK-09 `expectations.json` 从 `HOMI-COMB-*` 迁移到 `CTX-RISK-*`。声明组合分仍可展示，
但不参与权威 Risk Score 或验收真值。

## 安全边界

- 只读取和解析 Markdown，不执行 Workspace 内容；
- 不调用工具、Hook、Skill、MCP、Scheduler 或 LLM；
- Finding 不证明运行时可达性或实际执行；
- 输出保持 report-only、runtime-unverified、non-blocking；
- Unknown 保持 Coverage 状态，不自动计为高风险。

## 版本影响

```text
Homi Operation Context Output  0.1.0 → 0.2.0
Context Rule Pack              0.1.0 → 0.2.0
Context Risk Report            0.1.0 → 0.2.0
Context Risk Score Model       0.2.0 → 0.3.0
Context Risk Score Report      0.2.0 → 0.3.0
```
