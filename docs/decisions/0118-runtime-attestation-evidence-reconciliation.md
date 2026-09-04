# ADR-0118：Runtime Attestation / Evidence Reconciliation

- **状态**：Accepted for AgentSec 0.4.x source development
- **日期**：2026-09-04
- **任务**：RISK-06

## 背景

AgentSec 的 Homi 分析默认是静态、离线、report-only。静态声明可以帮助识别能力、操作上下文和潜在影响，但不能证明 Tool、OAuth、Permission、Scheduler 或具体操作在运行时可达。为了避免继续把静态潜在影响误读为当前态势，需要允许外部系统提交运行时观察，同时保持权限和策略边界不变。

## 决策

新增独立 Runtime Attestation 和 Evidence Reconciliation 合约：

1. 运行时证明只能由 Homi 沙箱、平台遥测或其他组织批准的外部系统生成；AgentSec 不执行目标 Agent，也不生成证明。
2. Attestation 作为不可信输入，必须具备严格格式、版本、确定性 ID、固定 Authority 和脱敏字段。
3. 运行时证据必须通过三重哈希绑定：
   - Homi Pilot Snapshot 的原始 JSON SHA-256；
   - Operation Context Set 的规范化 SHA-256；
   - RISK-04 Context Risk 报告的规范化 SHA-256。
4. 对账按照 operation ID、action、target 和 Finding context IDs 确定性完成，显式报告未观察、未声明和冲突。
5. 只有已验证且完全对账的证据可以获得 Evidence Confidence A；部分或冲突证据降为 B，未验证证据为 D。
6. Runtime Evidence 不改变风险 Finding、Severity、静态 Potential Impact、Policy、Hard Gate 或 CI 结果。
7. `report_only=true`、`policy_authority=false`、`ci_blocked=false` 为不可变安全边界。
8. Homi Bundle 以 sidecar 形式展示对账结果，不覆盖静态报告，也不把 Runtime Attestation 解释为身份认证或权限授予。

## 被拒绝的方案

### 让 AgentSec 自己执行被扫描 Agent

拒绝。会破坏静态扫描的安全边界，并把不可信 Workspace 内容带入命令、Hook、Skill、MCP 或 Scheduler 执行链路。

### 只看 `runtime_verified=true` 就提升 Confidence A

拒绝。外部输入仍可能来自错误快照、错误 Context 或伪造字段。必须通过 Snapshot/Context/RISK-04 三重绑定和完整对账。

### Runtime Attestation 直接更新静态 `homi-risk-score.json`

拒绝。静态报告和运行时证据的生命周期不同；原地覆盖会损失审计可追溯性并混淆 Potential Impact 与 Current Posture。运行时结果使用独立 sidecar。

### Runtime 观察直接授权或阻断 CI

拒绝。运行时证据是风险评估输入，不是权限系统、身份系统或策略控制面。若将来需要决策，必须新增独立、经过治理和人工批准的 Policy 合约。

## 后果

### 正面

- 可以在不执行目标内容的情况下接收外部运行时证据；
- 通过哈希绑定避免不同 Agent、不同 Context 和不同风险报告拼接；
- Confidence A 有明确、可审计的资格条件；
- `partial`、`conflict`、`unverified` 和 Unknown 不会被误报为“已验证安全”；
- Homi 能以 JSON/Markdown/HTML 展示运行时证据覆盖情况。

### 限制

- 仓库不包含真实 sandbox、telemetry 或 Attestation issuer；
- 没有 endpoint、凭据和组织审批时，只能做离线 fixture 和导入验证；
- Runtime Observation 只能证明已观察到脱敏的 operation 元数据，不能证明漏洞可利用或完整业务成功；
- 需要后续真实 Pilot 和人工校准验证外部系统的可信度、覆盖率和误报漏报。
