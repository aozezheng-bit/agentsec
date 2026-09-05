# RISK-08：Homi Agent Snapshot、分层 Drift 与统一 Risk CLI

- 日期：2026-09-04
- 状态：本地实现完成；RISK-09/10 旧预期等待独立重校准；未提交、未发布
- 前置任务：RISK-01~05、RISK-06/07
- 决策：`docs/decisions/0120-unified-homi-risk-context-authority.md`

## 目标

统一 Risk CLI 必须审查操作语境和控制后风险，而不是把网络、人格、长期记忆或能力存在
直接当成高风险。RISK-03、RISK-04、RISK-05 构成权威静态风险链；旧 Homi 组合规则只保留
为声明信号。

## 已交付

### 1. Homi Agent Snapshot

```bash
agentsec homi snapshot create <workspace> --subject-id homi:agent:<immutable-id> --output baseline.json
agentsec homi snapshot verify --baseline baseline.json --subject-id homi:agent:<immutable-id> <workspace>
```

Snapshot 绑定六类文件、静态能力、人格信号、旧组合 Finding、Policy Observation、Coverage
和引擎版本。篡改失败关闭。Agent 身份由平台显式提供的稳定 `subject_id` 绑定；`project_name` 仅用于展示。

### 2. 分层 Drift

```bash
agentsec homi drift --baseline baseline.json --subject-id homi:agent:<immutable-id> <workspace>
```

分别输出文件、Capability、Persona、旧 Finding、Policy Observation、Coverage 和版本绑定变化。
这些层描述静态变化，不自动等价于风险上升。

### 3. 统一 Context-aware Risk

```bash
agentsec homi risk <workspace> --subject-id homi:agent:<immutable-id> --format json
```

执行链：

```text
Homi Pilot
  → RISK-03 Pilot-bound Operation Context
  → RISK-04 Context-aware Deterministic Rules
  → RISK-05 Potential / Residual / Posture
  → RISK-08 Unified Homi Risk Report
```

权威口径：

```text
risk_score = residual_risk_score
risk_level = residual_risk_level
risk_basis = operation_context_residual_risk
```

报告包含：

- Potential Impact；
- Residual Risk；
- Current Posture 与可空态势分；
- Evidence Confidence；
- Context、Risk Finding、Coverage Finding、Unknown 数量；
- Finding → Context → Evidence 绑定；
- 控制覆盖和每条 Finding 分数贡献；
- `declaration_signal_*` 旧组合信号，明确不参与权威风险分。

Operation Context 必须绑定同一 Pilot JSON。跨报告拼接直接拒绝。

### 4. Context Risk Drift

只有 Snapshot 不足以计算行为风险漂移。需要同时提供绑定的基线 Operation Context：

```bash
agentsec homi risk <workspace> \
  --subject-id homi:agent:<immutable-id> \
  --baseline baseline-snapshot.json \
  --baseline-context baseline-report/homi-operation-context.json \
  --format json
```

行为：

- Snapshot + Context Baseline 均有效：输出 RISK-05 Drift Score 和方向；
- 只有 Snapshot：仍输出文件/Capability/Persona 层变化，但 `drift_risk_score=null`；
- 无基线：`drift_status=not_established`、`drift_risk_score=null`；
- 身份不匹配：不计算跨 Agent 风险漂移。

风险下降不会被包装成正向风险上升。Unknown 和 Coverage Gap 不自动等于高风险或安全通过。

### 5. 合同与接线

- `HOMI_RISK_REPORT_VERSION = 0.5.0`；
- `schemas/risk/homi-risk-report.schema.json`；
- Python API：`HomiRiskFindingSummary`、`HomiRiskReport`、`build_homi_risk_report`；
- Homi Skill：`commands/snapshot.sh`、`commands/drift.sh`、`commands/risk.sh`；
- 全部输出固定 report-only，不授予权限、不认证身份、不阻断 CI。

## 验证

RISK-08 专属测试覆盖：

- 默认模板不产生上下文风险；
- 控制文件自修改产生 RISK-04 Finding 和 RISK-05 分数；
- 旧组合分只进入 declaration signal；
- Potential、Residual、Posture、Confidence 独立；
- Pilot/Operation Context 错误绑定失败关闭；
- 基线 Context Drift 与无 Context Baseline 的 null 语义；
- JSON Schema 与 Authority 常量。

RISK-09/10 仍包含旧 `HOMI-COMB-*` 分数预期。它们不是 RISK-08 失败，而是后续语料和验收
真值需要按新版权威口径重新标注；本任务不静默改写其真值。

## 安全边界

- 不执行 Workspace 代码、Hook、Skill、MCP、Tool、Scheduler 或命令；
- 不调用 LLM；
- 不输出 Secret、Credential、用户原文、URL 或 IP；
- 静态证据不产生 Runtime Attestation；
- Severity 与 Evidence Confidence 分离；
- Critical Finding 不通过平均被稀释；
- 所有结果固定 `report_only=true`、`runtime_verified=false`、`ci_blocked=false`。

## RISK-08B Snapshot Risk Evidence Binding

Current Snapshot `0.3.0` additionally covers RISK-03 Operation Context, RISK-04
Context Finding, and RISK-05 Context Score summaries plus their canonical
SHA-256 bindings. Layered Drift `0.4.0` reports Operation Context, Context
Finding, and Context Score changes. Unified Risk `0.5.0` verifies baseline
Context/Risk/Score digests before calculating Risk Drift. Details:
`docs/tasks/RISK-08B-snapshot-context-summary.md`.
