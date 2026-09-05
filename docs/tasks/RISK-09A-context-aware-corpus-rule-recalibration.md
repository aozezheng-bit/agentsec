# RISK-09A：Context-aware Corpus / Rule Recalibration

- 日期：2026-09-05
- 状态：本地实现完成；未提交、未推送、未重建 Candidate
- 前置任务：RISK-03、RISK-04、RISK-05、RISK-08C、RISK-09
- 决策：`docs/decisions/0124-context-aware-corpus-rule-recalibration.md`

## 目标

将 RISK-09 固定语料从旧声明组合风险迁移到权威 Operation Context 风险链，补齐真实操作、
目的、影响和控制条件，避免因网络、人格或普通记忆能力直接判高风险。

## 已交付

### Operation Context

- `scenario-07`：识别完整对话记录、Personal Data、Indefinite Retention；
- `scenario-08`：识别 Scheduled Mailbox Read、Personal Data、Notification Purpose；
- `scenario-10`：识别 Autonomous External Send、Approval Missing；
- `scenario-12`：识别 Approval Policy Disable、Approval/Consent Control Absent。

### Context Rules

- `CTX-RISK-007`：个人/敏感数据无限期保留且缺少 Retention/Consent Control；
- `CTX-RISK-008`：外部 Send/Write 自主执行且缺少 Approval；
- `CTX-RISK-002`：个人数据定时操作保持 High，Secret/Credential 弱授权仍可 Critical；
- `CTX-RISK-003/006`：静态控制文件修改与审批移除校准为 High。

### Score 与 Drift

- 新增 Finding 的解释加项不再把 Drift Score 推高到当前 Residual Risk 以上；
- Benign Drift 保持 `0.0`；
- Risk decrease、resolved、unknown、unchanged 保持正向漂移 `0.0`。

## 固定回放结果

```text
scenario-07  CTX-RISK-007              8.0 high
scenario-08  CTX-RISK-002              8.0 high
scenario-10  CTX-RISK-008              5.5 medium
scenario-12  CTX-RISK-003/006          8.0 high
scenario-14  CTX-RISK-003/006          8.0 high
```

`scenario-01~06` 良性基线、文案、人格和非敏感偏好保持 `0.0`。`scenario-09` 仅公开网络
读取保持 `0.0`。

## 验收

```text
RISK-09 Replay                         16/16 passed
Operation Context / Rule / Score      34 passed
RISK-09 Replay + RISK-10 acceptance   15 passed, no xfail
Affected Homi / Context suites        195 passed
Affected-file Ruff / Mypy             passed
JSON contracts / git diff --check     passed
```

全量仓库回归：`1763 passed, 4 failed`。其中 3 个失败来自未重建的旧 Candidate
Source Inventory / Reconciliation Bundle；按当前“暂停 Candidate 重建”约束保留。另 1 个失败
位于并行未提交的 Capability Trust-root 修改，不属于 RISK-09A 写集。

## 边界

- `scenario-11/13` 仍是声明或 Coverage 观察，不在缺少操作链时制造 Risk Finding；
- 不证明邮箱、外发、记忆或控制文件能力在运行时存在；
- 不执行 Workspace，不调用 LLM，不阻断 CI。
