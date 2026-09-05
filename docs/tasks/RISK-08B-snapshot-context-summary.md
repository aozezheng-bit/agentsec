# RISK-08B：Snapshot Context / Finding / Score Summary

- 日期：2026-09-04
- 状态：本地实现完成；未提交、未推送、未重建 Candidate
- 前置任务：RISK-03、RISK-04、RISK-05、RISK-08A
- 决策：`docs/decisions/0122-snapshot-context-risk-score-summary-binding.md`

## 目标

让 Homi Snapshot 同时表达：

```text
Agent 身份
+ Workspace 内容
+ 静态能力与人格
+ Operation Context
+ Context-aware Findings
+ Potential / Residual / Posture Score
```

## Snapshot 0.3 新增字段

```text
operation_context_sha256
context_risk_report_sha256
context_score_report_sha256
operation_contexts[]
context_findings[]
context_score
```

所有字段进入 `snapshot_digest`。修改 Context、Finding、Score 或其 Digest 后，如果未同步重算
Snapshot Digest，Decoder 拒绝。

## Operation Context 摘要

每条操作包含：

```text
operation_id
operation/action target
data classification/sharing/retention
trigger purpose authorization
reversibility scope frequency status
controls present/absent/unknown/not_applicable
evidence_ids
```

不保存 Evidence 原文、Source Path、URL、IP 或 Secret 值。

## Context Finding 摘要

每条 RISK-04 Finding 包含：

```text
finding_id / rule_id / kind / category
likelihood / impact / severity / confidence
context_ids / evidence_ids / rationale_code
```

Coverage Finding 也进入 Snapshot，避免 Coverage 状态变化丢失。

## Context Score 摘要

```text
model_version
coverage_complete
unknown_dimensions
potential_impact_score / level
residual_risk_score / level
current_posture / current_posture_score
contribution_count
```

`current_posture_score` 保持可空。静态输入不得伪造运行时态势分。

## 构建流程

```text
Homi Pilot
  → Pilot-bound Operation Context
  → RISK-04 deterministic replay
  → RISK-05 deterministic replay
  → value-minimized summaries
  → Snapshot canonical payload
  → snapshot_digest
```

CLI `snapshot create|verify`、`homi drift`、`homi risk` 自动执行该链。Python API 必须显式提供
`operation_context`，禁止创建不含上下文风险证据的新 Snapshot。

## Drift 输出

Snapshot Verification：

```text
operation_context_changes
context_findings_added
context_findings_removed
context_score_changed
```

Layered Drift：

```text
operation_context_changes
context_finding_changes
context_score_changed
```

Context Digest Match 也进入 `baseline_binding`。

## 安全边界

- 不执行扫描内容；
- 不调用 LLM；
- 不包含原始用户数据或 Secret；
- 不产生 Runtime Attestation；
- 不授权、不认证、不阻断；
- Evidence Confidence 与 Severity 分开保存；
- Critical Finding 不被平均稀释。

## 验证结果

```text
Homi / Runtime Homi targeted suite: 124 passed
Snapshot dedicated suite: 14 passed
Affected-module Mypy: passed
Affected-file Ruff check: passed
Affected-file Ruff format: passed
Snapshot / Drift / Risk / Skill Request JSON: valid
```

手工 Smoke Test：Baseline Snapshot `0.3.0` 成功包含 Operation Context、Coverage
Finding、Context Score 和三项 canonical digest；风险注入后 Snapshot Verification 与
Layered Drift 同时报告 Operation Context、Context Finding 和 Context Score 变化。

## 已知独立阻塞

RISK-09/10 仍有 7 个旧 `HOMI-COMB-*` 风险真值断言失败和 1 个既有 xfail，属于新版
Context-aware 风险语料重校准，不是 RISK-08B Snapshot 摘要接线失败。全量 Mypy 仍受
`src/agentsec/cli/capability.py:371` 的既有 `Path | None` 问题阻塞。
