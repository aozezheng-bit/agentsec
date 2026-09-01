# P3-20：Provider Evaluation Import / Semantic Gate Qualification

- **状态**：代码完成；真实 Provider Evaluation 仍取决于 P3-19 Live Pilot
- **日期**：2026-09-01
- **依赖**：P3-18、P3-19
- **权限模式**：Shadow-only / report-only

## 目标

将 Provider Evaluation Report 或已完成的 P3-19 Pilot Report 绑定到当前 Semantic Gate
Candidate 和人工 Human Corpus，执行确定性的 Gate Qualification，并输出明确的
Report-only Promotion Evidence。

本任务解决的不是“让模型决定权限”，而是解决以下证据链完整性问题：

```text
Candidate Digest
  -> Human Corpus Digest
  -> Provider / Model / Prompt Contract
  -> Evaluation Report Digest
  -> Semantic Gate Qualification
  -> Report-only Promotion
```

## 已实现内容

### P3-20-01：Provider Evaluation Import Contract

实现：

```text
src/agentsec/semantic/evaluation_import.py
```

`SemanticGateEvaluationImport` 包含：

- Gate ID；
- Candidate ID；
- Corpus ID / Corpus SHA-256；
- Evaluation Report SHA-256；
- Provider ID / Model ID；
- Prompt Version；
- System Prompt SHA-256；
- Output Schema SHA-256；
- Prompt Contract SHA-256；
- Human Reviewer IDs；
- Evaluation Source；
- Semantic Evaluation Report；
- 固定 report-only / shadow-only 权限边界。

导入时拒绝：

- Case ID 集合与 Corpus 不一致；
- Corpus Digest 不一致；
- Evaluation Digest 不一致；
- Provider/Model 不一致；
- Prompt Contract 不是当前版本；
- Corpus 仍有 Draft、Unknown 或 Unresolved Case；
- Report 声明 Runtime、CI、Policy 或 Release 权限。

### P3-20-02：Evaluation / Candidate / Corpus Binding

`build_semantic_gate_evaluation_import()` 将当前 Candidate、41 Case Human Corpus 和
Evaluation Report 绑定为一个不可变 Import Artifact。

`build_import_from_pilot_report()` 只接受：

- `status=completed`；
- `live_invocation=true`；
- 存在 Evaluation Report；
- Pilot Gate、Corpus ID、Corpus Digest 与当前输入一致。

`preflight_blocked` 或失败 Pilot 不能被当成 Provider Evaluation 导入。

### P3-20-03：Semantic Gate Qualification Wiring

`qualify_semantic_gate_evaluation()` 将 Evaluation Import 转换为 P3-18
`QualityGateReport`，并接入：

- Provider quality；
- Human Corpus Coverage；
- Provider Promotion；
- Human Evidence Confidence；
- Candidate thresholds；
- P3-18 deterministic qualification runner。

输出：

```text
qualified
conditionally_qualified
not_qualified
```

### P3-20-04：Report-only Promotion Evidence

`SemanticGateReportOnlyPromotion` 和 `promote_report_only()` 只允许生成：

```text
promoted=true / report-only
```

或：

```text
promoted=false / not qualified
```

无论哪种结果，权限字段均固定为：

```json
{
  "report_only": true,
  "blocks": false,
  "can_block_ci": false,
  "can_publish_rule": false,
  "can_approve_waiver": false,
  "can_grant_runtime_authority": false
}
```

### P3-20-05：CLI

导入 Provider Evaluation：

```bash
PYTHONPATH=src .venv/bin/python \
  scripts/import-semantic-gate-evaluation.py \
  --candidate <candidate.json> \
  --human-corpus <human-corpus-final-41.json> \
  --evaluation-report <evaluation-report.json> \
  --output <evaluation-import.json>
```

导入已完成的 Pilot：

```bash
PYTHONPATH=src .venv/bin/python \
  scripts/import-semantic-gate-evaluation.py \
  --candidate <candidate.json> \
  --human-corpus <human-corpus-final-41.json> \
  --pilot-report <completed-pilot-report.json> \
  --output <evaluation-import.json>
```

执行 Qualification：

```bash
PYTHONPATH=src .venv/bin/python \
  scripts/run-semantic-gate-qualification.py \
  --candidate <candidate.json> \
  --human-corpus <human-corpus-final-41.json> \
  --evaluation-import <evaluation-import.json> \
  --provider-promotion <provider-promotion.json> \
  --evidence-confidence <evidence-confidence.json> \
  --format json \
  --output <qualification-report.json> \
  --promotion-output <report-only-promotion.json>
```

等价的顶层 CLI：

```bash
agentsec semantic gate-qualify \
  --candidate <candidate.json> \
  --human-corpus <human-corpus-final-41.json> \
  --evaluation-import <evaluation-import.json> \
  --provider-promotion <provider-promotion.json> \
  --evidence-confidence <evidence-confidence.json> \
  --format json \
  --output <qualification-report.json> \
  --promotion-output <report-only-promotion.json>
```

## 真实 Provider 关系

P3-19 的当前状态仍是：

```text
41 Case Corpus：覆盖完成
Pilot Preflight：完成
真实 Endpoint：未配置
Credential：未配置
Live Evaluation：待组织审批
```

因此 P3-20 已完成离线导入、绑定、Qualification 和 Promotion 链路，但当前不能
声称真实 Provider 质量已经合格。只有 P3-19 生成 `completed` 的真实 Pilot Report
后，才能导入真实 Evaluation 并得出真实指标。

## 验收标准

- Evaluation Import 的 Candidate/Corpus/Report Digest 可重算；
- Prompt Contract 绑定当前版本；
- 41 Case 集合完全一致；
- 非法旧报告、篡改报告、错误 Provider/Model 均 fail-closed；
- Qualification 不执行二次 Provider 调用；
- Qualification 不修改 Finding、Rule、Policy、CI、Waiver 或 Runtime；
- Report-only Promotion 永远不能阻断 CI；
- 离线回放结果确定性；
- Schema、Provenance、Candidate Artifact 均完成更新。

## 当前验证

```text
P3-20 tests：25 passed
P3-18 / P3-19 focused tests：45 passed
全量测试：1604 passed
Mypy：PASS
Ruff：PASS
Ruff format：PASS
```
