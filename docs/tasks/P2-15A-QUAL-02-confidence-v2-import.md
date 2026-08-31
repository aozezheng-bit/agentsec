# P2-15A-QUAL-02：Confidence v2 导入与 Qualification 重跑

- Task ID: `P2-15A-QUAL-02`
- Status: Complete
- Date: 2026-08-24
- Gate: `HG-CAPCHAIN-001`

## 1. 输入

```text
calibration/confidence-review-20/reviewer-a/reviewer-a-confidence-20-completed.json
calibration/confidence-review-20/reviewer-b/reviewer-b-confidence-20-completed.json
calibration/p2-15a-capchain-40/human-evidence/human-capchain-40-confidence.json
```

Reviewer A/B 均完成 20/20 条 Confidence-only 评审：

```text
Reviewer A：B=20
Reviewer B：B=20
Confidence Agreement：20/20
Cohen's Kappa：1.0
```

## 2. 导入命令

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec

PYTHONPATH=src .venv/bin/python \
  scripts/import-confidence-recalibration.py
```

导入器会：

- 校验两个 Reviewer 的 Package/Selection/Case 绑定；
- 只接受 `confidence`、`confidence_rationale`、`status` 的变更；
- 检查 20 条 Case 全部完成；
- 检查 Confidence A/B/C/D 合法性；
- 保留 Reviewer A/B 原始 v1 结果；
- 生成 v2 Confidence Evidence；
- 非覆盖写入并使用 `0600` 权限。

## 3. v2 产物

```text
calibration/p2-15a-capchain-40/human-evidence/human-capchain-40-confidence-v2.json
```

v2 产物：

```text
supersedes_artifact_id = human-capchain-40-confidence.json 的 Artifact ID
recalibrated_case_count = 20
retained_v1_case_count = 20
final Confidence 分布：A=20，B=20
```

其中：

- 20 条 Confidence-only Case 使用本轮独立复核的 `B`；
- 另外 20 条未参与本轮复核的 Case 保留 v1 结果；
- 原始 `human-capchain-40-confidence.json` 不修改。

## 4. Qualification 重跑

```bash
PYTHONPATH=src .venv/bin/python \
  scripts/qualify-capchain-subset.py \
  --confidence-path \
  calibration/p2-15a-capchain-40/human-evidence/human-capchain-40-confidence-v2.json \
  --output-json \
  calibration/p2-15a-capchain-40/human-evidence/hg-capchain-001-qualification-report-v2.json \
  --output-text \
  calibration/p2-15a-capchain-40/human-evidence/hg-capchain-001-qualification-report-v2.txt
```

## 5. Qualification 结果

```text
status = accepted
eligible_for_report_only_gate = true
```

| 指标 | 结果 |
|---|---:|
| TP | 20 |
| FP | 0 |
| FN | 0 |
| TN | 20 |
| Precision | 1.0 |
| Recall | 1.0 |
| F1 | 1.0 |
| Human vs Detector Confidence Agreement | 1.0 |
| Reviewer Confidence Kappa | 1.0 |
| Coverage complete | true |
| Relevant Unknown free | true |
| D Confidence | 0 |

## 6. 当前状态

本次结果允许进入 Report-only Gate 展示/集成，但不允许自动授权或 CI 阻断：

```text
formal_human_evidence = true
gate_qualification = accepted
eligible_for_report_only_gate = true
hard_gate = false
ci_blocking = false
fail_on = false
runtime_capability_verified = false
llm_used = false
```

下一步可以执行：

```text
P2-15A-PILOT-04：将 HG-CAPCHAIN-001 接入 Report-only Gate 展示和 Demo
```

或者进入独立的：

```text
P2-15B：Policy-controlled CI Enforcement 设计与实现
```

但在 P2-15B 完成前，不能启用生产 CI Blocking、`--fail-on` 或 `hard_gate=true`。
