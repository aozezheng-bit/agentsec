# P2-CAL-04A-HUMAN-SUBSET-02：HG-CAPCHAIN-001 Human Evidence 子集导入

- Task ID: `P2-CAL-04A-HUMAN-SUBSET-02`
- Status: Complete
- Date: 2026-08-24
- Gate: `HG-CAPCHAIN-001`
- Rule: `CAP-CHAIN-001`
- Scope: 40 条最小独立评审子集

## 1. 目标

在 Reviewer A、Reviewer B 完成 40 条独立评审，并由项目负责人完成 5 条
Correlation 差异裁决后，生成不覆盖原始评审的、可校验的 Gate-scoped Human
Evidence 产物。

本任务不把 40 条子集伪装成完整 431 条 P2-CAL-04 Corpus，也不修改已有的完整
Reviewer Pack Importer。

## 2. 输入

```text
calibration/p2-15a-capchain-40/package-manifest.json
calibration/p2-15a-capchain-40/selection.json
calibration/p2-15a-capchain-40/reviewer-a/labels.template.json
calibration/p2-15a-capchain-40/reviewer-a/reviewer-a-capchain-40-completed.json
calibration/p2-15a-capchain-40/reviewer-b/labels.template.json
calibration/p2-15a-capchain-40/reviewer-b/reviewer-b-capchain-40-completed.json
calibration/p2-15a-capchain-40/adjudication-decisions.json
```

`adjudication-decisions.json` 仅包含 5 条实际 A/B Correlation 分歧，最终均裁决为
`same_source`，并保留项目负责人的裁决说明。

## 3. 导入命令

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec

PYTHONPATH=src .venv/bin/python \
  scripts/import-capchain-review-subset.py
```

也可以显式指定路径：

```bash
PYTHONPATH=src .venv/bin/python \
  scripts/import-capchain-review-subset.py \
  --package-dir calibration/p2-15a-capchain-40 \
  --reviewer-a calibration/p2-15a-capchain-40/reviewer-a/reviewer-a-capchain-40-completed.json \
  --reviewer-b calibration/p2-15a-capchain-40/reviewer-b/reviewer-b-capchain-40-completed.json \
  --adjudications calibration/p2-15a-capchain-40/adjudication-decisions.json \
  --output-dir calibration/p2-15a-capchain-40/human-evidence
```

导入器具有以下安全行为：

- 校验 Package、Selection、Reviewer A/B 的 Pack/Corpus/Case/Source 绑定；
- 校验 Source SHA-256、Evidence Path 和行号范围；
- 只接受 40 条完整 `status=reviewed` 提交；
- 只接受恰好全部真实分歧的 Adjudication 输入；
- 不允许对 A/B 已一致的 Case 额外裁决；
- 不生成 TP/FP/FN/TN；
- 不执行 Fixture、脚本、Hook、Skill 或 MCP；
- 不调用 LLM 或网络；
- 输出采用非覆盖创建并设置为 `0600`；
- 输出 Boundary 明确保持 `gate_qualification=false` 和 `ci_blocking=false`。

## 4. 产物

输出目录：

```text
calibration/p2-15a-capchain-40/human-evidence/
```

### 4.1 Human Adjudications

```text
human-capchain-40-adjudications.json
```

包含：

- A/B 比较摘要；
- 六个结构化字段的逐字段一致性；
- 5 条项目负责人裁决；
- 原始 Reviewer ID 和 Evidence 绑定；
- 裁决后的 Correlation 和 Rationale Code。

### 4.2 Human Confidence

```text
human-capchain-40-confidence.json
```

包含：

- Reviewer A 的 40 条 Confidence/Correlation；
- Reviewer B 的 40 条 Confidence/Correlation；
- 裁决前后 Correlation 一致性；
- 最终 40 条 Confidence/Correlation 视图。

### 4.3 Human Resolutions

```text
human-capchain-40-resolutions.json
```

包含 40 条最终人工解析结果：

- `human_condition_label`；
- `observed_finding`；
- `category`；
- `confidence`；
- `correlation`；
- `disposition`；
- `evidence_locations`；
- `finding_summary`；
- `rationale_code`；
- `adjudication_required`；
- `adjudication_notes`。

`classification` 保持为 `null`，留给后续受信任的确定性评估 Runner 计算，避免人工直接填写
TP/FP/FN/TN。

## 5. 本次导入结果

```text
Cases: 40
Reviewer rows: 80
A/B agreed rows before adjudication: 35
Adjudicated rows: 5
Unresolved rows: 0
Match: 20
No-match: 20
Confidence agreement: 40/40
Correlation agreement before adjudication: 35/40
Correlation agreement after adjudication: 40/40
```

## 6. 当前边界

本任务完成的是 40 条子集的 Human Evidence Formalization，不等价于 Gate 已获得生产资格。

仍然保持：

```text
formal_human_evidence = true
Gate qualification = false
hard_gate = false
ci_blocking = false
runtime_capability_verified = false
LLM used = false
```

下一步应执行：

```text
P2-15A-QUAL-01：HG-CAPCHAIN-001 Gate Qualification Report
```

该阶段需要基于最终 40 条人审结果和确定性 Detector 输出计算：

- Precision；
- Recall；
- False Positive / False Negative；
- Evidence Confidence 校准；
- Coverage / Unknown 约束；
- Report-only Gate 资格结论。

即使资格报告通过，也不能自动开启 CI Blocking；CI Enforcement 仍需独立的
Policy-controlled P2-15B 任务。
