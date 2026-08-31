# P2-CAL-04A-HUMAN-SUBSET-01：HG-CAPCHAIN-001 40 条独立评审包

- Task ID: `P2-CAL-04A-HUMAN-SUBSET-01`
- Status: Reviewer package prepared; human review pending
- Date: 2026-08-24
- Gate: `HG-CAPCHAIN-001`
- Review rows per Reviewer: `40`
- Selection: `20 Positive + 20 Eligible Negative/Near-miss`
- Expected labels distributed: `false`
- Ground Truth distributed: `false`
- Joint Evidence distributed: `false`
- Formal Human Evidence: `false` until import and validation complete

## 1. Package location

```text
calibration/p2-15a-capchain-40/
```

Package ID:

```text
gate-review-package-sha256:4bebfb271060eab3b638e5d229d3e8fb6d0c1c8284f4daaab77b961372787997
```

Selection ID:

```text
gate-subset-selection-sha256:4ef30e1a30ca4e6d4c87b32f07328946e8fdef4034ca78e48f8aef203104b2ae
```

## 2. Distribution to Reviewers

只将以下内容分别发给对应专家：

Reviewer A：

```text
calibration/p2-15a-capchain-40/reviewer-a/
calibration/p2-15a-capchain-40/reviewer-instructions.md
```

Reviewer B：

```text
calibration/p2-15a-capchain-40/reviewer-b/
calibration/p2-15a-capchain-40/reviewer-instructions.md
```

不要将以下内容发给 Reviewer：

```text
calibration/corpus.json
calibration/gate-coverage-matrix.json
calibration/pilot-review-100/joint-expert-evidence.json
calibration/reviewer-pack/...
```

Reviewer 只能填写自己目录中的：

```text
labels.template.json
```

## 3. 包含内容

每位 Reviewer 收到：

```text
40 个 opaque Case
40 条 pending Review Row
中英文/双语 Case 展示
JSON、Manifest、YAML、TOML、Markdown 多种输入格式
Evidence Path 和行号信息
```

Reviewer 不会看到：

```text
Positive/Negative 逐 Case 标签
Ground Truth
Joint Expert 结论
Seed Confidence
```

## 4. 评审范围

规则条件为：

```text
execute + secret-access + external network
```

每条 Case 需要填写：

```text
human_condition_label
observed_finding
category
confidence
correlation
disposition
evidence_locations
finding_summary
rationale_code
review_notes
status=reviewed
```

两位 Reviewer 必须独立完成，不得共同讨论后填写，不得交换结果。

## 5. 当前边界

当前包只是独立评审数据包，不是正式 Human Evidence：

```text
不计算 Reviewer Agreement
不生成 Cohen's Kappa
不启用 hard_gate=true
不启用 --fail-on
不阻断 CI
```

评审完成后还需要：

```text
Subset Import
→ Human Confidence Set
→ Reviewer A/B Comparison
→ 仅对分歧进行 Adjudication
→ Gate-scoped Precision/Recall
→ HG-CAPCHAIN-001 资格报告
```

## 6. 重新生成

如果 Corpus 或 Reviewer Pack 发生变化，不能继续使用当前包。重新生成：

```bash
PYTHONPATH=src .venv/bin/python \\
  scripts/build-capchain-review-subset.py \\
  --output calibration/p2-15a-capchain-40
```

工具使用非覆盖写入；已有输出目录时会失败，以避免静默替换评审材料。
