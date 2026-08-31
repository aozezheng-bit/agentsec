# P2-CAL-04A Pilot Review — 100 Questions

## 目标

这是一个 **Demo-first Pilot Review** 子集，用于尽快验证 Reviewer 能否理解
AgentSec 的规则、证据、Confidence 和 Correlation，并优先校准中文
Capability Drift Demo 的核心规则 `CAP-CHAIN-001`。

它不是正式 431 条 Reviewer Pack 的替代品，也不产生 P2-15A Hard Gate
资格结论。

## 选择结果

```text
总评审问题：100
CAP-CHAIN-001 Demo Track：44 条
其余 28 个 Rule：每个 1 条 match + 1 条 no_match，共 56 条
语言：English / 简体中文 / 双语
格式：Markdown / JSON / YAML / TOML / Manifest JSON
```

Demo Track 包含：

```text
CAP-CHAIN-001：20 条 Positive
CAP-CHAIN-001：20 条 Eligible Negative / Near-miss
CAP-CHAIN-001：4 条相关 Unknown 边界
```

其余 Rule 的 56 条只用于快速冒烟和理解，不足以单独完成正式统计校准。

## Reviewer 使用方式

Reviewer 不应直接阅读 Corpus `case.json`、`facts.json`、Gate Matrix 或任何
包含 Ground Truth 的文件。请使用正式 Pack 中对应 Reviewer 的盲评 Case：

```text
calibration/reviewer-pack/reviewer-a/
calibration/reviewer-pack/reviewer-b/
```

本目录的 `selection.json` 和 `selection.csv` 只有 opaque
`review_case_id`、Rule ID 和输入格式，不包含 expected outcome、Case kind、
Ground Truth、Gate 状态或期望 Confidence。

Reviewer A 使用：

```text
calibration/pilot-review-100/reviewer-a-labels.template.json
```

Reviewer B 使用：

```text
calibration/pilot-review-100/reviewer-b-labels.template.json
```

每一行只填写人工观察结果，不要自行填写 TP/FP/FN/TN。请至少完成：

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
status=reviewed
```

## 校验、进度报告和合并

在 Reviewer 评审过程中，可以随时检查当前 Pilot 进度：

```bash
PYTHONPATH=src .venv/bin/python scripts/pilot-review.py \
  --operation report \
  --reviewer reviewer-a \
  --format text
```

只做结构和绑定校验：

```bash
PYTHONPATH=src .venv/bin/python scripts/pilot-review.py \
  --operation validate \
  --reviewer reviewer-a
```

Pilot 完成后，可以生成一个新的、不会覆盖原文件的 431 行进度快照：

```bash
PYTHONPATH=src .venv/bin/python scripts/pilot-review.py \
  --operation merge \
  --reviewer reviewer-a \
  --output /safe/reviewer-a-full-progress.json
```

合并快照仍包含未完成的 431 条行，因此不能直接作为正式 P2-CAL-04
Human Evidence 输入。它只用于保留增量进度。

## Joint Expert Review Evidence（P2-15A-PILOT-01）

如果多位专家**共同评审**（而非独立盲评）得出一套共识结论，必须将其
形式化为 Joint Expert Review Evidence，不得存放在任一 Reviewer 的模板中
冒充独立证据。输入是在 Pilot 标签模板上增加 `joint_panel` 元数据块：

```bash
PYTHONPATH=src .venv/bin/python scripts/pilot-review.py \
  --operation import-joint-panel \
  --input calibration/pilot-review-100/joint-panel-pilot-input.json \
  --output calibration/pilot-review-100/joint-expert-evidence.json
```

导入会强制校验 Pack manifest 哈希、Selection 绑定和每行
corpus/question-set/case-fingerprint/source 哈希；Case、Corpus 或 Pack
任一变化都会拒绝导入。产物为 `agentsec-joint-expert-review-evidence`
（Schema 0.1.0），`qualification=pilot_only`：

```text
不是 Reviewer A/B Independent Evidence
不能计算 Reviewer Agreement / Cohen's Kappa
不能作为正式 P2-CAL-04 Human Evidence
不能用于 P2-15A Hard Gate 资格结论
```

当前已形式化的联合证据：`joint-expert-evidence.json`（expert-panel-001，
50 条，2026-08-24）。相应的 `reviewer-a-labels.template.json` 已复位为
全 pending 的干净盲评模板。

当 Reviewer A 和 Reviewer B 都完成 100 条后，可以生成仅包含字段分歧的
Pilot Comparison：

```bash
PYTHONPATH=src .venv/bin/python scripts/pilot-review.py \
  --operation compare \
  --reviewer-a /safe/reviewer-a-pilot.json \
  --reviewer-b /safe/reviewer-b-pilot.json \
  --format json
```

随后可以生成供人工 Adjudicator 使用的分歧模板：

```bash
PYTHONPATH=src .venv/bin/python scripts/pilot-review.py \
  --operation adjudication-template \
  --reviewer-a /safe/reviewer-a-pilot.json \
  --reviewer-b /safe/reviewer-b-pilot.json \
  --output /safe/pilot-adjudication-template.json
```

Comparison 和 Adjudication Template 只记录分歧字段，不复制 Reviewer 的原始
备注或隐藏答案，也不产生正式 AdjudicationResolutionSet。

## 重要边界

当前正式 `build-reviewer-pack.py validate/import` 仍按完整 431 条 Pack 校验。
因此 Pilot Template 不能直接作为正式 P2-CAL-04 Human Evidence 输入；它的
用途是：

1. 先完成 Demo Rule 的人工可理解性和规则语义校准；
2. 发现明显误报、漏报、证据定位或中文表达问题；
3. 决定是否值得继续投入完整 431 条 Review；
4. 后续再把 Pilot 结果合并回完整 Pack，或实现显式的 subset import。

Pilot Review 不会启用：

```text
hard_gate=true
CI Blocking
--fail-on
LLM authorization
runtime Tool/OAuth/Permission verification
```

## 继续补充策略

优先顺序建议：

```text
Pilot 100 → 修复规则/文档/证据问题 → 扩充到每个 Gate 的 20/20 reviewed
→ 完成 Reviewer A/B 全量或经批准的 subset import → Adjudication
→ 重新运行 P2-CAL-04 human mode → 再评估 P2-15A
```
