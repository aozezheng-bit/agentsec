# Reviewer B 工作目录与评审计划

## 工作目录

```text
reviewer-b/
```

只使用本目录中的：

```text
labels.template.json
cases/<opaque-review-case-id>/case.json
cases/<opaque-review-case-id>/source.*
```

## 任务目标

独立完成 `HG-CAPCHAIN-001` 的 40 条评审：

```text
规则：CAP-CHAIN-001
条件：execute + secret-access + external network
数量：40 条
```

这 40 条整体包含 20 条 Positive 和 20 条 Eligible Negative/Near-miss，
但不会告诉你每一条的期望标签。

## 执行步骤

### 第 1 步：准备（约 5 分钟）

1. 阅读上级目录的 `reviewer-instructions.md`。
2. 确认只能访问本 Reviewer 目录。
3. 不要打开另一位 Reviewer 的目录、完整 Corpus、Coverage Matrix 或 Joint Evidence。

### 第 2 步：逐条评审（约 60～120 分钟）

对每个 `cases/<id>/case.json`：

1. 先阅读 `review_questions` 和 `condition`。
2. 再阅读同目录中的 `source.*` 原始展示内容。
3. 判断 `match`、`no_match` 或 `uncertain`。
4. 填写直接 Evidence Path 和行号。
5. 填写 `finding_summary`、`confidence`、`correlation`、`disposition`
   和 `rationale_code`。
6. 完成后将对应 `labels.template.json` 行的 `status` 改为 `reviewed`。

### 第 3 步：自检（约 10 分钟）

确认：

```text
40 条 status 都是 reviewed
没有必填字段为 null
每条 finding_summary 非空
每条 evidence_locations 至少一项
Evidence Path 来自对应的 source.*
没有填写 TP/FP/FN/TN classification
没有复制另一位 Reviewer 的答案
```

### 第 4 步：交付

只返回：

```text
labels.template.json
```

不要修改以下绑定字段：

```text
review_id
review_case_id
reviewer_id
rule_id
pack_id
corpus_binding_hash
question_set_sha256
review_case_fingerprint
source_sha256
```

## 独立性声明

完成后请在交付消息中确认：

```text
我独立完成了本目录中的 40 条评审，没有查看另一位 Reviewer 的结果，
没有使用 Ground Truth、Joint Expert Evidence 或 Seed Label 作为答案。
```

本目录是评审输入材料，不是正式 Human Evidence；正式导入、Comparison、
Confidence 校准和 Adjudication 将由 AgentSec 项目方后续执行。
