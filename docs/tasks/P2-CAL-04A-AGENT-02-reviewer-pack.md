# Agent 2 工作文档：Independent Reviewer Pack

## 1. 任务身份

```text
Task ID: P2-CAL-04A-AGENT-02
工作目录：/Users/zaz/Desktop/大安全/ice/AgentSec
任务：生成不泄露 Ground Truth 的 Reviewer Pack
```

本任务依赖 Agent 1 完成 Calibration Corpus Expansion。

## 2. 必须阅读

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/AGENTS.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/scope.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/calibration-adjudication-report.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/decisions/0037-independent-adjudication-and-gate-candidates.md
```

## 3. 写入范围

允许修改：

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/calibration/reviewer-pack/
/Users/zaz/Desktop/大安全/ice/AgentSec/scripts/build-reviewer-pack.py
/Users/zaz/Desktop/大安全/ice/AgentSec/tests/test_reviewer_pack.py
```

不要修改：

```text
src/agentsec/calibration/
src/agentsec/capability_rules/
calibration/cases/*/case.json
calibration/confidence-reviews.json
calibration/adjudication-reviews.json
P2-15A 或 P2-15B 代码
```

## 4. 目标目录

生成：

```text
calibration/reviewer-pack/
├── README.md
├── reviewer-instructions.md
├── case-matrix.json
├── case-matrix.csv
├── reviewer-label-schema.json
├── adjudication-label-schema.json
├── reviewer-a/
│   ├── cases/
│   └── labels.template.json
├── reviewer-b/
│   ├── cases/
│   └── labels.template.json
└── adjudicator/
    ├── adjudication-instructions.md
    └── adjudication.template.json
```

## 5. Ground Truth 隔离要求

Reviewer Pack 不得包含：

```text
expected outcome
expected Rule match
expected confidence
expected correlation
expected Gate status
recommended disposition
P2-CAL-04 by_rule 结果
P2-CAL-04 gate_candidates 结果
```

不得直接复制：

```text
calibration/cases/<case-id>/case.json
```

因为原始 Case 文件包含 Ground Truth。

应生成 Reviewer View，只包含：

```text
review_case_id
synthetic fixture
source location
input format
language
review questions
```

## 6. Reviewer Label Template

Label Template 至少包括：

```text
review_id
review_case_id
reviewer_id
rule_id
observed_finding
classification
category
confidence
correlation
disposition
rationale_code
review_notes
status
```

模板不得预填真实判断。由于正式 Schema 不包含 `pending`，模板可以省略
`status` 或将其作为非正式模板注释字段；转换为正式 Review Set 时，必须由
真实 Reviewer 填写 `reviewed`。

不能在未经过人工评审时使用：

```text
reviewed
adjudicated
```

## 7. Reviewer 指导文档

`reviewer-instructions.md` 必须说明：

- 不能执行 Fixture 或任何配置中的 Command；
- Reviewer A 和 Reviewer B 必须独立评审；
- 需要区分 Detection FP、Policy-Accepted Risk、In-Scope FN、Out-of-Scope 和 Runtime Uncertainty；
- 不确定时不得默认安全；
- 需要填写 Confidence 和 Correlation；
- 需要填写 Evidence 位置；
- 不得修改原始 Case；
- 不得将“风险看起来很高”直接当作 Hard Gate 合格；
- Reviewer Label 只能代表人工意见，不能直接改变 Rule 或 Gate。

## 8. CLI 要求

新增：

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/scripts/build-reviewer-pack.py
```

建议用法：

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec
.venv/bin/python scripts/build-reviewer-pack.py \
  --corpus calibration \
  --output calibration/reviewer-pack
```

要求：

```text
输出目录不可覆盖
输出文件权限为 0600
输入路径必须 containment-safe
拒绝 symlink
不执行 Fixture
不输出 Ground Truth
生成确定性 Case Matrix
```

## 9. 测试要求

至少覆盖：

```text
Reviewer Pack 可重复生成
Reviewer A/B 不包含 Ground Truth
expected 字段不会出现在 Reviewer View
输出不覆盖已有目录
路径越界被拒绝
symlink 被拒绝
模板 JSON 可以正常解析
```

## 10. 完成报告

必须报告：

```text
Reviewer Pack 路径
Reviewer A/B Case 数量
Ground Truth 隔离验证结果
生成命令
测试命令和结果
安全限制
真实 Reviewer 仍需人工完成
```


## 11. FIX-02 final hardening extension

The completed implementation additionally requires:

```text
Pack Schema 0.3.0 exact file Manifest
AdjudicationResolutionSet 0.1.0
separate AdjudicationReviewSet / ConfidenceReviewSet / Resolution outputs
P2-CAL-04 explicit seed/human evidence mode
no human Confidence fallback to Seed labels
original Reviewer disagreement preserved after adjudication
```

Architecture and provenance decisions are recorded in ADR-0038.
