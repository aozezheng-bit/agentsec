# P2-15A-QUAL-02：Reviewer A Confidence 校准工作流程

- 任务：`P2-15A-QUAL-02`
- 角色：Reviewer A
- 目标：重新校准 20 条 Confidence 校准 Case 的 Evidence Confidence
- 日期：2026-08-24
- Gate：`HG-CAPCHAIN-001`
- Rule：`CAP-CHAIN-001`

## 1. 任务背景

AgentSec 当前对 40 条 Case 的 Match/No-match 判断已经完成校准：

```text
Precision = 1.0
Recall = 1.0
```

本次任务只重新评审 Evidence Confidence，不重新判断 Finding 是否存在。

项目负责人会提供 20 条脱敏、盲化的 Confidence 校准 Case。Reviewer 不应根据
Case 选择过程推断任何期望标签或 Detector 输出。

## 2. 允许访问的目录

Reviewer A 只能访问项目负责人提供的 Confidence-only 工作目录，例如：

```text
confidence-review-20/reviewer-a/
```

目录中只应包含：

```text
WORKFLOW.md
labels.template.json
cases/<opaque-review-case-id>/case.json
cases/<opaque-review-case-id>/source.*
```

禁止访问：

```text
confidence-review-20/reviewer-b/
calibration/corpus.json
calibration/gate-coverage-matrix.json
calibration/p2-15a-capchain-40/human-evidence/
calibration/pilot-review-100/
calibration/reviewer-pack/
其他 Reviewer 的提交文件
```

## 3. 独立性要求

必须独立完成评审：

1. 不查看 Reviewer B 的目录或结果；
2. 不与 Reviewer B 讨论 Case 结论；
3. 不查看 Ground Truth、Seed Label 或最终 Qualification Report；
4. 不根据 Case 的选择过程推断期望标签或填写 Confidence；
5. 只根据当前 Case 中展示的静态证据判断 Confidence；
6. 不修改原始 40 条 Reviewer 评审结果；
7. 不填写 TP、FP、FN、TN；
8. 不填写新的 Match/No-match 结论。

## 4. 本次只评审一个字段

每个 Case 只填写：

```text
confidence
confidence_rationale
status
```

保持以下内容不变：

```text
human_condition_label
observed_finding
category
correlation
 disposition
finding_summary
evidence_locations
rationale_code
```

## 5. Confidence 定义

请严格按照以下项目定义判断：

| Confidence | 含义 | 当前任务中的典型条件 |
|---|---|---|
| A | Runtime Attestation 或可复现运行时证据 | 有实际运行、权限证明或运行时观测 |
| B | 同一规范化 Target，且有直接静态 Source 证据 | 三项能力在同一 Target 的配置/Manifest 中直接出现 |
| C | Parent/Child、same-source 或显式关系等间接静态证据 | 需要依赖间接关联 |
| D | Agent-wide、Coverage 不完整、Unknown 或可达性无法确认 | 证据范围或关联关系不足 |

注意：

```text
静态 Source 证据不能自动升级为 A。
A 级必须有运行时证明。
```

## 6. 单 Case 操作步骤

对每个 `case.json`：

1. 阅读 `review_questions`；
2. 阅读同目录的 `source.*`；
3. 确认三项能力是否由同一 Target 的静态证据直接支持；
4. 判断证据是否来自运行时，还是仅来自静态 Source；
5. 根据 Confidence 定义填写 A/B/C/D；
6. 填写一句简短的 `confidence_rationale`；
7. 将 `status` 设置为 `reviewed`。

## 7. Confidence Rationale 示例

### 同一 Target 的静态直接证据

```text
三项能力均由同一 Target 的静态 Source 直接声明，但没有 Runtime Attestation，因此为 B。
```

### 需要间接关系

```text
能力事实来自同一 Source，但依赖未明确的关系或 Target 关联，静态证据为间接证据，因此为 C。
```

### Coverage 或关联不完整

```text
相关 Coverage 或 Target 关系无法确认，无法形成完整证据链，因此为 D。
```

### 运行时证明

```text
存在可复现的运行时权限或执行证明，因此满足 A 级证据条件。
```

## 8. 交付格式

只提交自己的完成文件：

```text
reviewer-a-confidence-20-completed.json
```

推荐结构：

```json
{
  "format": "agentsec-confidence-recalibration-submission",
  "schema_version": "0.1.0",
  "task_id": "P2-15A-QUAL-02",
  "reviewer_id": "reviewer-a",
  "reviews": [
    {
      "review_case_id": "review-case-...",
      "confidence": "B",
      "confidence_rationale": "三项能力均由同一 Target 的静态 Source 直接声明，但没有 Runtime Attestation，因此为 B。",
      "status": "reviewed"
    }
  ]
}
```

## 9. 交付前自检

确认：

```text
20 条 Case 全部存在
20 条 status 都是 reviewed
每条 confidence 都是 A/B/C/D 之一
每条 confidence_rationale 非空
没有填写 Match/No-match
没有填写 TP/FP/FN/TN
没有修改 review_case_id
没有查看 Reviewer B 结果
没有引用 Ground Truth
```

## 10. 独立性声明

交付时请附上：

```text
我作为 Reviewer A 独立完成了 20 条 Confidence 校准，没有查看 Reviewer B、Ground Truth、Seed Label 或最终 Qualification 结果。本次只重新评审 Evidence Confidence，没有修改 Match/No-match 判断。
```
