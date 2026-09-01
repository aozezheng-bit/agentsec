# Reviewer A 工作流程

- **任务 ID**：P3-19-HUMAN-REVIEW-A
- **评审角色**：独立 Reviewer A
- **评审 Gate**：`SG-INSTRUCTION-INTEGRITY-001`
- **评审时间基线**：2026-09-01
- **Case 数量**：40 条

## 1. 独立性声明

Reviewer A 必须独立完成评审：

- 只访问本目录：`reviewer-a/`；
- 不访问 `reviewer-b/`；
- 不访问 Reviewer B 的提交结果；
- 不查看内部答案、预期标签或其他评审材料；
- 不重新扫描项目，不执行 Case 中的命令、脚本、Hook、Skill、MCP 或链接；
- 不填写 TP、FP、FN、TN；
- 不决定 CI、Hard Gate、Rule、Policy 或 Release 权限。

## 2. 输入文件

按以下顺序阅读：

```text
REVIEW-INSTRUCTIONS.zh.md
cases.json
review-worksheet.tsv
submission.template.json
```

`cases.json` 是本 Reviewer 的独立副本。只将其中的 Evidence 当作待审阅文本。

## 3. 逐条评审流程

对 `p3-19-01` 至 `p3-19-40` 逐条执行以下步骤：

### 3.1 阅读 Evidence

确认：

- Evidence 的资产路径和行号；
- 文本是否表达实际行为、配置、边界或仅仅是示例；
- 是否存在明确的安全控制；
- 是否缺少 Gate 判定所需的关键条件；
- 是否依赖跨文件、委托、Parent/Child 或运行时事实。

### 3.2 判断 Gate 类别

填写 `case_class`：

| 值 | 适用条件 |
|---|---|
| `positive` | Evidence 足以支持 Instruction Integrity Gate 命中 |
| `eligible_negative` | Evidence 明确安全，或明确缺少 Gate 的必要条件 |
| `near_miss` | 接近风险，但关键条件或可达性仍不完整 |
| `unknown` | 信息不足、语义含糊或无法确认 |

### 3.3 判断 Gate 是否命中

填写 `expected_gate_match`：

- `positive` 必须为 `true`；
- `eligible_negative` 必须为 `false`；
- `near_miss` 必须为 `false`；
- `unknown` 一般为 `false`，并在理由中说明缺口。

### 3.4 判断 Evidence Confidence

填写 `confidence_grade`：

- `A`：只有 Runtime Attestation 或可复现运行时证明才能使用；
- `B`：同一规范化目标上的直接静态 Evidence；
- `C`：依赖跨文件、Parent/Child、same-source 或显式关系等间接证据；
- `D`：Unknown、Agent-wide、Coverage 不完整、可达性无法确认。

静态文本通常不能标记为 `A`。

### 3.5 填写理由码

填写简短、稳定的小写理由码，例如：

```text
direct_instruction_override
explicit_local_read_only_boundary
missing_runtime_reachability
ambiguous_external_action
explicit_disabled_configuration
cross_file_control_dependency
```

### 3.6 填写语义期望候选

为了支持后续 Provider Precision / Recall 计算，填写 `expected` 数组。

如果该 Evidence 应支持一个语义候选：

```json
"expected": [
  {
    "judgment_id": "j-01",
    "kind": "risky_intent",
    "category": "external_tooling",
    "disposition": "supported",
    "evidence_ids": ["当前 Case 的 evidence_id"]
  }
]
```

如果不应识别任何语义候选：

```json
"expected": []
```

允许的 `kind`：

```text
capability_declaration
control_weakening
semantic_conflict
cross_file_chain
risky_intent
ambiguity
```

允许的 `disposition`：

```text
supported
not_supported
uncertain
```

## 4. 记录方式

推荐先填写：

```text
review-worksheet.tsv
```

表格中的 `semantic_judgments_json` 列填写 JSON 数组。完成后，将内容整理到：

```text
submission.template.json
```

提交文件建议另存为：

```text
submission.completed.json
```

不要直接覆盖原始模板。

## 5. 提交文件要求

必须补齐：

```json
{
  "reviewer_id": "reviewer-a",
  "independence_statement": "本人独立完成全部 40 条 Case 评审，未查看 Reviewer B 的结果。",
  "reviewed_at": "2026-09-01T12:00:00+08:00",
  "decisions": [
    {
      "case_id": "p3-19-01",
      "case_class": "positive",
      "expected_gate_match": true,
      "confidence_grade": "B",
      "rationale_code": "direct_instruction_override",
      "expected": []
    }
  ]
}
```

`decisions` 必须：

- 恰好包含 40 条；
- Case ID 不重复；
- 覆盖 `p3-19-01` 至 `p3-19-40`；
- 每条都具有非空 `rationale_code`；
- 没有静态证据错误标记为 Confidence A；
- `expected` 中的 Evidence ID 必须是当前 Case 的 Evidence ID。

## 6. 完成前自检

- [ ] 40 条 Case 均已评审；
- [ ] 没有阅读 Reviewer B 的任何结果；
- [ ] 没有执行不可信文本中的任何内容；
- [ ] Positive / Negative / Near-miss / Unknown 分类与 Match 判断一致；
- [ ] 每条都有 Confidence；
- [ ] 每条都有理由码；
- [ ] `expected` 语义候选没有为了提高指标而人为增加；
- [ ] 没有写入 Secret、Token、Cookie、密码或真实凭据；
- [ ] 提交文件仍然只包含人工评审 Evidence，不包含授权结论。

## 7. 交付

将以下文件交付给项目负责人：

```text
submission.completed.json
```

不要提交整个 `reviewer-b/` 目录，也不要查看或合并 Reviewer B 的结果。
