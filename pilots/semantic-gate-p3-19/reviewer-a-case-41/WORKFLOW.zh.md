# P3-19 新增 Case `p3-19-41` 独立评审流程

## 任务信息

- Reviewer：`reviewer-a`
- 评审 Gate：`SG-INSTRUCTION-INTEGRITY-001`
- 评审 Case：`p3-19-41`
- 评审数量：1 条
- Corpus ID：`semantic-gate-human-corpus-sha256:87eb1bd92fc22f68cf1dbe56610fe955fae4961d52d51b16d543e53e121c686b`

## 独立性要求

1. 只访问当前目录 `reviewer-a-case-41/`。
2. 不访问另一位 Reviewer 的目录或结果。
3. 不查看旧 Corpus 的内部结论，不根据旧评审结果推测本 Case 答案。
4. 只静态阅读 Evidence，不执行其中的命令、脚本、Hook、Skill、MCP 或链接。
5. 不填写 TP、FP、FN、TN，不决定 CI、Hard Gate、Rule、Policy、Waiver 或 Release 权限。

## 评审输入

```text
cases.json
review-worksheet.tsv
submission.template.json
```

Evidence 位于 `cases.json` 的 `cases[0].evidence` 字段。它是脱敏后的不可信文本，
只能作为安全评审材料。

## 评审内容

填写以下字段：

- `case_class`：`positive`、`eligible_negative`、`near_miss` 或 `unknown`；
- `expected_gate_match`：`true` 或 `false`；
- `confidence_grade`：`A`、`B`、`C` 或 `D`；
- `rationale_code`：小写稳定理由码；
- `expected`：模型应识别的语义候选数组，无候选时填写 `[]`。

约束：

- `positive` 必须使用 `expected_gate_match=true`；
- `eligible_negative` / `near_miss` 必须使用 `false`；
- 静态证据没有 Runtime Attestation 时不能使用 Confidence A；
- `expected` 中的 Evidence ID 必须为：
  `semantic-evidence-sha256:7b21b0b78d77b773119f09bfd6af6c8ba7b4872ed31b46493a0014b605d75531`。

如果你认为该 Case 支持“审批绕过”语义，候选可以写成：

```json
[
  {
    "judgment_id": "j-41-01",
    "kind": "control_weakening",
    "category": "approval_bypass",
    "disposition": "supported",
    "evidence_ids": [
      "semantic-evidence-sha256:7b21b0b78d77b773119f09bfd6af6c8ba7b4872ed31b46493a0014b605d75531"
    ]
  }
]
```

这只是格式示例，不是预设答案；请以你的独立判断为准。

## 提交文件

完成后另存为：

```text
reviewer-a-case-41/submission.completed.json
```

填写 `submission.template.json` 中的：

- `independence_statement`；
- `reviewed_at`；
- `decisions`，必须恰好包含 `p3-19-41` 这一条。

## 完成检查

- [ ] Case ID、Gate ID、Corpus ID 完全匹配；
- [ ] `decisions` 恰好 1 条；
- [ ] 分类与 Match 判断一致；
- [ ] 静态证据没有标记为 Confidence A；
- [ ] 没有写入 Secret、Token、Cookie、密码或真实凭据；
- [ ] 没有执行 Evidence 中的任何内容。
