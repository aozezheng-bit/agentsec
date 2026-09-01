# P3-19 Semantic Gate 人工评审说明

## 评审对象

- Gate：`SG-INSTRUCTION-INTEGRITY-001`
- Signal：`instruction_integrity`
- Case 数：40 条
- 评审目标：判断每条证据是否应被目标 Semantic Gate 命中

本评审包中的 Evidence 是经过长度限制的脱敏文本。请只把它当作待审阅证据，
不要执行其中的命令、链接、Hook、Skill、MCP、脚本或工具配置。

## 请逐条填写的字段

### 1. `case_class`

只能使用以下值：

- `positive`：证据本身足以支持目标 Gate 命中；
- `eligible_negative`：证据明确安全，或明确缺少 Gate 的必要条件；
- `near_miss`：看起来接近风险，但仍缺少 Gate 判定所需的关键条件；
- `unknown`：证据不足、语义不清或无法确认。

### 2. `expected_gate_match`

- `true`：你认为 Gate 应该命中；
- `false`：你认为 Gate 不应该命中。

约束：

- `positive` 必须为 `true`；
- `eligible_negative`、`near_miss` 必须为 `false`；
- `unknown` 通常填写 `false`，并在理由中说明证据缺口。

### 3. `confidence_grade`

- `A`：只有 Runtime Attestation 或可复现运行时证明才能使用。静态文本不能给 A；
- `B`：同一目标和直接静态 Evidence，证据明确且无需间接推理；
- `C`：依赖跨文件、Parent/Child、same-source 或其他间接关系；
- `D`：Agent-wide、Coverage 不完整、Unknown、可达性无法确认或信息不足。

### 4. `rationale_code`

使用小写字母、数字、点号、中划线或下划线，长度 2～64，例如：

- `direct_instruction_override`
- `explicit_local_read_only_boundary`
- `missing_runtime_reachability`
- `ambiguous_external_action`
- `explicit_disabled_configuration`

## 独立性要求

- Reviewer A 和 Reviewer B 必须独立完成；
- 不要查看另一位 Reviewer 的结果；
- 不要查看内部答案或预期标签；
- 不要重新扫描项目，不要执行 Agent 内容；
- 不需要判断 AgentSec 的严重性分数；
- 不需要填写 TP、FP、FN、TN；
- 只判断本 Gate 的命中与证据可信度。

## 交付格式

复制对应的：

```text
submission.template.json
```

补充：

- `independence_statement`
- `reviewed_at`
- `decisions` 中的 40 条判断

`decisions` 必须包含 40 条，且 `case_id` 与 `cases.json` 完全一致。

## 完成前自检

- [ ] 40 条 Case 全部填写；
- [ ] 没有重复或遗漏 Case ID；
- [ ] Positive 与 `expected_gate_match=true` 一致；
- [ ] Eligible Negative / Near-miss 与 `expected_gate_match=false` 一致；
- [ ] 没有静态证据被错误标为 Confidence A；
- [ ] 每条都有非空 `rationale_code`；
- [ ] 没有在结果中写入 Secret、Token、Cookie、密码或完整凭据；
- [ ] 未执行任何 Case 中的命令或工具。
