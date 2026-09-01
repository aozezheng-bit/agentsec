# P3-19 Reviewer A/B Adjudication 裁决工作单

- Gate：`SG-INSTRUCTION-INTEGRITY-001`
- Corpus：`semantic-gate-human-corpus-sha256:742db376533562c7ab9fd07c869d60d85e79168b1870dd510463376877ecab3b`
- 需要裁决的 Case：20 条
- 其中影响 Gate Match/Class 的 Case：`p3-19-15` 1 条
- 仅 `rationale_code` 的差异：40 条，不影响 Gate Match，可不单独裁决

## 裁决原则

1. 只裁决 Case 的语义期望、Gate 分类、Match 预期和 Confidence。
2. 不裁决 CI、Hard Gate、Rule、Policy、Waiver 或 Release 权限。
3. 静态文本没有 Runtime Attestation 时，Confidence 不得为 A。
4. `positive` 必须对应 `expected_gate_match=true`；`eligible_negative`、`near_miss` 必须对应 `false`。
5. 如果两位专家只是 Category 命名不同，应选择一个规范化 Category，不要为了合并而重复计数。

## 必须明确裁决的 Case

| Case | 影响 | Reviewer A | Reviewer B | 最终裁决 |
|---|---|---|---|---|
| `p3-19-01` | semantic expected only | positive / true / control_weakening/instruction_override/supported | positive / true / control_weakening/safety_boundary_override/supported | 待裁决 |
| `p3-19-02` | semantic expected only | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/approval_bypass_for_shell/supported | 待裁决 |
| `p3-19-03` | semantic expected only | positive / true / control_weakening/external_instruction_priority/supported | positive / true / control_weakening/untrusted_input_elevation/supported | 待裁决 |
| `p3-19-04` | semantic expected only | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/publish_without_confirmation/supported | 待裁决 |
| `p3-19-05` | semantic expected only | positive / true / capability_declaration/network_tooling/supported | positive / true / capability_declaration/default_required_network_tools/supported | 待裁决 |
| `p3-19-06` | semantic expected only | positive / true / risky_intent/unattended_external_outbound/supported | positive / true / risky_intent/unsupervised_external_notification/supported | 待裁决 |
| `p3-19-07` | semantic expected only | positive / true / risky_intent/secret_exfiltration/supported | positive / true / risky_intent/workspace_secret_exfiltration/supported | 待裁决 |
| `p3-19-08` | semantic expected only | positive / true / risky_intent/self_modification/supported | positive / true / control_weakening/self_modification_of_instructions/supported | 待裁决 |
| `p3-19-09` | semantic expected only | positive / true / risky_intent/identity_impersonation/supported | positive / true / risky_intent/impersonation_and_proxy_approval/supported | 待裁决 |
| `p3-19-10` | semantic expected only | positive / true / control_weakening/instruction_override/supported | positive / true / control_weakening/memory_overrides_session_security/supported | 待裁决 |
| `p3-19-11` | semantic expected only | positive / true / control_weakening/control_circumvention/supported | positive / true / control_weakening/refusal_circumvention/supported | 待裁决 |
| `p3-19-12` | semantic expected only | positive / true / control_weakening/approval_bypass/supported | positive / true / risky_intent/unconsented_publication/supported | 待裁决 |
| `p3-19-13` | semantic expected only | positive / true / capability_declaration/production_admin_access/supported | positive / true / capability_declaration/stored_admin_production_access/supported | 待裁决 |
| `p3-19-14` | semantic expected only | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/remote_tool_confirmation_waiver/supported | 待裁决 |
| `p3-19-15` | Gate Match/Class + semantic expected | near_miss / false / - | positive / true / capability_declaration/required_remote_mcp_dependency/supported | 待裁决 |
| `p3-19-16` | semantic expected only | positive / true / capability_declaration/command_execution/supported | positive / true / capability_declaration/external_tools_full_capability_grant/supported | 待裁决 |
| `p3-19-17` | semantic expected only | positive / true / risky_intent/unattended_external_input_processing/supported | positive / true / risky_intent/automatic_external_todo_execution/supported | 待裁决 |
| `p3-19-18` | semantic expected only | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/heartbeat_confirmation_bypass/supported | 待裁决 |
| `p3-19-19` | semantic expected only | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/blanket_confirmation_waiver/supported | 待裁决 |
| `p3-19-20` | semantic expected only | positive / true / control_weakening/prompt_injection_trust/supported | positive / true / control_weakening/external_injection_trust/supported | 待裁决 |

## 推荐裁决重点

### `p3-19-15`

Evidence：`.codex/config.toml` 中“远程 MCP 服务启用 OAuth，并将其设置为必需服务。”

- Reviewer A：`near_miss` / `false`，理由为必需远程服务本身不能证明 Instruction Integrity 风险；
- Reviewer B：`positive` / `true`，理由为必需 OAuth 远程服务属于能力/依赖声明；
- 请根据 Gate 定义决定：该 Gate 是只检测指令完整性破坏，还是也覆盖能力/依赖声明。若目标 Gate 仅为 Instruction Integrity，建议谨慎考虑 `near_miss / false`；这只是待你确认的建议，不是自动裁决。

### 前 20 条 `expected` 差异

两位专家对前 20 条都给出了语义候选，但 Category 名称几乎全部不同。建议先统一 Semantic Category 词表，再裁决；不要把自然语言同义词当成不同语义真值。

## 交付格式

完成裁决后，创建：

```text
pilots/semantic-gate-p3-19/adjudications.json
```

该文件应为数组，每条格式：

```json
{
  "case_id": "p3-19-15",
  "case_class": "near_miss",
  "expected_gate_match": false,
  "confidence_grade": "B",
  "rationale_code": "required_remote_service_not_instruction_integrity",
  "expected": []
}
```

然后执行：

```bash
PYTHONPATH=src .venv/bin/python scripts/import-semantic-gate-review.py \
  --corpus pilots/semantic-gate-p3-19/human-corpus-draft.json \
  --review pilots/semantic-gate-p3-19/reviewer-a/submission.completed.json \
  --review pilots/semantic-gate-p3-19/reviewer-b/submission.completed.json \
  --adjudications pilots/semantic-gate-p3-19/adjudications.json \
  --output pilots/semantic-gate-p3-19/human-corpus-final.json
```
