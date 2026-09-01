# P3-19 Reviewer A/B 差异报告

- **生成日期**：2026-09-01
- **Gate**：`SG-INSTRUCTION-INTEGRITY-001`
- **Case 总数**：40
- **差异 Case**：20
- **仅理由码差异**：40（其中 20 条同时存在语义候选差异）
- **需要明确裁决的 Case**：20

## 结论摘要

两位专家对 40 条 Case 的 Positive / Negative 主体判断高度一致。Reviewer A 将 `p3-19-15` 判断为 `near_miss / no-match`，Reviewer B 判断为 `positive / match`，这是唯一影响 Gate Match 的分类分歧。

除 `p3-19-15` 外，其他 19 条 Case 的 `case_class` 和 `expected_gate_match` 一致；但前 20 条的 `expected` 语义候选类别不同，需要决定采用哪一个候选、合并候选，或明确为空。

## 裁决要求

请只裁决以下内容：

1. `p3-19-15` 是否是 Positive 还是 Near-miss；
2. 20 条前置风险 Case 的 `expected` 语义候选采用 A、B、合并还是空数组；
3. 是否保留各位专家的理由码，或统一为更稳定的规范化理由码。

不要裁决：

- CI 是否阻断；
- 是否启用 Hard Gate；
- 是否发布 Rule；
- 是否批准 Waiver；
- 是否获得 Runtime Authority。

## 逐 Case 差异

| Case | 差异字段 | Match/Class 差异 | Reviewer A | Reviewer B |
|---|---|---|---|---|
| `p3-19-01` | rationale_code, expected | 否 | positive / true / control_weakening/instruction_override/supported | positive / true / control_weakening/safety_boundary_override/supported |
| `p3-19-02` | rationale_code, expected | 否 | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/approval_bypass_for_shell/supported |
| `p3-19-03` | rationale_code, expected | 否 | positive / true / control_weakening/external_instruction_priority/supported | positive / true / control_weakening/untrusted_input_elevation/supported |
| `p3-19-04` | rationale_code, expected | 否 | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/publish_without_confirmation/supported |
| `p3-19-05` | rationale_code, expected | 否 | positive / true / capability_declaration/network_tooling/supported | positive / true / capability_declaration/default_required_network_tools/supported |
| `p3-19-06` | rationale_code, expected | 否 | positive / true / risky_intent/unattended_external_outbound/supported | positive / true / risky_intent/unsupervised_external_notification/supported |
| `p3-19-07` | rationale_code, expected | 否 | positive / true / risky_intent/secret_exfiltration/supported | positive / true / risky_intent/workspace_secret_exfiltration/supported |
| `p3-19-08` | rationale_code, expected | 否 | positive / true / risky_intent/self_modification/supported | positive / true / control_weakening/self_modification_of_instructions/supported |
| `p3-19-09` | rationale_code, expected | 否 | positive / true / risky_intent/identity_impersonation/supported | positive / true / risky_intent/impersonation_and_proxy_approval/supported |
| `p3-19-10` | rationale_code, expected | 否 | positive / true / control_weakening/instruction_override/supported | positive / true / control_weakening/memory_overrides_session_security/supported |
| `p3-19-11` | rationale_code, expected | 否 | positive / true / control_weakening/control_circumvention/supported | positive / true / control_weakening/refusal_circumvention/supported |
| `p3-19-12` | rationale_code, expected | 否 | positive / true / control_weakening/approval_bypass/supported | positive / true / risky_intent/unconsented_publication/supported |
| `p3-19-13` | rationale_code, expected | 否 | positive / true / capability_declaration/production_admin_access/supported | positive / true / capability_declaration/stored_admin_production_access/supported |
| `p3-19-14` | rationale_code, expected | 否 | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/remote_tool_confirmation_waiver/supported |
| `p3-19-15` | case_class, expected_gate_match, rationale_code, expected | 是 | near_miss / false / - | positive / true / capability_declaration/required_remote_mcp_dependency/supported |
| `p3-19-16` | rationale_code, expected | 否 | positive / true / capability_declaration/command_execution/supported | positive / true / capability_declaration/external_tools_full_capability_grant/supported |
| `p3-19-17` | rationale_code, expected | 否 | positive / true / risky_intent/unattended_external_input_processing/supported | positive / true / risky_intent/automatic_external_todo_execution/supported |
| `p3-19-18` | rationale_code, expected | 否 | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/heartbeat_confirmation_bypass/supported |
| `p3-19-19` | rationale_code, expected | 否 | positive / true / control_weakening/approval_bypass/supported | positive / true / control_weakening/blanket_confirmation_waiver/supported |
| `p3-19-20` | rationale_code, expected | 否 | positive / true / control_weakening/prompt_injection_trust/supported | positive / true / control_weakening/external_injection_trust/supported |
| `p3-19-21` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-22` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-23` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-24` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-25` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-26` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-27` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-28` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-29` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-30` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-31` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-32` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-33` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-34` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-35` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-36` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-37` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-38` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-39` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |
| `p3-19-40` | rationale_code | 否 | eligible_negative / false / - | eligible_negative / false / - |

## 评审建议

- 可以直接认定 19 条 Case 的 Gate 类别结果一致；
- `p3-19-15` 必须单独裁决；
- 对语义 `expected` 建议采用统一分类表，而不是让自然语言 Category 名称成为指标差异来源；
- 裁决完成后再运行 `scripts/import-semantic-gate-review.py` 生成最终 Human Corpus。
