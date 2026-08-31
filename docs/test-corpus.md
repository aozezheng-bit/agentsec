# AgentSec Phase 1 Test Corpus

- Initial task: `P1-28`
- Chinese extension: `M1-01`
- Status: Complete
- Decision date: 2026-08-19
- Total Cases: `45`

## 1. Purpose

The Phase 1 corpus provides stable, non-executable inputs for Collector, Parser,
Rule Pack, Coverage, reporting, integration, and future Demo regression work.

Every directory contains a strict `case.json` plus one or more supported Agent
Markdown assets. Tests read the assets only as untrusted bytes or text and never
execute instructions, code blocks, links, scripts, Hooks, Skills, or MCP servers.

## 2. Distribution

| Category | Cases | Primary role |
|---|---:|---|
| Safe | 11 | Negative and defensive-policy regression |
| Risky | 21 | Positive deterministic Rule and composite signals |
| Prompt Injection | 7 | Scanner-control attempts retained as data |
| Malformed | 6 | Encoding, empty, control, and structural boundaries |
| **Total** | **45** | Phase 1 target is 30–50 |

## 3. Production Rule coverage

All 15 Rule Pack `0.3.0` IDs have at least one isolated Case whose expected
`rule_ids` list contains only that Rule.

| Rule ID | Isolated or focused corpus Cases |
|---|---|
| `MD-APPROVAL-001` | `prompt-injection-auto-approve`, `risky-approval-chinese` |
| `MD-DEPLOY-001` | `risky-package-publish` |
| `MD-DESTRUCT-001` | `risky-database-drop` |
| `MD-EXEC-001` | `prompt-injection-execute-command`, `risky-shell-fenced` |
| `MD-EXEC-002` | `risky-dynamic-eval` |
| `MD-INSTR-001` | `prompt-injection-disregard-prior`, `risky-instruction-override-only` |
| `MD-INSTR-002` | `prompt-injection-hide-instruction`, `prompt-injection-suppress-findings`, `risky-safety-check-disable-only` |
| `MD-MEMORY-001` | `risky-cross-session-memory` |
| `MD-NET-001` | `risky-external-api` |
| `MD-OBFUSC-001` | `risky-obfuscated-instructions` |
| `MD-PRIV-001` | `risky-production-write` |
| `MD-PRIV-002` | `risky-root-access` |
| `MD-SECRET-001` | `risky-credential-read` |
| `MD-SELF-001` | `risky-self-modify-skill` |
| `MD-TOOL-001` | `risky-executable-reference`, `risky-external-tool-text` |

The existing unit-level positive and negative Rule tests remain authoritative for
individual matcher semantics. The corpus adds file layout, parser, multi-Asset,
prompt-injection, and end-to-end Rule Runner realism.

## 4. Case index

| Case ID | Category | Coverage | Assets | Expected Rule IDs | Signals |
|---|---|---|---:|---|---|
| `malformed-embedded-nul` | malformed | complete | 1 | `MD-OBFUSC-001` | `control_character` |
| `malformed-empty-document` | malformed | complete | 1 | — | `empty_content` |
| `malformed-invalid-utf8` | malformed | incomplete | 1 | — | `unsupported_encoding` |
| `malformed-invalid-utf8-truncated` | malformed | incomplete | 1 | — | `unsupported_encoding` |
| `malformed-unclosed-code-fence` | malformed | complete | 1 | — | `unclosed_code_fence` |
| `malformed-unclosed-frontmatter` | malformed | complete | 1 | — | `malformed_content` |
| `prompt-injection-chinese-scanner-control` | prompt-injection | complete | 1 | `MD-INSTR-001`, `MD-INSTR-002` | `instruction_integrity` |
| `prompt-injection-auto-approve` | prompt-injection | complete | 1 | `MD-APPROVAL-001` | `human_approval` |
| `prompt-injection-disregard-prior` | prompt-injection | complete | 1 | `MD-INSTR-001` | `instruction_integrity` |
| `prompt-injection-execute-command` | prompt-injection | complete | 1 | `MD-EXEC-001` | `code_execution` |
| `prompt-injection-hide-instruction` | prompt-injection | complete | 1 | `MD-INSTR-002` | `instruction_integrity` |
| `prompt-injection-ignore-scanner` | prompt-injection | complete | 1 | `MD-INSTR-001`, `MD-INSTR-002` | `instruction_integrity` |
| `prompt-injection-suppress-findings` | prompt-injection | complete | 1 | `MD-INSTR-002` | `instruction_integrity` |
| `risky-chinese-admin-destructive-dynamic` | risky | complete | 1 | `MD-DESTRUCT-001`, `MD-EXEC-002`, `MD-OBFUSC-001`, `MD-PRIV-002` | `code_execution`, `destructive_action`, `obfuscation`, `privileged_access`, `zero_width` |
| `risky-chinese-capability-chain` | risky | complete | 1 | `MD-APPROVAL-001`, `MD-DEPLOY-001`, `MD-EXEC-001`, `MD-NET-001`, `MD-PRIV-001`, `MD-SECRET-001` | `code_execution`, `destructive_action`, `human_approval`, `network_access`, `privileged_access`, `secret_access` |
| `risky-chinese-governance-memory` | risky | complete | 2 | `MD-INSTR-001`, `MD-INSTR-002`, `MD-MEMORY-001`, `MD-SELF-001`, `MD-TOOL-001` | `external_tooling`, `instruction_integrity`, `persistent_memory`, `self_modification` |
| `risky-approval-bypass` | risky | complete | 1 | `MD-APPROVAL-001`, `MD-INSTR-001`, `MD-INSTR-002` | `instruction_integrity`, `human_approval` |
| `risky-approval-chinese` | risky | complete | 1 | `MD-APPROVAL-001` | `human_approval` |
| `risky-credential-read` | risky | complete | 1 | `MD-SECRET-001` | `secret_access` |
| `risky-cross-session-memory` | risky | complete | 1 | `MD-MEMORY-001` | `persistent_memory` |
| `risky-database-drop` | risky | complete | 1 | `MD-DESTRUCT-001` | `destructive_action` |
| `risky-dynamic-eval` | risky | complete | 1 | `MD-EXEC-002` | `code_execution` |
| `risky-executable-reference` | risky | complete | 1 | `MD-TOOL-001` | `external_tooling` |
| `risky-external-api` | risky | complete | 1 | `MD-NET-001` | `network_access` |
| `risky-external-tool-text` | risky | complete | 1 | `MD-TOOL-001` | `external_tooling` |
| `risky-instruction-override-only` | risky | complete | 1 | `MD-INSTR-001` | `instruction_integrity` |
| `risky-obfuscated-instructions` | risky | complete | 1 | `MD-OBFUSC-001` | `base64_like`, `zero_width`, `mixed_script_confusable` |
| `risky-package-publish` | risky | complete | 1 | `MD-DEPLOY-001` | `destructive_action` |
| `risky-production-write` | risky | complete | 1 | `MD-PRIV-001` | `privileged_access` |
| `risky-root-access` | risky | complete | 1 | `MD-PRIV-002` | `privileged_access` |
| `risky-safety-check-disable-only` | risky | complete | 1 | `MD-INSTR-002` | `instruction_integrity` |
| `risky-self-modify-skill` | risky | complete | 1 | `MD-SELF-001` | `self_modification` |
| `risky-shell-fenced` | risky | complete | 1 | `MD-EXEC-001` | `code_execution` |
| `risky-shell-secret-network` | risky | complete | 1 | `MD-APPROVAL-001`, `MD-EXEC-001`, `MD-NET-001`, `MD-SECRET-001` | `code_execution`, `human_approval`, `network_access`, `secret_access` |
| `safe-chinese-local-review` | safe | complete | 1 | — | — |
| `safe-approval-required` | safe | complete | 1 | — | — |
| `safe-document-reference` | safe | complete | 1 | — | — |
| `safe-ephemeral-session` | safe | complete | 1 | — | — |
| `safe-local-only-network` | safe | complete | 1 | — | — |
| `safe-minimal-agent` | safe | complete | 1 | — | — |
| `safe-nested-skill` | safe | complete | 2 | — | — |
| `safe-override-layer` | safe | complete | 2 | — | — |
| `safe-read-only-control-assets` | safe | complete | 1 | — | — |
| `safe-redaction-policy` | safe | complete | 1 | — | — |
| `safe-shell-explanation` | safe | complete | 1 | — | — |

## 5. Safe and boundary coverage

The Safe group includes explicit approval, non-executing shell documentation,
local-only network behavior, defensive redaction, ephemeral session handling,
read-only control assets, a non-executable Markdown reference, nested Skill
discovery, and nested `AGENTS.override.md` discovery.

The Malformed group includes:

- two distinct invalid UTF-8 byte sequences;
- unclosed frontmatter;
- an unclosed fenced code block;
- an empty readable Agent asset;
- an embedded NUL control character, which produces `MD-OBFUSC-001` through
  the real parser-indicator and Rule chain.

Expected Coverage is replayed through the real `CollectionAssessmentEngine`.
Readable structural boundaries remain complete when the current parser accepts
them; invalid encodings produce incomplete Coverage with structured Issues.

## 6. Prompt-injection coverage

The injection group directs the scanner to ignore earlier instructions, suppress
Findings, hide instructions, auto-approve content, or execute a command. The
fixtures are processed by the same deterministic Rules as other Markdown and
never gain control over scanner flow.

## 7. Corpus safety controls

Tests enforce:

- globally unique stable Case IDs matching category and directory;
- strict top-level and expected-result manifest fields;
- project-relative sorted unique supported Asset paths;
- 30–50 total Cases and category minimums;
- complete coverage of all 15 production Rule IDs;
- exact expected Rule IDs against the real Rule Runner;
- expected Coverage against the real Collector and Parser pipeline;
- no symbolic links;
- no executable fixture files;
- no full secret value recognized by the P1-26 redactor;
- no non-reserved HTTP host; all fixture URLs use `.invalid`;
- no email-like personal data;
- invalid UTF-8 fixtures are intentionally read as bytes.

## 8. Authoring rules

When adding or changing a Case:

1. use a stable `category-case-name` Case ID;
2. update `case.json` and every declared Asset together;
3. list exact sorted production Rule IDs;
4. use signal names from Domain categories, Coverage codes, parser indicators,
   or the documented boundary vocabulary;
5. replay the real Rule Pack and Collection Assessment tests;
6. use synthetic placeholders and reserved `.invalid` hosts only;
7. do not add executable files, symlinks, real credentials, internal addresses,
   or personal information;
8. do not special-case production code for a fixture path or Case ID.

## 9. Version decision

P1-28 originally published 40 inert Cases without changing production Rule
semantics. M1-01 adds five Chinese Cases and also expands the reviewed Chinese
trigger set of the same 15 Rule IDs. The behavior change is therefore recorded
by ADR-0017 and increments only:

```text
RULE_PACK_VERSION = 0.3.1
```

Config, Domain, Baseline, Diff, Assessment Output, and Risk Model versions remain
unchanged. Fixture additions alone do not require a version change; the Rule
Pack increment is required because identical Chinese Markdown can now produce
new Findings.

## 10. Current integration status

The integration suite replays all 45 Cases through `agentsec scan --format json`,
validates the strict Assessment report, compares unique production Rule IDs,
verifies Coverage and exit codes, and keeps fixture content inert. The corpus is
reused by the English and Chinese Release Agent Demo tracks without executing
any instruction.
