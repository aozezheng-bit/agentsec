# AgentSec Static Capability Profile

- Task: `P2-09`
- Status: Complete
- Agent Manifest Schema: `0.3.0`
- Decision: `docs/decisions/0026-static-capability-profile.md`

## 1. Purpose

`CapabilityExtractor` populates the existing Agent Manifest permission, control,
and runtime identity profiles from P2-08 static associations and parser-backed
Rules/MCP declarations.

```python
from agentsec.manifests import CapabilityExtractor

capability_manifest = CapabilityExtractor().extract(manifest, inspection)
```

It returns a new immutable Manifest. It does not execute or connect to anything.

## 2. Permission profile

Known static tool side effects become permissions with separate `action`,
`resource`, `scope`, and `effect` fields.

```text
execute + MCP stdio → action=execute, resource=shell
a MCP HTTP server  → action=network, resource=network
secret/env reference → action=secret_access, resource=environment
unknown tool effect  → action=unknown, resource=tool
```

Tool availability is not folded into permission effect. For example, a disabled
MCP server can still have a recorded static execute/network potential while its
separate enablement control is `disabled`.

HTTP scope handling is conservative:

```text
remote endpoint → external
local endpoint  → unknown
```

`.rules` declarations are different because they contain explicit decisions:

```text
allow    → permission effect allow + control state allow
prompt   → permission effect prompt + control state prompt
forbidden → permission effect deny + control state deny
```

The rule target is a stable hash. Pattern values are not serialized.

## 3. Control profile

P2-09 creates source-backed controls for reviewed static MCP fields:

| MCP evidence | Control kind | State |
|---|---|---|
| explicit `enabled=true/false` | `enablement` | enabled/disabled |
| missing `enabled` | `enablement` | unknown |
| explicit `required=true/false` | `required` | required/optional |
| missing `required` | `required` | unknown |
| `auto` approval | `human_approval` | allow |
| `prompt`, `approve`, `writes` | `human_approval` | prompt |
| enabled/disabled tool filter | `tool_filter` | allow/deny |
| endpoint | `network_policy` | configured |
| startup/tool timeout | `timeout` | configured |
| environment/header reference | `secret_handling` | configured/unknown |

Each control includes an exact field path and 1-based line range when the
parser provides one.

## 4. Runtime identities

One identity is created per static MCP server. Only reviewed declaration facts
are used:

```text
OAuth                  → oauth_session / oauth
ChatGPT auth           → chatgpt / chatgpt
Bearer/env HTTP auth   → api_client / environment
Plugin-bundled         → plugin / unknown
No reviewed auth       → unknown / unknown
```

The operational environment is `local` for STDIO and local HTTP, `external`
for non-local HTTP, and `unknown` for plugin-bundled servers. `privileged` is
`null` unless explicitly proven by a future reviewed source.

No credential or environment value is stored.

## 5. Resolution state

| Condition | Permissions / controls / identities |
|---|---|
| no relevant declaration sources | preserve `unknown` |
| visible facts, complete Coverage, no uncertainty | `resolved` |
| incomplete Coverage or unknown/unsupported static facts | `partial` |
| relevant source but no recognized fact | `partial` |

This prevents a config file containing unsupported or unrelated fields from
being reported as a clean absence of capability.

## 6. Provenance and safety

Every generated permission, control, and identity carries source provenance.
MCP commands, URLs, header values, environment values, Rules patterns, and
justifications are not copied into the Manifest. Sanitized field paths and line
ranges remain available for review.

The extractor performs no:

```text
filesystem reread
command execution
Skill execution
MCP launch or network connection
runtime tool enumeration
environment lookup
secret read
Rules evaluation
scanned-code import
LLM call
```

## 7. Current boundary

P2-09 does not yet produce risk Findings, Capability Diff, runtime attestation,
sub-Agent/memory relationships, or CLI output. P2-10 owns delegation and memory
relations; P2-11 owns systematic Unknown generation and later Capability Diff
integration.
