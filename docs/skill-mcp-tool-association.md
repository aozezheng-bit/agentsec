# AgentSec Skill / MCP / Tool Association

- Task: `P2-08`
- Status: Complete
- Agent Manifest Schema: `0.3.0`
- Decision: `docs/decisions/0025-skill-mcp-tool-association.md`

## 1. Purpose

`AssociationExtractor` converts inspected Codex Skill and static MCP
Declarations into a deterministic source-backed `ManifestTool` inventory and
`ManifestRelation` graph.

```python
from agentsec.manifests import AssociationExtractor

associated_manifest = AssociationExtractor().extract(manifest, inspection)
```

The input Manifest remains immutable. The extractor returns a new validated
Manifest and does not perform filesystem reads.

## 2. Input integrity

The extractor must receive the same logical inspection used by
`AgentManifestBuilder`. Before consuming parser output it matches every
inspected asset against the Manifest by:

```text
portable scope/root/path
format
roles
SHA-256 content digest
size and line count
Adapter precedence rank
```

A stale or mismatched pair raises `AssociationExtractionError` with a safe,
content-free message.

## 3. Skill inventory

Each inspected `SKILL.md` with the `skill` role creates:

| Field | Value |
|---|---|
| `kind` | `skill` |
| `availability` | `declared` |
| `side_effects` | `[unknown]` |
| `sources` | whole `SKILL.md` source reference |

The Skill directory name becomes bounded display metadata and a stable ID such
as `skill:review`. The Markdown body is not copied or executed.

## 4. MCP server inventory

Each static parsed MCP server creates an `mcp_server` item and a `uses_mcp`
relationship. Static enablement is represented as:

| Declaration | Availability |
|---|---|
| no `enabled` field | `declared` |
| `enabled = true` | `enabled` |
| `enabled = false` | `disabled` |

Conservative potential side effects are:

| Transport | Side effect |
|---|---|
| `stdio` | `execute` |
| `streamable_http` | `network` |
| `plugin_bundled` | `unknown` |

These values do not prove runtime activation, reachability, or authorization.

MCP server provenance includes a structured field path and source line range,
for example:

```text
source: .codex/config.toml
field: $.mcp_servers.docs
lines: 2-8
```

## 5. MCP tool inventory

Static `enabled_tools`, `disabled_tools`, and `tool_policies` are associated
without contacting the MCP server. Each logical tool becomes an `mcp_tool`
child of its server:

```text
mcp-tool:docs:search
parent_tool_id = mcp-server:docs
```

Availability is `enabled`, `disabled`, `declared`, or `unknown` when the same
name occurs in both enabled and disabled filters. Tool policy approval modes
remain source-backed evidence only; they are not converted to permissions or
controls in P2-08.

Tool provenance points to the exact filter or policy field path and line range.
The value of the tool name is not serialized into a source field value; only
bounded normalized metadata and provenance are retained.

## 6. Relations

Generated relation types are:

```text
uses_skill → Skill target
uses_mcp   → MCP server target
uses_tool  → MCP tool target
```

All relation states are `declared`, never `active`, because P2-08 performs no
runtime verification. Every relation carries source provenance and its source
Agent ID must match the Manifest identity.

## 7. Stable identifiers

Readable IDs are used for unique names. Distinct declarations that collide
after normalization receive a deterministic short SHA-256 suffix derived from
the portable source identity. IDs never contain absolute paths, commands,
URLs, environment values, or tokens.

Examples:

```text
skill:review
mcp-server:docs
mcp-tool:docs:search
relation:uses-mcp:mcp-server:docs
```

## 8. Resolution and coverage

| Input condition | Tool / relationship status |
|---|---|
| no Skill/MCP sources | preserve `unknown` |
| declarations + complete Coverage | `resolved` |
| declarations + incomplete Coverage | `partial` |

`partial` is retained even when the visible declarations are successfully
associated, because skipped or unreadable assets may hide additional tools.

## 9. Security boundary

The extractor performs no:

```text
filesystem reads
Skill execution
command execution
MCP process launch
MCP network connection
environment lookup
secret/header value read
Rules evaluation
runtime tool enumeration
scanned-code import
LLM call
```

P2-08 does not create permissions, controls, runtime identities, risk Findings,
Capability Diff, or CI blocking decisions.
