# ADR-0025: Skill / MCP / Tool Association

- Status: Accepted
- Date: 2026-08-20
- Task: P2-08
- Agent Manifest Schema: `0.3.0` (unchanged)

## Context

P2-04 returns parser-coherent Framework asset records, including parsed Codex
Skills and static MCP declarations. P2-05 deliberately keeps parsed values out
of the Agent Manifest, while P2-06 and P2-07 resolve instruction and
configuration source order. The next boundary is to turn only the reviewed,
static declarations into a capability inventory and relationship graph.

A declaration is not proof of runtime activation. A Skill may be unavailable,
an MCP server may fail to start, and an MCP tool list may be an allow/deny
filter rather than an enumeration of the server's real tool surface. The
association stage must therefore preserve that distinction and must not perform
runtime verification as a side effect of scanning.

## Decision

### 1. Separate extraction from source-only Manifest building

Add `AssociationExtractor.extract(manifest, inspection) -> AgentManifest` in
`src/agentsec/manifests/associations.py`. The extractor consumes the same
`FrameworkInspectionResult` used to build the Manifest and returns a new
validated immutable Manifest. It does not read files again.

Before extraction, it verifies portable source locator, format, role, digest,
size, line count, and precedence metadata. A stale or mismatched inspection is
rejected safely instead of being combined with a Manifest from another scan.

`AssociationResolver` is provided as a compatibility name for callers that
model P2-08 as a Resolver step.

### 2. Skill associations

For every inspected Markdown asset with the `skill` role:

```text
ManifestTool.kind         = skill
ManifestTool.availability = declared
ManifestTool.side_effects = [unknown]
ManifestRelation.kind     = uses_skill
ManifestRelation.state    = declared
```

The Skill directory name is normalized into bounded display metadata and a
stable ASCII ID. The `SKILL.md` body is never copied, loaded as executable
content, or interpreted as an authorization decision.

### 3. MCP server associations

For every parsed static MCP server declaration:

```text
ManifestTool.kind         = mcp_server
ManifestRelation.kind     = uses_mcp
ManifestRelation.state    = declared
```

Availability is derived only from an explicit static `enabled` field:

```text
missing enabled → declared
true             → enabled
false            → disabled
```

The extractor records only safe source-backed declaration metadata. It never
stores commands, arguments, endpoint values, query strings, static headers,
or environment-variable values in the Manifest.

The following side effects are conservative static potential classifications,
not runtime claims:

```text
stdio           → execute
streamable_http → network
plugin_bundled  → unknown
```

### 4. MCP tool associations

If a static MCP declaration contains `enabled_tools`, `disabled_tools`, or
`tool_policies`, create one `mcp_tool` inventory item per logical declared tool.
The item is a child of its MCP server through `parent_tool_id` and receives a
`uses_tool` relationship.

Availability is:

```text
enabled_tools only                → enabled
disabled_tools only              → disabled
tool policy only                 → declared
both enabled and disabled         → unknown
```

A tool policy is evidence that a tool name is declared; P2-08 does not yet
interpret approval modes as permissions or controls. Static tool declarations
are not treated as proof that a runtime MCP server exposes that tool.

### 5. Stable IDs and collision handling

Human-readable IDs use the following forms when no collision exists:

```text
skill:<normalized-name>
mcp-server:<normalized-name>
mcp-tool:<server-id-without-prefix>:<normalized-name>
relation:uses-skill:<tool-id>
relation:uses-mcp:<server-id>
relation:uses-tool:<tool-id>
```

Non-ASCII, control, path-separator, and oversized values are normalized for
IDs. If two distinct portable declarations map to the same readable ID, a
short SHA-256 suffix derived from the portable source identity is appended.
The output remains deterministic, bounded, and free of absolute host paths.

### 6. Provenance

Every generated tool and relation has at least one `ManifestSourceReference`.
MCP server references include a structured field path and server line range.
MCP tool references include the exact filter or policy field path and line
range. Skill references point to the inspected `SKILL.md` source. Source
provenance is retained without copying the associated untrusted values.

### 7. Resolution state

When Skill or MCP declaration sources exist:

```text
complete Coverage   → tools/relationships = resolved
incomplete Coverage → tools/relationships = partial
```

No relevant declaration sources remain `unknown` after the association stage.
The stage does not emit Findings, permissions, risk scores, or CI blocking
decisions.

## Security boundary

P2-08 never:

- executes `SKILL.md`, commands, hooks, plugins, or MCP processes;
- connects to MCP endpoints or performs network access;
- reads environment-variable values or static secret/header values;
- enumerates runtime MCP tools;
- evaluates `.rules` decisions;
- treats a declaration as active runtime capability;
- derives permissions, controls, runtime identities, or risk Findings;
- imports scanned project code or calls an LLM.

Deterministic rules remain the owner of formal security decisions. Future LLM
analysis may add evidence, but cannot authorize a declaration.

## Version impact

No Manifest fields or enum values are added. `AGENT_MANIFEST_SCHEMA_VERSION`
therefore remains `0.3.0`. This ADR records the semantic activation of the
existing `ManifestTool`, `ManifestRelation`, and provenance fields without
changing the serialized schema shape.

## Consequences

### Positive

- The Manifest now exposes a deterministic, source-backed Skill/MCP/tool graph.
- Static execution and network potential are visible without starting anything.
- Field-level provenance makes findings explainable and reviewable.
- Runtime availability, permissions, and risk remain separate from declaration
  facts.
- Duplicate or colliding names fail closed or receive deterministic IDs.

### Negative

- The inventory cannot prove that a Skill or MCP tool is active at runtime.
- Tool side effects are conservative potential classifications, not complete
  semantic behavior analysis.
- MCP server configuration fields and approval modes remain for P2-09/P2-10
  extraction and must be re-read from the bounded parser result by later stages.
