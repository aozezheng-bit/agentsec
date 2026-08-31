# AgentSec Agent Manifest Schema

- Task: `P2-05`, extended by `P2-06`
- Status: Complete
- Schema version: `0.3.0`
- Decision date: 2026-08-20
- Decisions: `docs/decisions/0022-agent-manifest-schema.md`,
  `docs/decisions/0023-instruction-inheritance-override-resolver.md`

## 1. Purpose

The Agent Manifest is AgentSec's framework-neutral, deterministic declaration
inventory. It separates Framework Adapter parsing from later inheritance,
capability, permission, identity, relationship, Diff, and risk processing.

The schema is currently `0.2.0`; P2-06 extends the P2-05 source-only schema
with deterministic instruction-resolution provenance.

It answers:

1. Which portable control assets were inspected?
2. Which instruction sources are candidates for effective resolution?
3. Which sources may declare tools, permissions, controls, runtime identities,
   and relationships?
4. Which dimensions are resolved, unresolved, partial, conflicting, not
   applicable, or unknown?
5. Was source inspection complete?

The Manifest does not claim that a declared capability is active or available at
runtime.

## 2. Independent version

```python
AGENT_MANIFEST_SCHEMA_VERSION = "0.3.0"
```

This is independent from:

```text
Domain Schema
Baseline Schema
Diff Output
Assessment Output
Rule Pack
Risk Model
```

Pre-1.0 readers accept only the same major and minor version.

## 3. Build from Framework inspection

```python
from agentsec.frameworks import CodexAdapter, FrameworkInspectionRequest
from agentsec.manifests import AgentManifestBuilder

inspection = CodexAdapter().inspect(
    FrameworkInspectionRequest(
        project_root=project_root,
        working_directory=working_directory,
        user_home=user_home,
    )
)

manifest = AgentManifestBuilder().build(
    inspection,
    agent_id="release-agent",  # optional trusted stable ID
)
```

When `agent_id` is omitted, the current builder uses a safe deterministic local
identity derived from Framework ID and subject root ID, such as:

```text
codex:project
```

This identity is local to the Manifest context. Systems aggregating multiple
projects should supply their own trusted stable ID.

## 4. Top-level structure

```text
AgentManifest
├── schema_version
├── metadata
├── identity
├── sources
├── instructions
├── tools
├── permissions
├── controls
├── runtime_identities
├── relationships
├── unknowns
└── coverage
```

Every object is immutable and rejects unknown fields.

## 5. Metadata and subject identity

Metadata contains:

```text
scanner_version
framework_id
framework_display_name
adapter_version
deterministic
```

Subject identity contains:

```text
agent_id
subject_scope
subject_root_id
declared_name
resolution
sources
```

Subject identity describes which logical Agent the Manifest represents. It is
not the operating-system user, service account, OAuth session, API key, or
production principal. Those belong to `runtime_identities`.

P2-05 knows the Framework and project subject but does not yet resolve a declared
Agent name, so the Builder emits `identity.resolution=partial`.

## 6. Source inventory

Each `ManifestSource` contains only:

```text
portable locator: scope + root_id + relative path
format
sorted neutral roles
content SHA-256
byte count
line count
precedence rank
```

It does not contain source text or structured scalar values.

A `ManifestSourceReference` can identify:

```text
whole source asset
optional normalized field path
optional 1-based inclusive line range
```

Every source reference must resolve to a top-level source. A line range cannot
exceed the source line count.

## 7. Resolution status

| Status | Meaning |
|---|---|
| `unresolved` | Relevant declarations exist, but the owning Resolver/Extractor has not selected final facts |
| `partial` | Some facts are normalized, while relevant facts remain unresolved |
| `resolved` | The supported deterministic scope has been resolved |
| `unknown` | Available evidence is insufficient; this does not mean absent or safe |
| `not_applicable` | The dimension is explicitly outside the subject's supported model |
| `conflict` | Multiple incompatible declarations remain unresolved |

An unresolved profile must retain its declaration sources. An unknown profile
cannot contain hidden declaration sources or resolved items.

## 8. Instructions

P2-05 creates `ManifestInstructionCandidate` records for:

```text
AGENTS.md          → base
AGENTS.override.md → override
```

Each candidate contains a whole-source reference and the Adapter precedence
rank. P2-05 does not select an effective source.

P2-06 populates:

```text
instructions.resolution
effective_sources
effective_order
overridden_sources
resolution_trace
```

P2-07 adds the required `configuration` profile with source-level Framework,
Rules, and MCP candidates. It preserves configuration `effective_sources`,
`effective_order`, and `resolution_trace`; field-level value merging remains
outside the current Manifest Schema boundary.

## 9. Tools

The Schema defines `ManifestTool` with:

```text
tool_id
name
kind
availability
side_effects
optional parent_tool_id
sources
```

Supported tool kinds include Skill, MCP Server, MCP Tool, Command, Builtin,
Plugin, and Other. Side-effect vocabulary covers read, write, execute, network,
destructive, secret access, privileged, and unknown.

P2-05 only records Skill and MCP declaration sources. P2-08 creates concrete tool
items and associations. Skill and MCP tool items remain static declaration facts,
not runtime authorization or availability proofs.

## 10. Permissions

`ManifestPermission` contains:

```text
permission_id
action
effect
resource
scope
optional target
sources
```

Actions include read, write, execute, network, secret access, admin, deploy,
publish, delegate, persist, and unknown. Effects are allow, prompt, deny, or
unknown.

P2-05 records Rules and configuration declaration sources. P2-09 performs
permission extraction and classification.

## 11. Controls

`ManifestControl` represents approval and guardrail facts:

```text
human approval
sandbox
prefix rule
trust
tool filter
timeout
network policy
secret handling
enablement
required state
other
```

Control state includes enabled, disabled, required, optional, allow, prompt,
deny, configured, and unknown.

P2-05 does not interpret individual controls; it retains their possible source
assets for P2-07/P2-09. P2-08 associates MCP tool filters but does not turn
approval modes into controls.

## 12. Runtime identities

`ManifestRuntimeIdentity` is credential-free. It can represent:

```text
principal kind
authentication kind
operational environment
optional privileged state
sources
```

It never stores API keys, tokens, passwords, OAuth tokens, cookies, static
headers, or environment-variable values.

P2-09 populates runtime identity facts.

## 13. Relationships

`ManifestRelation` supports:

```text
delegates_to
uses_skill
uses_mcp
uses_tool
reads_memory
writes_memory
persists_memory
other
```

Each relationship has a stable ID, source Agent ID, target ID, state, and source
provenance. P2-08 populates `uses_skill`, `uses_mcp`, and `uses_tool` facts with
`declared` state; P2-10 owns delegation and memory relationships.

## 14. Unknowns

`UnknownExtractor` now materializes stable unresolved facts into the existing
`ManifestUnknown` field without changing the Manifest structure.

Unknown dimensions cover identity, instructions, tools, permissions, controls,
runtime identities, relationships, and Coverage. Reasons include:

```text
not_analyzed
missing_source
incomplete_coverage
unsupported_field
ambiguous_precedence
conflicting_declarations
runtime_verification_required
```

P2-05 leaves the explicit `unknowns` tuple empty. P2-11 maps unresolved,
unknown, partial, and conflicting profile states plus item-level unknown values
into deterministic entries. Runtime `privileged=null` is retained as
`runtime_verification_required`; incomplete Coverage receives an explicit
Coverage Unknown. Extraction is idempotent.

## 15. Coverage

Manifest Coverage preserves:

```text
discovered_assets
inspected_assets
skipped_assets
complete
issues
```

The invariant is:

```text
inspected_assets + skipped_assets = discovered_assets
```

A complete Manifest source inventory has no skipped assets and no Issues.
Coverage is not a permission, Finding, Severity, or risk score.

## 16. JSON and Schema interfaces

```python
from agentsec.manifests import (
    decode_agent_manifest_json,
    encode_agent_manifest_json,
    export_agent_manifest_json_schema,
    validate_agent_manifest_payload,
)
```

Encoding is deterministic:

```text
UTF-8 Unicode
sorted JSON keys
two-space indentation
one trailing newline
```

Validation checks compatibility before the remaining payload and exposes only
safe error codes and field paths.

The Schema exporter writes:

```text
agent-manifest.schema.json
```

with:

```text
$schema=https://json-schema.org/draft/2020-12/schema
x-agentsec-agent-manifest-schema-version=0.3.0
```

## 17. P2-05 Builder output

The initial Builder performs only:

```text
Framework source metadata normalization
Framework Coverage normalization
base/Override instruction candidate creation
future dimension declaration-source selection
explicit unresolved/unknown statuses
```

It intentionally does not read or copy Parser values. Therefore AGENTS text,
Skill instructions, Rules literals, MCP commands, arguments, URLs, environment
values, and arbitrary TOML scalars do not appear in the Manifest.

## 18. P2-06 instruction resolution

`InstructionResolver` groups Base and Override candidates by source scope, root,
and parent directory. It applies User sources before Project sources and root
directories before deeper directories. A same-directory Override replaces only
that directory’s Base candidate.

The Resolver preserves both canonical and semantic order:

```text
effective_sources → canonical locator order
effective_order   → inheritance/application order
overridden_sources → Base sources replaced by Override
resolution_trace  → one safe decision per candidate
```

Complete Coverage produces `resolved`; incomplete Coverage produces `partial`.
No candidates remain `unknown`. Ambiguous candidate slots fail closed as
`conflict` with no effective source selection. No source text is read or copied.

See `docs/instruction-resolver.md` and ADR-0023.

## 19. P2-07 configuration precedence

The `configuration` profile is a source-level precedence model. It contains:

```text
candidates
effective_sources
effective_order
resolution_trace
```

Candidates are typed as `framework_config`, `prefix_rules`, or `mcp_config` and
retain source, rank, and portable chain key. The Resolver orders all visible
sources rather than replacing a complete lower-precedence file, because
field-level merge semantics are not yet available.

See `docs/configuration-precedence-resolver.md` and ADR-0024.

## 20. P2-08 Skill / MCP / Tool Association

`AssociationExtractor` consumes the same `FrameworkInspectionResult` used by the
Builder and verifies portable source metadata before creating facts. It adds:

```text
Skill tools and uses_skill relationships
MCP server tools and uses_mcp relationships
MCP filter/policy tools and uses_tool relationships
field-path and line-range provenance
static stdio=execute / HTTP=network / bundled=unknown side-effect facts
```

All relationship states are `declared`, never `active`, because the extractor
performs no runtime verification. Skill Markdown, commands, arguments, endpoint
values, header values, environment values, and arbitrary structured values are
not copied into the Manifest. Tool filters and approval policies are not yet
permissions or controls.

Complete Coverage produces resolved tool and relationship profiles; incomplete
Coverage produces partial profiles. Collision-safe stable IDs remain bounded and
portable. P2-08 keeps `AGENT_MANIFEST_SCHEMA_VERSION = 0.3.0` because no fields or
enum values were added. See `docs/skill-mcp-tool-association.md` and ADR-0025.

## 21. P2-09 Static Permission, Control, and Runtime Identity Extraction

`CapabilityExtractor` consumes the P2-08 associated Manifest and the same
parser-coherent inspection result to populate existing permission, control, and
runtime identity profiles. It adds:

```text
static side-effect → permission action/resource/scope
.rules decision → explicit allow/prompt/deny permission and Prefix Rule control
MCP enablement/required/approval/filter/timeout/network/secret controls
credential-free MCP runtime identity hypothesis
```

Permission effects remain `unknown` for inferred Tool side effects. A disabled
Tool is not rewritten into a permission `deny`; availability and permission
effect remain separate dimensions. Remote HTTP endpoints use
`resource_scope=external`; local endpoints remain `unknown` rather than being
mistaken for a project authorization boundary.

MCP OAuth, ChatGPT, bearer/environment references, transport, and sanitized
endpoint locality are mapped to runtime identity kinds. No token, header value,
environment value, command, URL query, or Rules pattern is copied. Every output
retains source provenance. Complete Coverage with no uncertainty produces
`resolved`; incomplete Coverage or unknown/unsupported facts produce `partial`.

P2-09 keeps `AGENT_MANIFEST_SCHEMA_VERSION = 0.3.0` because no serialized fields
or enum values were added. See `docs/static-capability-profile.md` and ADR-0026.

## 22. P2-10 Sub-Agent and Memory Relationships

`RelationshipExtractor` consumes valid Markdown frontmatter declarations and
adds `delegates_to`, `reads_memory`, `writes_memory`, and `persists_memory` edges
to the existing relationship graph. It preserves P2-08 Skill/MCP/tool edges.

Only explicit declaration fields are recognized; free-form prose, headings,
Markdown links, and paths are not dereferenced or inferred. Valid relations use
`declared` state and exact frontmatter field/line provenance. Repeated logical
edges merge their sources. Unsafe or unsupported values create bounded hashed
`unknown` targets and make the profile `partial`; raw target values never enter
the Manifest. Malformed frontmatter is retained as uncertainty.

P2-10 keeps `AGENT_MANIFEST_SCHEMA_VERSION = 0.3.0`. See
`docs/sub-agent-memory-relationships.md` and ADR-0027.

## 23. P2-11 Explicit Unknowns and Capability Diff

`UnknownExtractor` adds deterministic `ManifestUnknown` entries for profile
resolution gaps, unknown item fields, runtime verification requirements, and
incomplete Coverage. It does not change the underlying resolution states and is
idempotent.

`CapabilityDiffer` compares Tools, Permissions, Controls, Runtime Identities,
Relationships, Unknowns, profile resolution states, and Coverage state for the
same Agent/Framework. Changes are `added`, `removed`, or `modified` and contain
only stable item IDs, trusted changed-field names, before/after SHA-256
fingerprints, and source references. Complete item payloads are not copied into
the Diff.

Capability Diff has a new independent interface:

```text
CAPABILITY_DIFF_SCHEMA_VERSION = 0.1.0
```

with deterministic JSON, compatibility-first validation, safe field-path errors,
and Draft 2020-12 JSON Schema export. Agent Manifest Schema remains `0.3.0`;
Phase 1 `DIFF_OUTPUT_VERSION` remains `0.1.0` because the CLI output is not
changed. See `docs/manifest-unknowns-capability-diff.md` and ADR-0028.

## 24. Current boundary

P2-11 still does not:

- read source content during Unknown generation or Capability Diff;
- dereference paths, read memory stores, or access credentials/environment values;
- execute Sub-Agents, Skills, commands, hooks, plugins, Rules, or MCP;
- connect to MCP/network targets or enumerate runtime tools;
- turn Unknown/Diff into Risk Findings, Severity, or CI policy;
- integrate Capability Diff into the current CLI;
- call an LLM or perform runtime attestation.

Phase 2 now has a structurally complete static Manifest, explicit uncertainty,
and deterministic Capability Diff. Combination-risk rules, semantic/LLM
evidence, CLI presentation, and Demo integration remain later work.

## 25. Verification

P2-05 through P2-11 completion gate:

```text
Ruff passed
Ruff Format check passed: 142 files
Mypy strict passed: 141 source files
Pytest: 743 passed
P2-08 dedicated association tests: 5 passed
P2-09 dedicated capability tests: 2 passed
P2-10 dedicated relationship tests: 5 passed
P2-11 dedicated Unknown/Capability Diff tests: 5 passed
```

The existing Phase 1 `dist/` wheel, sdist, and frozen Schemas were not rebuilt.
