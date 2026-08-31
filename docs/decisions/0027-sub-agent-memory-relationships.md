# ADR-0027: Sub-Agent and Memory Relationships

- Status: Accepted
- Date: 2026-08-20
- Task: P2-10
- Agent Manifest Schema: `0.3.0` (unchanged)

## Context

P2-08 creates Skill/MCP/tool relationships and P2-09 creates static permission,
control, and runtime identity facts. The remaining relationship vocabulary in
the existing Manifest is:

```text
delegates_to
reads_memory
writes_memory
persists_memory
```

Free-form Markdown prose, links, and filenames are too ambiguous to become
relationship facts. The first deterministic implementation therefore needs an
explicit declaration contract that is safe to parse and easy for a Framework
Adapter to extend later.

## Decision

### 1. Explicit frontmatter-only contract

`RelationshipExtractor` consumes valid Markdown frontmatter fields only. It does
not infer relationships from paragraphs, headings, link labels, or relative
paths, and it never dereferences a declared target.

Supported top-level delegation fields:

```yaml
delegate_to: <string | list[string]>
delegates_to: <string | list[string]>
sub_agent: <string | list[string]>
sub_agents: <string | list[string]>
subagent: <string | list[string]>
subagents: <string | list[string]>
```

Supported top-level memory fields:

```yaml
memory_read: <string | list[string]>
memory_reads: <string | list[string]>
reads_memory: <string | list[string]>
memory_write: <string | list[string]>
memory_writes: <string | list[string]>
writes_memory: <string | list[string]>
memory_persist: <string | list[string]>
memory_persists: <string | list[string]>
persists_memory: <string | list[string]>
persistent_memory: <string | list[string]>
```

A compact nested form is also supported:

```yaml
memory:
  read: session
  write: scratch
  persist: long-term
```

Unknown nested `memory` keys are ignored as relationship declarations but the
presence of an unsupported/invalid recognized field makes the profile partial.

### 2. Relationship semantics

Each valid string declaration produces a `ManifestRelation` with:

```text
source_agent_id = current Manifest Agent ID
state           = declared
sources         = frontmatter field path and source line range
```

The mapping is:

```text
delegation fields → delegates_to
read fields       → reads_memory
write fields      → writes_memory
persist fields    → persists_memory
```

A repeated logical relation from different fields or Markdown assets is merged
into one relation with multiple source references. Existing P2-08 Skill/MCP/tool
relations are retained.

### 3. Target identity and redaction boundary

Target IDs use bounded prefixes:

```text
agent:<safe-id>
memory:<safe-id>
```

Only a strict ASCII identifier component is retained as readable metadata. Paths,
URLs, control characters, whitespace, oversized values, and other unsafe target
strings become a deterministic short hash:

```text
agent:unknown:<sha256-prefix>
memory:unknown:<sha256-prefix>
```

Unsafe or structurally invalid values create `state=unknown` relations rather
than being silently discarded. Raw target values are never serialized.

### 4. Malformed and incomplete declarations

A malformed frontmatter region is treated as possible missed relationship
configuration and makes the relationship profile `partial`. A recognized field
with an unsupported value also produces an `unknown` relation and `partial`
status. No relationship is marked `active`; static declaration is not runtime
execution or persistence proof.

### 5. Source declaration scope

The Builder's relationship declaration sources include Markdown instruction,
Override, and Skill assets, as well as the existing MCP sources. This allows
P2-10 to consume frontmatter in `AGENTS.md`, `AGENTS.override.md`, and `SKILL.md`
without changing the Manifest shape.

## Security boundary

P2-10 never:

- executes a Sub-Agent, Skill, command, hook, or plugin;
- opens or follows a relative path;
- connects to URLs or MCP servers;
- reads memory stores or environment values;
- imports scanned project code;
- treats a relation as runtime activation, authorization, or persistence proof;
- calls an LLM or emits risk/CI decisions.

## Version impact

P2-10 populates existing `ManifestRelation` and
`ManifestRelationshipProfile` fields. No serialized field or enum is added:

```text
AGENT_MANIFEST_SCHEMA_VERSION = 0.3.0
```

remains unchanged.

## Consequences

### Positive

- Delegation and memory edges become deterministic and source-traceable.
- Free-form Markdown is not over-interpreted.
- Unsafe target values cannot leak into the Manifest.
- Duplicate declarations retain all provenance without duplicate graph edges.
- The contract is explicit enough for later Framework-specific adapters.

### Negative

- Relationships declared only in prose are not detected in P2-10.
- An `unknown` relation target cannot be displayed by its original value.
- Runtime Sub-Agent scheduling and memory persistence remain unverified.
- A later phase is needed for systematic Unknown records and Capability Diff.
