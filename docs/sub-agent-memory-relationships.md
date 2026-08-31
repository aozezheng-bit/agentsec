# AgentSec Sub-Agent and Memory Relationships

- Task: `P2-10`
- Status: Complete
- Agent Manifest Schema: `0.3.0`
- Decision: `docs/decisions/0027-sub-agent-memory-relationships.md`

## 1. Purpose

`RelationshipExtractor` adds explicit Sub-Agent and memory edges to the existing
Manifest relationship graph.

```python
from agentsec.manifests import RelationshipExtractor

relationship_manifest = RelationshipExtractor().extract(manifest, inspection)
```

The input Manifest remains immutable. The extractor returns a new validated
Manifest and retains existing P2-08 Skill/MCP/tool relations.

## 2. Declaration contract

P2-10 reads valid Markdown frontmatter only. It supports:

```yaml
delegates_to: [research, writer]
memory:
  read: session
  write: scratch
  persist: long-term
```

Equivalent top-level delegation aliases include `delegate_to`, `sub_agent`,
`sub_agents`, `subagent`, and `subagents`. Equivalent memory aliases include
`memory_read`, `reads_memory`, `memory_write`, `writes_memory`,
`memory_persist`, `persists_memory`, and `persistent_memory`.

The following are deliberately not relationship evidence:

```text
paragraph prose
heading names
Markdown link labels
relative paths without an explicit frontmatter declaration
Skill text describing a possible future action
```

## 3. Relationship mapping

| Declaration | Relation kind |
|---|---|
| delegation field | `delegates_to` |
| read memory field | `reads_memory` |
| write memory field | `writes_memory` |
| persist memory field | `persists_memory` |

All recognized valid declarations use:

```text
state = declared
source_agent_id = Manifest identity.agent_id
```

P2-10 never uses `active` because no runtime verification is performed.

## 4. Target IDs

Safe identifier values become bounded IDs:

```text
agent:research
memory:session
memory:long_term
```

Unsafe values such as paths, URLs, whitespace-containing strings, control
characters, or oversized values become deterministic hashed IDs:

```text
agent:unknown:<sha256-prefix>
memory:unknown:<sha256-prefix>
```

The corresponding relation state is `unknown`, and the profile becomes
`partial`. The original target value is not serialized.

## 5. Provenance and merging

Each relation source includes:

```text
portable source locator
frontmatter field path
1-based start line
1-based end line
```

For a list declaration, the extractor adds an index to the field path:

```text
$.frontmatter.sub_agents[0]
$.frontmatter.memory.read[0]
```

The same logical relation declared in multiple fields or assets is merged into
one graph edge with all unique, deterministically sorted source references.

## 6. Resolution status

| Condition | Relationship status |
|---|---|
| no relationship declaration sources | preserve `unknown` |
| no explicit P2-10 declaration, existing P2-08 relations | preserve existing status |
| valid declarations and complete Coverage | `resolved` |
| malformed/unsupported/unsafe declaration | `partial` |
| unsafe target value | relation `unknown`, profile `partial` |

An unknown relation is evidence that a declaration existed but its target could
not be safely normalized. It is not evidence that the target is absent.

## 7. Security boundary

The extractor performs no:

```text
filesystem reread
path dereference
Sub-Agent execution
Skill or command execution
MCP launch or connection
memory-store read/write
environment lookup
scanned-code import
LLM call
```

P2-10 does not produce risk Findings, CI blocking decisions, runtime attestation,
or Capability Diff output. P2-11 owns systematic Unknown and later Diff
integration.
