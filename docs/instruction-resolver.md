# AgentSec Instruction Inheritance / Override Resolver

- Task: `P2-06`
- Status: Complete
- Manifest Schema version: `0.2.0`
- Decision: `docs/decisions/0023-instruction-inheritance-override-resolver.md`

## 1. Purpose

The Resolver converts the Agent Manifest's instruction candidates into an
explainable final source selection. It does not read Markdown content and does
not decide whether the instructions themselves are safe.

```python
from agentsec.manifests import InstructionResolver

resolved_manifest = InstructionResolver().resolve(manifest)
```

The input Manifest is not mutated. The returned Manifest is a newly validated
immutable value.

## 2. Candidate slot

A candidate slot is:

```text
source scope + source root_id + parent directory
```

Examples:

```text
(project, project, "")       → project/AGENTS.md
(project, project, "service") → project/service/AGENTS.md
(user, codex_home, "")       → codex_home/AGENTS.md
```

The Resolver validates the filename/kind contract:

```text
base     → AGENTS.md
override → AGENTS.override.md
```

Invalid candidate shape produces `InstructionResolutionError` with a fixed safe
message.

## 3. Same-directory selection

| Candidates in one slot | Decision |
|---|---|
| Base only | Select Base |
| Override only | Select Override |
| Base and Override | Select Override; Base is `overridden` |
| Duplicate same-kind candidates | Fail closed |

An Override replaces only the Base candidate in the same slot. It does not erase
an inherited Base or Override from the project root or another directory.

## 4. Inheritance order

Selected candidates are applied in this order:

```text
1. User scope before Project scope
2. Root directory before nested directories
3. Stable root_id and portable directory tie-breakers
```

For example:

```text
user AGENTS.md
project AGENTS.md
project/service AGENTS.md
```

`effective_order` preserves this application order.

`effective_sources` remains canonical locator order for deterministic set-like
serialization and comparison. Consumers that need inheritance order must use
`effective_order`, not sort `effective_sources` themselves.

## 5. Resolution fields

The `instructions` profile contains:

```text
candidates
resolution
effective_sources
effective_order
overridden_sources
resolution_trace
```

### `effective_sources`

Canonical, unique, locator-sorted selected sources.

### `effective_order`

Unique selected sources in actual inheritance/application order.

### `overridden_sources`

Base source references replaced by a same-slot Override.

### `resolution_trace`

One entry per candidate:

```text
source
action: selected | overridden | conflict
reason: only_candidate | inherited | override_replaces_base | ambiguous_duplicate
precedence_rank
chain_key
```

The trace never includes source text.

## 6. Status mapping

| Condition | `instructions.resolution` |
|---|---|
| Candidates and complete Coverage | `resolved` |
| Candidates and incomplete Coverage | `partial` |
| No candidates | `unknown` |
| Ambiguous candidate slot | `conflict` |

For `conflict`, both effective source fields are empty. This prevents a partial
selection from being mistaken for an authorized final instruction set.

## 7. Coverage behavior

The Resolver never hides Framework Coverage. If the Adapter skipped an asset or
reported a discovery gap, selected visible candidates may still be returned,
but the instruction profile is `partial`.

Coverage remains separate from instruction semantics and is not converted into a
Finding, Severity, permission, or authorization decision.

## 8. Security guarantees

P2-06 does not:

- read source files;
- concatenate or interpret Markdown;
- execute instructions or code blocks;
- load Skills, Hooks, Plugins, or Rules;
- run MCP commands or connect to MCP;
- read environment values;
- perform network access;
- call an LLM;
- infer runtime capability;
- assign security risk.

## 9. Schema and versioning

The Resolver adds these Manifest fields:

```text
effective_order
overridden_sources
resolution_trace
```

Therefore:

```text
AGENT_MANIFEST_SCHEMA_VERSION = 0.3.0
```

The change is recorded in ADR-0023. Phase 1 Domain, Baseline, Diff,
Assessment, Rule Pack, and Risk Model versions do not change.

## 10. Next step

P2-07 now consumes the resolved instruction and Adapter source model through a
separate `ConfigurationResolver` to implement source-level Agent-local
configuration precedence. It keeps instruction resolution and configuration
resolution as separate explainable operations.
