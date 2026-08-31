# ADR-0023: Deterministic Instruction Inheritance and Override Resolver

- Status: Accepted
- Date: 2026-08-20
- Task: P2-06

## Context

P2-04 discovers Codex instruction candidates from the explicit user and project
scopes. P2-05 records those candidates in Agent Manifest Schema 0.1.0 but
intentionally does not select the final instruction sources.

The next stage needs to answer which instruction files are effective without
reading or executing their Markdown content. The result must preserve the
root-to-working-directory chain, user/project ordering, same-directory
Override behavior, incomplete Coverage, and an explanation of why each
candidate was selected or superseded.

A single sorted `effective_sources` tuple is insufficient to express application
order: portable locator sorting is not the same as inheritance order when user
and project sources are both present. It also loses the base file that an
Override replaced. These are security-review facts, not merely presentation
metadata.

## Decision

### Resolver interface

1. Add a deep `InstructionResolver` module with one public behavior method:

```python
resolved_manifest = InstructionResolver().resolve(manifest)
```

2. The Resolver consumes only a validated `AgentManifest`; it performs no
   filesystem reads and never needs instruction text.
3. Return a new validated immutable `AgentManifest`; do not mutate the input.

### Candidate slots

4. Group each `ManifestInstructionCandidate` into a slot:

```text
(source scope, source root_id, parent directory of the instruction path)
```

5. Validate the candidate filename before resolution:

```text
base     → AGENTS.md
override → AGENTS.override.md
```

6. For one slot:

```text
base only       → select base
override only    → select override
base + override → select override, mark base overridden
```

7. An ambiguous duplicate candidate for the same slot fails closed with a safe
   `InstructionResolutionError` and does not expose the candidate path.

### Inheritance order

8. Apply selected instruction sources in this order:

```text
User scope before Project scope
Within a scope/root: root directory before deeper directories
Ties: root_id, then portable directory order
```

9. Preserve the application order in `effective_order`.
10. Keep `effective_sources` as a canonical locator-sorted set for stable set-like
    comparison and serialization.
11. Keep every base source replaced by an Override in `overridden_sources`.
12. Keep one `resolution_trace` step for every candidate, including action,
    reason, precedence rank, and a safe chain key.

### Status and Coverage

13. With at least one candidate and complete Framework Coverage, set:

```text
resolution = resolved
```

14. With at least one candidate and incomplete Framework Coverage, resolve the
    visible safe subset but set:

```text
resolution = partial
```

15. If no instruction candidates exist, preserve `unknown`; absence of a
    supported file is not proof that no instructions exist elsewhere.
16. If any candidate slot is ambiguous, fail closed:

```text
resolution = conflict
effective_sources = empty
effective_order = empty
```

The trace remains available so the caller can diagnose the conflict without
mistaking partial output for an effective instruction set.

### Version impact

17. Increment:

```text
AGENT_MANIFEST_SCHEMA_VERSION: 0.1.0 → 0.2.0
```

because the Manifest gains required resolution provenance fields:

```text
effective_order
overridden_sources
resolution_trace
```

18. Keep Package, Domain, Baseline, Diff, Assessment, Rule Pack, and Risk Model
    versions unchanged.

### Security boundary

19. Never read, concatenate, render, execute, or send instruction content to an
    LLM.
20. Never execute a command, Skill, Rule, Hook, Plugin, or MCP declaration while
    resolving instructions.
21. Never convert an effective instruction source into a risk Finding. This
    Resolver only supplies provenance to later analysis.
22. Do not infer that selected instructions are safe, authorized, or available at
    runtime.

## Consequences

### Positive

- Effective instruction source selection is deterministic and explainable.
- Same-directory Override behavior is explicit and does not erase inherited
  sources from other directories.
- User/project and root-to-working-directory order is preserved separately from
  canonical serialization order.
- Incomplete Coverage remains visible through `partial` rather than being
  presented as a complete result.
- Conflicting or malformed candidates fail closed.
- No instruction content crosses the Resolver seam.

### Negative

- The Resolver cannot determine semantic conflicts inside Markdown text; that
  remains outside P2-06.
- `unknown` with no candidates remains deliberately conservative and may require
  later framework-specific discovery.
- Manifest Schema 0.1.0 payloads are not accepted by the current pre-1.0
  0.2.0 reader without an explicit migration/rebuild.
