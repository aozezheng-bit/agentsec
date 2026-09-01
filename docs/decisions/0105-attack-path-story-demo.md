# ADR-0105: Attack Path Story Demo

- Date: 2026-08-31
- Status: Accepted
- Scope: P3-AG-07

## Decision

Maintain a dedicated inert Homi-like fixture and a repeatable story runner for
Attack Path Evidence association. The runner uses the production CLI and emits
both machine-readable and presenter-readable artifacts. It reduces the full
static graph to one selected path for narration while preserving the original
validated graph construction and association implementation.

The story demonstrates three different correlation results:

```text
Finding             → partially_supports
Semantic Candidate  → duplicates
Unrelated Candidate → unmatched
```

## Rationale

A complete real workspace can produce many path/Finding combinations that are
useful for tests but too noisy for a live explanation. A bounded story slice
makes the security boundary and Evidence semantics understandable to
developers and management while leaving the full graph available in the
`graph.json` artifact.

## Safety

The fixture contains only text/configuration. The runner invokes no target
scripts, Skills, Hooks, MCP servers, network services, or real Providers. The
association output is report-only and never changes Finding, Severity,
Confidence, Policy, CI, Hard Gate, release, runtime, or exploitability state.

## Consequences

- The Demo can run offline and in a clean local checkout.
- Artifact hashes and strict Schemas make the presentation reproducible.
- The selected path is illustrative, not a coverage or quality qualification
  sample.
- Attack Path calibration and larger corpus evaluation remain separate tasks.
