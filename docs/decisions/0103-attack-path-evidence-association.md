# ADR-0103: Attack Path Evidence Association

- Date: 2026-08-31
- Status: Accepted
- Scope: P3-AG-05

## Decision

Introduce a deterministic, read-only association layer that correlates static
Attack Graph paths with existing Finding Evidence and trusted Shadow Semantic
Evidence using only:

- normalized relative asset path;
- content SHA-256;
- overlapping line ranges;
- trusted Semantic Evidence IDs supplied separately from model output.

The layer emits a content-addressed report with explicit `duplicates`,
`supports`, `partially_supports`, and `unmatched` relations. It keeps graph
node/edge provenance roles and value-free target locators, but never copies raw
source text or Finding excerpts.

## Context

P3-AG-04 deliberately reports paths without source details, Severity, or
Finding identity. P3-AG-05 needs to make a path reviewable alongside the
scanner's deterministic Findings and Shadow semantic candidates while keeping
the authority boundary intact.

Existing Findings and Semantic Results are immutable validated objects. Their
Evidence can be correlated, but a path is not itself a Finding and a semantic
candidate is not an authorization input.

## Alternatives rejected

1. **String or category matching** — can produce false links and is not bound to
   the actual asset revision.
2. **Path/node ID supplied by the model** — allows untrusted output to invent
   graph provenance.
3. **Copying excerpts into the association report** — increases secret and
   sensitive-data exposure without improving identity binding.
4. **Mutating Findings or severity** — violates the deterministic Rule and
   reviewed Policy ownership of decisions.
5. **Runtime validation in the associator** — out of scope; runtime reachability
   and exploitability remain `not_proven`.

## Consequences

### Positive

- Same inputs yield byte-identical association output.
- Reviewers can trace a matched path to deterministic and semantic Evidence
  locators without opening a second untrusted data channel.
- Partial and missing Evidence remain visible instead of being silently
  promoted to exact matches.
- Input digests make report provenance auditable.

### Limitations

- The association cannot prove runtime reachability or exploitability.
- Findings with configuration-only or runtime-only Evidence are not eligible
  for static path matching.
- A CLI and end-to-end artifact ingestion surface are deferred to a follow-up
  task; the Python API is the frozen source of truth for this task.
- Existing builder gaps for `writes_to` and `installs` remain outside this ADR.

## Security invariants

```text
report_only=true
blocks=false
finding_authority=false
semantic_authority=false
policy_authority=false
ci_authority=false
hard_gate_authority=false
release_authority=false
runtime_verified=false
no source excerpts or secret values in output
no Finding/Semantic Candidate mutation
```
