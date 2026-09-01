# ADR-0103: Batch Shadow Mode Pipeline With Non-Blocking Case Recording

- Status: Accepted
- Date: 2026-08-31
- Task: P3-16
- Scope: P3-16 Shadow Mode pipeline (batch, non-blocking, record-only)

## Context

The Phase 3 plan (P3-16) requires "实现 Shadow Mode：LLM 不阻断，只记录".
P3-08 already delivered the single-input `SemanticShadowPipeline`
(verified Shadow invocation → trusted Finding links → review-required Rule
Candidates → one digest-bound aggregate report), and P3-14/P3-15 deliver
paired-corpus detection metrics and replay comparability. What is still
missing for "Shadow Mode" is the batch behavior the plan names: a mode of
operation that runs a whole set of semantic inputs through the Shadow
pipeline, records every result, and provably never blocks or mutates
anything — neither the deterministic scan it shadows nor any decision
path.

Three gaps separate P3-16 from P3-08:

1. **Batch scope.** P3-08 handles exactly one input per call; Shadow Mode
   runs collections (up to 256 cases) in one immutable aggregate record.
2. **Non-blocking failure semantics.** A case whose Shadow invocation
   fails with a P3-02 stable error code must become a recorded `failed`
   row while the batch continues — Shadow Mode must never interrupt the
   host workflow. Structural or type defects are not stable Provider
   failures and still fail closed.
3. **Aggregate evidence shape.** Batch rows are value-free (analysis id,
   child pipeline digest, stable error code, count summaries) with an
   aggregate digest binding, mirroring the P3-08/P3-09 child-hash
   pattern at batch scale.

## Decision

Add `agentsec.semantic.shadow_mode` with the versioned
`agentsec-p3-16-semantic-shadow-mode-report` family
(`SEMANTIC_SHADOW_MODE_VERSION` /
`SEMANTIC_SHADOW_MODE_OUTPUT_VERSION` = `0.1.0`, report-family
classification, frozen Schema export under `schemas/semantic-analysis/`):

1. **Runner.** `SemanticShadowModeRunner().run_cases(cases,
   adapter=...)` accepts up to 256 `ShadowModeCase` entries (a semantic
   input plus optional per-case Finding/evidence context, following the
   P3-08 `run` seam). It reuses the P3-05/P3-08
   `SemanticShadowPipeline` for each case — either a caller-supplied
   pipeline or a default one built from the given Shadow adapter — so no
   Shadow logic is duplicated.

2. **Non-blocking case recording.** `SemanticShadowInvocationError`
   (P3-02 stable codes only) is caught per case, producing a `failed`
   row with `error_code` and zero child digest; the batch continues.
   Wrong types, invalid inputs, duplicate analysis IDs, bound violations,
   or a missing pipeline/adapter raise stable `ShadowModeError` codes and
   abort the batch — contract defects are not Provider failures.

3. **Aggregate report.** `SemanticShadowModeReport` records sorted-unique
   per-case rows (status, child `pipeline_sha256`, error code,
   candidate/link/proposal counts), aggregate counts cross-checked
   against the rows, and a `shadow_mode_sha256` digest over the canonical
   row payloads. Rows are value-free: no corpus text, model summaries, or
   raw payloads survive in the aggregate.

4. **Frozen non-blocking authority.** The report fixes
   `operating_mode="shadow_only"`, `blocks=false`,
   `deterministic_decisions_affected=false` and the usual
   finding/rule-publication/severity/policy/ci/runtime-false literals at
   report level. Deterministic decisions, Findings, Rules, Policies, CI
   gates, and releases are never changed by a Shadow Mode run; the batch
   only adds recorded evidence for human review.

Determinism: identical cases, adapter, and pipeline produce
byte-identical report JSON (child digests plus ordered rows; no
timestamps).

## Consequences

- P3-17 (human feedback loop) and P3-02x rule-evolution work can consume
  batch Shadow runs as first-class, digest-auditable evidence artifacts.
- The runner deliberately composes existing seams (P3-05 adapter,
  P3-08 pipeline, P3-06 Finding integration); any future change to those
  contracts versions through their own ADRs, and this report family only
  versions the batch wrapper.
- A CLI command and persisted Shadow Mode run archive are intentionally
  out of scope until evaluation evidence from P3-17+ requests them.
- The next ADR number is 0104.
