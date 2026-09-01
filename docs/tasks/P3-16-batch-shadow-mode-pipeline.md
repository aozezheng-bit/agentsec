# P3-16: Batch Shadow Mode Pipeline

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-05 (Shadow adapter), P3-08 (single-input pipeline),
  P3-14 (scenario corpus wiring used by tests); all complete
- Mode: static, report-only; no corpus execution; no network; no LLM
- Decision record: ADR-0103

## Objective

Implement the plan's Shadow Mode: run a whole batch of semantic inputs
through the Shadow pipeline, record every case, and never block or
mutate anything — "LLM 不阻断，只记录".

## Gap analysis versus P3-08

```text
P3-08 SemanticShadowPipeline   one input per call: invocation →
                               Finding links → Rule Candidates → digest
P3-16 SemanticShadowModeRunner batch (≤256 cases), per-case stable-failure
                               recording, aggregate digest, frozen
                               non-blocking authority booleans
```

No Shadow logic is duplicated: the runner composes the P3-05 adapter and
the P3-08 pipeline case by case.

## What was delivered

```text
agentsec.semantic.shadow_mode             ShadowModeCase,
                                           SemanticShadowModeRunner,
                                           SemanticShadowModeReport,
                                           encode_semantic_shadow_mode_json
schemas/semantic-analysis/
  semantic-shadow-mode-report.schema.json          frozen Schema export
provenance                                SEMANTIC_SHADOW_MODE_
                                          SCHEMA/OUTPUT_VERSION 0.1.0
scripts/export_release_schemas.py         export wiring
tests/test_semantic_p3_16.py              14 tests
docs/decisions/0103-batch-shadow-mode-pipeline.md
```

## Key behaviors

- `run_cases(cases, adapter=...)` runs up to 256 `ShadowModeCase` entries
  (semantic input + optional Finding/evidence context) through the
  P3-08 pipeline per case; a caller-provided pipeline or a
  default-from-adapter pipeline is used.
- Non-blocking: a case whose invocation raises a P3-02 stable
  `SemanticShadowInvocationError` becomes a `failed` row (`error_code`,
  zero child digest) and the batch continues; completed rows carry the
  child `pipeline_sha256`.
- Fail closed on contract defects: empty or non-tuple cases, wrong case
  type, duplicate analysis IDs, bound violation, missing pipeline, or
  an invalid adapter raise stable `ShadowModeError` codes.
- Value-free rows: analysis id, status, digests, error codes, and
  candidate/link/proposal count summaries only; aggregate
  `shadow_mode_sha256` binds the canonical row payloads; rows are
  sorted by analysis ID and unique.
- Frozen authority: `operating_mode="shadow_only"`, `blocks=false`,
  `deterministic_decisions_affected=false`, plus the semantic
  finding/rule/severity/policy/ci/runtime false literals.
- Deterministic and round-trippable: identical inputs give
  byte-identical JSON with no timestamps.

## Authority boundary

```text
blocks / deterministic_decisions_affected / finding_authority /
rule_publication_authority / severity_authority / policy_authority /
ci_authority / runtime_disclosure_allowed / runtime_verified   false
report_only / operating_mode                     true / shadow_only
```

A batch Shadow Mode run only adds recorded evidence for human review.
It never changes deterministic decisions, Findings, Rules, Policies, CI
gates, or releases, and it makes no model-quality or runtime claim.

## Verification

```bash
.venv/bin/python -m pytest tests/test_semantic_p3_16.py -q    # 14 passed
.venv/bin/python scripts/export_release_schemas.py            # schema frozen
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy src tests
.venv/bin/python -m pytest
```

## Limitations and follow-ups

- The batch bound is 256 cases; larger sets split across runs (each run
  is independently digest-bound).
- A CLI command and a persisted run archive (comparing new batches
  against stored reports) are out of scope until P3-17 feedback needs
  them.
- With no per-case Findings supplied, all links record as `unmatched`
  (P3-06 fail-closed semantics); this is correct Shadow behavior, not a
  gap.
- P3-17 (human feedback loops) was intentionally not started
  (single-task principle).
- The next ADR number is 0104.
