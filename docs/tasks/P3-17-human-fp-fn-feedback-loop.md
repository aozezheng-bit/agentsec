# P3-17: Human FP/FN Feedback and the Closed Resolution Loop

- Status: Complete（人工评审已完成：54/54 行确认，confirmed 集已落地）
- Date: 2026-08-31
- Depends on: P3-12, P3-13 (frozen packs), P3-14 (evaluation casing),
  P3-11A workflow precedent; P3-16 not a hard dependency
- Mode: report-only; drafting needs no human, label confirmation does
- Decision record: ADR-0106

## Objective

Implement the plan's 人工反馈和标签: durable, digest-bound, reviewer-confirmed
false-positive and false-negative rows plus the closed loop that checks
whether a later run resolves each labeled issue.

## Gap analysis versus P3-07

```text
P3-07 candidate calibration     one labeled expectation per candidate,
                                run-scoped TP/FP/FN/TN metrics
P3-17 feedback rows + loop      per-issue FP/FN rows that persist beyond
                                a run, human confirmation workflow
                                (ai_draft_human_confirmed), and
                                resolved/unresolved re-evaluation
```

## What was delivered

```text
agentsec.semantic.feedback               draft/set/loop contracts,
                                          deterministic draft builder,
                                          confirmation builder,
                                          resolution evaluator, loaders
pilots/semantic-feedback-p3-17/          draft submission template (54 FN
                                          rows from the honest offline
                                          fixture) + Chinese review
                                          worksheet + README
scripts/build-p3-17-feedback-pack.py     idempotent draft pack generator
scripts/import-p3-17-feedback.py         fail-closed submission importer
schemas/semantic-analysis/
  semantic-feedback-set.schema.json      frozen Schema exports
  semantic-feedback-loop-report.schema.json
provenance                                SEMANTIC_FEEDBACK_SET_VERSION /
                                          SEMANTIC_FEEDBACK_LOOP_REPORT_VERSION
tests/test_semantic_p3_17.py              15 tests
docs/decisions/0104-human-fp-fn-feedback-loop.md
```

## Key behaviors

- `build_semantic_feedback_draft(packs, adapter, source_pack_sha256)`:
  deterministic FP/FN draft rows from expected-vs-predicted signature
  diffing; shared normal cases across packs deduplicate (divergent
  duplicates fail closed); stable invocation failures become unevaluated
  cases, never fabricated rows.
- `build_semantic_feedback_set(...)`: promotes confirmed rows, recomputes
  the set digest, rejects `ai_assisted` provenance, requires reviewer id
  and an independence statement (≥20 chars).
- `evaluate_feedback_resolution(set, packs, adapter)`: per-row
  resolved/unresolved/unevaluated with an issue-type-specific resolution
  rule (FP resolved ⇔ no longer predicted; FN resolved ⇔ detected
  again), `resolution_rate` over evaluated rows, loop digest binding the
  feedback digest and run identity.
- Value-free rows and reports; no corpus text, raw payloads, or model
  summaries anywhere.
- Importer fail-closed: missing reviewer, short statement, unresolved
  row status, unknown rows, invalid draft binding.

## Human confirmation (completed 2026-08-31)

All 54 draft rows were reviewed and confirmed by 呈屿 through the
REVIEW-GUIDE interactive workflow (progress, completed submission, and
the confirmed set all landed under `pilots/semantic-feedback-p3-17/`;
`feedback_sha256 a51af675…f2c02`). Closed-loop spot checks:
gold-echoing provider resolves 54/54; the zero-output fixture resolves
0/54.

## Workflow (historical; used for the review)

The shipped draft contains 54 false-negative rows (the offline fixture
predicts nothing, so every gold expectation is an honest FN suspect).
Confirm flow (README + worksheet describe it):

1. Review `draft/REVIEW-WORKSHEET.zh.md`; set each row `status` to
   `confirmed` / `rejected` in the submission template (notes optional).
2. Fill `reviewer_id` and `independence_statement`.
3. Run `scripts/import-p3-17-feedback.py` to emit
   `confirmed/semantic-feedback-set.json`.

Motivation context (recorded in the worksheet): the P3-11C real-provider
trial over the 45-case gold set hit precision 0.394 / recall 0.378
(FP=57 / FN=61).

## Authority boundary

```text
report_only=true; blocks / calibration_authority /
rule_publication_authority / policy_authority / ci_authority /
gate_authority / runtime_verified   all false (Literal)
```

Feedback and resolution rates are human-review evidence only; they grant
no calibration, publication, Policy, CI, gate, release, or runtime
authority and make no quality claims.

## Verification

```bash
.venv/bin/python -m pytest tests/test_semantic_p3_17.py -q    # 15 passed
.venv/bin/python scripts/build-p3-17-feedback-pack.py         # idempotent
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy src tests
.venv/bin/python -m pytest
```

Simulated confirmation (50 confirm / 4 reject) round-tripped through the
importer during development; the shipped confirmed set awaits the human
reviewer.

## Limitations and follow-ups

- Real live-model FP/FN drafts require issue-level predictions; value-free
  stored reports do not retain them, so drafts come from replays.
- The confirmed set does not exist until the worksheet is completed.
- P3-18 (limited LLM gate definition) is the next B-line task and was
  intentionally not started (single-task principle).
- The next ADR number is 0107. Note: ADR-0103 collided with a parallel
  session's `0103-attack-path-evidence-association.md`; per
  first-landed-first-earned numbering, ours (batch Shadow Mode, landed
  first) keeps 0103.
