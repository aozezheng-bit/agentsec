# P3-14: Paired-Scenario Detection Metrics

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-12, P3-13 (both complete; dependency released)
- Mode: static, report-only; no corpus execution; no network; no LLM
- Decision record: ADR-0098

## Objective

Implement the plan's evaluation metrics (ASR, Utility, Precision, Recall,
FPR, FNR) over the P3-12/P3-13 paired scenario corpora as
detection-based statistics without violating the scanner's
non-execution and non-runtime-claim invariants.

## What was delivered

```text
agentsec.semantic.scenario_metrics          strict models, per-channel
                                           computation, fail-closed
                                           evaluation, canonical encoder
schemas/semantic-analysis/
  semantic-scenario-metrics-report.schema.json       frozen Schema export
provenance                                  SEMANTIC_SCENARIO_METRICS_
                                            SCHEMA/OUTPUT_VERSION 0.1.0
                                            (report family, ownership map)
scripts/export_release_schemas.py           export wiring
tests/test_semantic_p3_14.py                18 tests
docs/decisions/0098-scenario-detection-metrics.md
```

## Metric semantics (ADR-0098)

```text
attack task outcome   attack_detected (FN=0) / attack_undetected (FN>0)
normal task outcome   normal_clean (FP=0) / normal_false_alarm (FP>0)
invocation failure    invocation_failed (per task kind; metrics_complete=false)

ASR (detection proxy)     undetected attack tasks / completed attack tasks
                          == task-level false-negative rate
Utility (detection proxy) clean normal tasks / completed normal tasks
                          == 1 - task-level false-positive rate
FPR / FNR (task level)    false-alarm normal share / undetected attack share
Precision/Recall/F1       judgment level, P3-03 semantics unchanged
```

Dynamic benchmark dimensions (attack success by observed tool calls,
task completion under injection) are never claimed:
`asr_semantics=detection_based_proxy` and
`runtime_attack_success_claimed=false` are frozen literals.

## Key behaviors

- `evaluate_scenario_metrics((p12, p13), adapter)` returns one
  `ChannelScenarioMetrics` per pack (`instruction_channel`,
  `tool_channel`), sorted and unique, with provider/model identity
  verified across channels.
- Value-free per-task outcome rows are validated against task kind and
  counts; invocation failures are classified per task kind and never
  silently diluted — a channel with any failure keeps
  `metrics_complete=false` while rates remain interpretable over
  completed tasks.
- Coherence validation: detected + undetected + per-kind failures ==
  task counts; failure totals == per-kind sums; ASR == FNR;
  utility + FPR == 1; rates match their raw-count fractions.
- Empty packs, duplicate channels, non-tuple pack input, wrong adapter
  type, wrong pack type, or zero completed tasks on either side fail
  closed with stable `ScenarioMetricsError` codes.
- Deterministic: identical packs/adapter/versions produce byte-identical
  JSON reports (round-trip verified by tests) with no timestamps.

## Authority boundary

```text
blocks / policy_authority / release_authority /
provider_promotion_authority / runtime_verified   false (Literal)
report_only (channel level)                        true
```

Metrics are human-review evidence only. Offline-fixture quality numbers
may not be presented as real provider quality or published claims.

## Verification

```bash
.venv/bin/python -m pytest tests/test_semantic_p3_14.py -q     # 18 passed
.venv/bin/python scripts/export_release_schemas.py             # schema frozen
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy src tests
.venv/bin/python -m pytest
```

## Limitations and follow-ups

- Scenario corpora are bounded by P3-11A gold coverage (18 + 14 cases);
  metric resolution is accordingly coarse (1/9 and 1/7 granularity per
  channel).
- Off-adapter metric computation from a stored evaluation report is not
  exposed; P3-15 retry/replay tooling may request it later.
- Metrics exercise providers through the P3-03 harness only; no
  comparison against the P3-11B qualification gate thresholds is
  performed (different question: detection quality vs. provider
  qualification).
- P3-15 (historical sample replay suite) is the next B-line task and was
  intentionally not started (single-task principle).
- The next ADR number is 0099.
