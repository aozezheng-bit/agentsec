# P3-15: Historical Sample Replay Suite

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-12, P3-13, P3-14 (all complete; dependency released)
- Mode: static, report-only; no corpus execution; no network; no LLM
- Decision record: ADR-0100

## Objective

Implement the plan's historical sample replay suite so model and Prompt
upgrades become measurable: the same frozen scenario packs are replayed
under different configurations and adjacent runs are compared without
granting promotion, rollback, or qualification authority.

## What was delivered

```text
agentsec.semantic.scenario_replay           strict run/comparison models,
                                            ScenarioReplayRunner,
                                            ReplayRunSpec, canonical encoder
schemas/semantic-analysis/
  semantic-scenario-replay-suite.schema.json           frozen Schema export
provenance                                  SEMANTIC_SCENARIO_REPLAY_
                                            SCHEMA/OUTPUT_VERSION 0.1.0
                                            (report family, ownership map)
scripts/export_release_schemas.py           export wiring
tests/test_semantic_p3_15.py                19 tests
docs/decisions/0100-scenario-replay-suite.md
```

## Key behaviors

- `ScenarioReplayRunner().replay(packs, specs)` (2..8 runs) evaluates
  each `ReplayRunSpec` through the P3-14 metrics path and records one
  `ScenarioReplayRun` per spec: `run_id` plus approved provider/model
  identity (cross-checked against the metrics report) and a
  caller-declared semver `prompt_version`.
- Adjacent runs are compared per injection channel:
  `ChannelReplayComparison` records before/after ASR, utility,
  precision, recall, FPR, FNR with `*_delta = after - before`
  (positive ASR/FPR/FNR delta = degradation; positive utility delta =
  improvement).
- Value-free per-task transition rows over a closed 17-value vocabulary:
  improvements, regressions, failed-side transitions (anything touching
  `invocation_failed`), and unchanged pairs; counts must sum to the task
  count and match the rows; a comparison with failed-side rows cannot
  claim `comparison_complete`.
- Fail-closed with stable `ScenarioReplayError` codes: empty packs,
  non-tuple input, fewer than two / too many runs, bad spec types,
  non-semver Prompt versions, duplicate run IDs, duplicate
  (provider, model, prompt) configurations, channel mismatch, and
  task-count/case-set drift.
- Deterministic: identical packs/spec order/adapters give byte-identical
  suite JSON (round-trip verified); no timestamps; no corpus text or raw
  payloads recorded.

## Reproduction snippet

```python
from agentsec.semantic import (
    ReplayRunSpec,
    ScenarioReplayRunner,
    SemanticShadowInvocationAdapter,
)

suite = ScenarioReplayRunner().replay(
    (p3_12_pack, p3_13_pack),
    (
        ReplayRunSpec(
            adapter=baseline_adapter, prompt_version="0.1.0", run_id="baseline"
        ),
        ReplayRunSpec(
            adapter=candidate_adapter, prompt_version="0.2.0", run_id="upgrade"
        ),
    ),
)
# suite.comparisons carries per-channel deltas and per-task transitions
```

## Authority boundary

```text
blocks / policy_authority / release_authority /
provider_promotion_authority / runtime_verified   false (Literal, at
                                                   suite/run/comparison)
report_only (run and comparison level)             true
```

A comparison is human-review evidence for change assessment only:
never a Provider promotion, rollback, qualification, rule publication,
CI, or release decision. Offline-fixture replay numbers are not quality
claims about live models.

## Verification

```bash
.venv/bin/python -m pytest tests/test_semantic_p3_15.py -q     # 19 passed
.venv/bin/python scripts/export_release_schemas.py             # schema frozen
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy src tests
.venv/bin/python -m pytest
```

## Limitations and follow-ups

- The offline Shadow adapter only accepts the approved fixture identity,
  so offline chains vary the Prompt version; model/provider upgrade runs
  require approved live bindings (P3-05/P3-11C channels) — the API is
  already identity-driven and needs no change for them.
- Recall/precision deltas are judgment-level (P3-03 semantics) and mix
  normal-side true positives, so task-level ASR/utility deltas are the
  primary upgrade signal; both are recorded.
- A CLI command and stored historical-run archive (re-comparing a new
  run against an imported previous suite JSON) are intentionally out of
  scope; they can follow with evaluation evidence from P3-16+.
- P3-16 (Shadow pipeline) was intentionally not started (single-task
  principle).
- The next ADR number is 0101.
