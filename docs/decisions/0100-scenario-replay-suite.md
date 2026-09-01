# ADR-0100: Historical Sample Replay Suite for Provider/Model/Prompt Upgrades

- Status: Accepted
- Date: 2026-08-31
- Task: P3-15
- Scope: P3-15 historical sample replay (model and Prompt upgrades comparable)

## Context

The Phase 3 plan (P3-15) requires a historical sample replay suite so
"模型和 Prompt 升级可比较": whenever a Provider, Model, or Prompt
changes, the same frozen evaluation samples must be replayable and the
results comparable against the previous run. P3-14 (ADR-0098) provides
the deterministic per-run detection metrics over the P3-12/P3-13 frozen
scenario packs, and P3-02/P3-03 provide the approved Shadow adapter and
evaluation harness. What is missing is the chain that records each
historical run with its configuration identity and compares adjacent
runs without granting any promotion or rollback authority.

The offline Shadow adapter only accepts the approved offline fixture
identity (or explicitly approved live bindings), so in offline replay
chains the observable configuration dimension is the Prompt version;
model/provider upgrades become replayable inputs once live bindings are
approved through the P3-05/P3-11C channels.

## Decision

Add `agentsec.semantic.scenario_metrics`-adjacent
`agentsec.semantic.scenario_replay` with the versioned
`agentsec-p3-15-scenario-replay-suite` report family
(`SEMANTIC_SCENARIO_REPLAY_SCHEMA_VERSION` /
`SEMANTIC_SCENARIO_REPLAY_OUTPUT_VERSION` = `0.1.0`, report-family
classification, frozen Schema export under `schemas/semantic-analysis/`):

1. **Run identity.** Every `ScenarioReplayRun` records its `run_id`,
   `provider_id`, `model_id` (both taken from the adapter's approved
   provider metadata and cross-checked against the metrics report), and a
   caller-declared semver `prompt_version`. A run whose recorded identity
   disagrees with its metrics report fails closed. Run IDs must be
   unique, and the (provider, model, prompt) configuration tuple must be
   unique across the chain — two runs that differ only in `run_id` are
   rejected as `duplicate_run_configuration`.

2. **Adjacent-pair comparisons.** `ScenarioReplayRunner.replay(packs,
   specs)` (minimum 2, maximum 8 runs) evaluates each spec through the
   P3-14 metrics path over the same frozen packs, then compares every
   adjacent run pair per injection channel. Each
   `ChannelReplayComparison` records before/after values and deltas
   (candidate minus baseline) for ASR, utility, precision, recall, FPR,
   and FNR, where a positive ASR/FPR/FNR delta means degradation and a
   positive utility delta means improvement.

3. **Per-task outcome transitions.** Comparisons carry value-free
   per-case transition rows over a closed 17-value vocabulary:
   improvements (`undetected_to_detected`, `false_alarm_to_clean`),
   regressions (`detected_to_undetected`, `clean_to_false_alarm`),
   failed-side transitions (any transition involving
   `invocation_failed`, including `failed_to_failed`), and unchanged
   pairs. Counts must sum to the task count and match the rows exactly;
   a comparison whose `failed_side_task_count` is nonzero cannot claim
   `comparison_complete`.

4. **Fail-closed guarantees.** Empty packs, non-tuple inputs, fewer than
   two runs, too many runs, invalid spec types, non-semver Prompt
   versions, duplicate run IDs or configurations, channel mismatches,
   and task-count/case-set drift between compared runs raise stable
   `ScenarioReplayError` codes. Model validation additionally enforces
   delta arithmetic (delta == after - before), the adjacent-pair
   structure (every channel compares each adjacent pair exactly once),
   and channel-set equality across runs.

5. **Authority boundary.** The suite is immutable and report-only:
   `blocks`, `policy_authority`, `release_authority`,
   `provider_promotion_authority`, and `runtime_verified` are frozen
   false literals at suite, run, and comparison levels. A comparison is
   human-review evidence for change assessment — it is never a
   promotion, rollback, or Provider qualification decision, and
   offline-fixture replay numbers are not quality claims about live
   models.

## Consequences

- Prompt upgrades are directly comparable offline today; Model and
  Provider upgrade comparisons become available as soon as approved live
  bindings exist, with no API change (each live adapter already carries
  its approved identity).
- P3-16 Shadow pipeline and later gates can embed or reference replay
  suites as evidence artifacts; the frozen Schema keeps them auditable.
- Determinism: identical packs, spec order, and adapters produce
  byte-identical suite JSON (no timestamps); the P3-01 assessment that
  fixture re-runs are not "learning" still holds.
- The suite deliberately records no corpus text, raw request/response
  payloads, or credentials; comparisons reference case IDs only.
- The next ADR number is 0101.
