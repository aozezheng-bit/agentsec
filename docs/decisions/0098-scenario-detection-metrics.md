# ADR-0098: Detection-Based Paired-Scenario Evaluation Metrics

- Status: Accepted
- Date: 2026-08-31
- Task: P3-14
- Scope: P3-14 evaluation metrics (ASR / Utility / Precision / Recall / FPR / FNR)

## Context

The Phase 3 plan (P3-14) requires evaluation metrics — ASR, Utility,
Precision, Recall, FPR, FNR — over the P3-12 (AgentDojo-style) and P3-13
(InjecAgent-style) paired scenario corpora. Both source benchmarks define
these terms *dynamically*: they execute an agent, inject adversarial
content during a live task, and observe real tool calls and task
completion. AgentSec's invariants forbid executing scanned content and
forbid claiming runtime reachability, exploitability, or attack success,
so dynamic benchmark semantics cannot be reproduced.

ADR-0094 and ADR-0095 already established the static adaptations and
explicitly deferred ASR semantics to P3-14. The P3-03 evaluation harness
provides deterministic per-case TP/FP/FN replay, and the packs record
which task is normal and which is attack.

## Decision

Add `agentsec.semantic.scenario_metrics` with the versioned
`agentsec-p3-14-scenario-evaluation-metrics` report family
(`SEMANTIC_SCENARIO_METRICS_SCHEMA_VERSION` / `SEMANTIC_SCENARIO_METRICS_OUTPUT_VERSION`
= `0.1.0`, report-family classification, frozen Schema export under
`schemas/semantic-analysis/`):

1. **Detection-based metric semantics.** All rates are detection
   statistics over paired tasks, never dynamic observations:

   ```text
   ASR (detection proxy) = attack tasks with ≥1 missed expected judgment
                           / completed attack tasks   == task-level FNR
   Utility (detection proxy) = normal tasks with zero false-alarm judgments
                           / completed normal tasks  == task-level TNR
   FPR (task level)      = false-alarm normal tasks / completed normal tasks
   FNR (task level)      = undetected attack tasks / completed attack tasks
   Precision/Recall/F1   = judgment level, P3-03 semantics unchanged
   ```

   The report freezes `asr_semantics=detection_based_proxy` and
   `runtime_attack_success_claimed=false`; dynamic benchmark dimensions
   (task completion under injection, observed tool calls) are explicitly
   not computed.

2. **Channel scoping.** `evaluate_scenario_metrics((packs...), adapter)`
   accepts the P3-12 and/or P3-13 packs, converts each through its
   hard-bound converter, replays it through the P3-03 harness, and
   produces one `ChannelScenarioMetrics` section per injection channel
   (`instruction_channel`, `tool_channel`), sorted and unique. Duplicate
   channels, empty packs, non-tuple packs, wrong adapter types, and
   provider/model identity drift across channels fail closed.

3. **Value-free task rows.** Each channel records per-task outcome rows
   (case ID, task kind, outcome, TP/FP/FN counts) with outcomes validated
   against task kind: attack rows must be `attack_detected` (FN=0) or
   `attack_undetected` (FN>0); normal rows must be `normal_clean`
   (FP=0) or `normal_false_alarm` (FP>0). Invocation failures are
   classified per task kind and surfaced as their own outcome
   (`invocation_failed`), which sets `metrics_complete=false`; task-level
   rates are computed over completed tasks only, and channels where a
   side has zero completed tasks fail closed instead of emitting
   undefined rates.

4. **Coherence guarantees.** Model validation enforces detected +
   undetected + per-kind failures == task counts, failure totals ==
   per-kind sums, ASR == FNR, utility + FPR == 1, and both rates matching
   their raw-count fractions; JSON round-trips, and identical
   packs/adapter/versions produce byte-identical reports (no timestamps).

5. **Authority boundary.** The report is immutable and report-only:
   `blocks`, `policy_authority`, `release_authority`,
   `provider_promotion_authority`, `runtime_verified` are frozen false
   literals. Metrics are evidence for human review only; they grant no
   Provider qualification, rule, CI, Hard-Gate, or release authority, and
   offline-fixture numbers may not be published as real quality claims.

## Consequences

- P3-15 (historical replay), P3-16 (Shadow pipeline), and later LLM
  gates can consume these metrics as plain evidence artifacts.
- Off-adapter evaluation (computing metrics from a stored
  `SemanticEvaluationReport` without re-invoking) is intentionally not
  exposed yet; a future task may add it with its own ADR if a CLI needs
  it.
- Task-level rates exclude invocation-failed tasks by design; consumers
  must check `metrics_complete` before interpreting a channel as clean.
- Confirming the repo-wide precedent, the public surface lives in the
  `agentsec.semantic` namespace; the shared `agentsec.api` module is
  not extended by this task.
- The next ADR number is 0099.
