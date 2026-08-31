# ADR-0060: Pilot-driven Rule and Score Calibration Retains Current Versions

- Status: Accepted
- Date: 2026-08-25
- Task: P2-31

## Context

P2-31 must use P2-30 Pilot data to calibrate deterministic Markdown Rules and
risk scoring before the internal MVP release. The Pilot has no observed FP/FN,
but covers positive scenarios for only nine of fifteen Markdown Rules. The
Agentic scoring chain already has seven frozen end-to-end replay cases.

## Decision

Create the versioned `agentsec-rule-score-calibration-report` contract `0.1.0`
and call this calibration generation `v1`.

For every built-in Markdown Rule, calculate scenario-presence TP/FP/FN from the
freshly replayed Pilot and bind its reviewed likelihood, high-water Impact,
score, Severity, Risk Model version, and a canonical profile SHA-256.

Recommendations are deterministic:

```text
FN > 0                    → review_false_negative
else FP > 0               → review_false_positive
else positive coverage > 0 → retain_current
else                      → more_data
```

A fresh P2-24 scoring suite must exactly match the frozen seven-case JSON before
P2-31 can declare the current scoring model stable.

Because no Pilot FP/FN exists and scoring replay is unchanged, retain:

```text
Markdown Rule Pack 0.3.0
Risk Model 0.4.0
```

Do not publish automatic Rule or score changes. Six uncovered Rules remain
`more_data`; they are not weakened, retired, or excluded from CI.

## Consequences

- The internal MVP may proceed with current deterministic versions.
- P2-31 produces a reviewable calibration conclusion rather than unnecessary
  version churn.
- Internal Pilot accuracy is not represented as production accuracy.
- Future external evidence with FP/FN must trigger review and a separate version
  impact decision before changing Rule or score semantics.
