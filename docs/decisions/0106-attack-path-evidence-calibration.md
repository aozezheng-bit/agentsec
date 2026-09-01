# ADR-0106: Attack Path Evidence Calibration

- Date: 2026-08-31
- Status: Accepted
- Scope: P3-AG-08

## Decision

Calibrate Attack Path Evidence association using labels bound to a frozen
`agentsec-attack-path-evidence-association-report` digest. Labels identify a
path, target kind, target ID, expected relation, case family, reviewer, and
rationale. The runner performs deterministic multi-class comparison and emits
accuracy plus one-vs-rest metrics for `supports`, `partially_supports`,
`duplicates`, and `unmatched`.

## Rationale

Association quality cannot be inferred from implementation tests alone. A
reviewer must be able to say that a particular path-to-target relation is exact,
partial, or invalid. Binding labels to the report digest prevents a later report
change from being silently evaluated against old labels.

## Seed evidence boundary

The initial checked-in three-case corpus is a seed pilot, not independent human
qualification evidence. It is useful for wiring and replay only. A single
reviewer or fixture-derived label cannot support an external Precision/Recall
claim.

## Alternatives rejected

1. **Binary matched/unmatched metric** — loses the distinction between exact and
   partial support.
2. **Re-labeling from the current implementation** — circular self-validation.
3. **Treating a missing row as unmatched** — hides dropped or unexpected output.
4. **Automatic rule tuning or Gate promotion** — calibration is evidence only;
   deterministic Rules and reviewed Policy retain authority.

## Security invariants

```text
No source excerpts or secret values are copied into calibration reports
No calibration result mutates an association, Finding, Rule, or Policy
No runtime reachability/exploitability claim
report_only=true; blocks=false; all authority booleans=false
```
