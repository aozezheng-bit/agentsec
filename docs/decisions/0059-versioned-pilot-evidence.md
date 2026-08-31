# ADR-0059: Versioned Pilot Evidence and Scenario-Level FP/FN Metrics

- Status: Accepted
- Date: 2026-08-25
- Task: P2-30

## Context

P2-30 needs reproducible pilot evidence covering CI decisions, detection
agreement, Coverage behavior, Waivers, and performance. A remote production
repository is not connected to this workspace, so evidence maturity must be
explicit rather than inferred from a successful local replay.

## Decision

Introduce `agentsec-pilot-plan` and `agentsec-pilot-report` contracts at version
`0.1.0`. Every case binds one inert repository-relative project state to an
explicit Organization Policy, reviewed expected exit code, expected Coverage,
expected unique Markdown Rule IDs, and a performance ceiling.

Pilot FP/FN metrics compare expected and observed unique Rule IDs per scenario:

```text
TP = expected ∩ observed
FP = observed - expected
FN = expected - observed
```

The report separately records decision, Coverage, detection, and performance
agreement. It does not average these into a new security score and does not
change CI authority.

Evidence maturity is mandatory:

```text
internal_integration → checked-in representative fixtures and local/CI replay
external_repository  → independently identified external repository evidence
```

The first checked-in pilot is explicitly `internal_integration`.

## Consequences

- P2-31 receives structured pilot data instead of prose-only observations.
- Local latency is visible but cannot be treated as a production SLA.
- Scenario-level Rule labels can reveal deterministic regression FP/FN, but they
  do not establish runtime exploitability or production prevalence.
- A future external pilot can reuse the contract without relabeling internal
  evidence as production evidence.
- Deterministic Organization Policy remains the only CI blocking authority.
