# ADR-0012: Report-Only Hard Gate Metadata and Risk Model 0.4.0

- Status: Accepted
- Date: 2026-08-19
- Task: P1-23

## Context

P1-21 and P1-22 provide score, Severity, and Evidence Confidence, but the final
Domain `Finding` still requires hard-gate state. The project plan also requires
Critical conditions to remain non-dilutable and states that Phase 1 must not
block CI by default.

The term “Hard Gate” can be confused with enforcement. A deterministic condition
may establish a minimum risk level even when the current product only reports
that fact. Conflating “matched” with “blocked” would make future reporter and
policy behavior ambiguous.

The project-plan section 6.8 lists future High and Critical combination
conditions, but Phase 1 does not resolve effective capabilities, permissions,
MCP behavior, or runtime attack paths. Activating those conditions from lexical
Markdown signals would overstate scanner certainty and duplicate P2-15.

Hard Gate floors affect effective score, Severity, aggregation behavior, and the
meaning of the Domain `hard_gate` field. The change therefore requires a Risk
Model version decision.

## Decision

Adopt these P1-23 decisions:

1. Define a Hard Gate as a deterministic minimum risk floor, not as a CI action.
2. Record canonical terminology in root `CONTEXT.md`.
3. Introduce immutable `HardGateMatch`, `HardGateAssessment`, and `GatedFinding`
   models plus a `HardGateEngine` Protocol and `DeterministicHardGateEngine`.
4. Support only `High` and `Critical` floors.
5. Map High to the CVSS-compatible lower bound `7.0` and Critical to `9.0`.
6. Calculate effective score as `max(base_score, strongest_floor_score)`.
7. Select the strongest floor when several matches exist; never sum or average
   matches.
8. Keep Evidence Confidence independent. No Confidence level can remove, lower,
   or disable a gate.
9. Support only `GateEnforcementMode.REPORT_ONLY` in Phase 1.
10. Define `blocks=false` for every Risk Model `0.4.0` assessment, including
    triggered gates.
11. Define Domain `hard_gate=true` to mean at least one deterministic gate match,
    independent from enforcement.
12. Require stable `HG-TOPIC-NNN` Gate IDs, stable supporting Rule IDs, Finding ID
    binding, non-empty trusted rationale, and unique Gate IDs per Finding.
13. Require each match to include the Rule ID of the Finding to which it is
    attached.
14. Exclude gate rationale and the underlying ConfidenceFinding from generated
    representations.
15. Allow the engine to consume trusted precomputed matches, but provide no
    production match detectors or active matches in Phase 1.
16. Reject orphan matches, duplicate Finding IDs, duplicate Gate IDs, and source
    Rule mismatch with fixed safe errors.
17. Let `GatedFinding.to_domain_finding()` assemble the existing Domain Finding
    without rendering it.
18. Preserve original Evidence, Finding ID, likelihood, impact, Confidence, and
    base risk metadata; only effective score, effective Severity, and hard-gate
    state come from gate aggregation.
19. Keep processing deterministic and free of filesystem, shell, network,
    scanned imports, Skill, MCP, and LLM dependencies.
20. Increment `RISK_MODEL_VERSION` from `0.3.0` to `0.4.0`.
21. Keep Domain Schema and Rule Pack versions at `0.2.0` because their existing
    structures and trigger meanings are unchanged.

## Consequences

### Positive

- Hard Gate matching and CI enforcement are no longer conflated.
- Future Critical conditions cannot be diluted by lower scores or D Confidence.
- Score and Severity remain internally consistent after a floor is applied.
- The complete existing Domain Finding can now be assembled for P1-24 and P1-25.
- Phase 1 remains report-only and cannot accidentally block CI.
- Future deterministic gate detectors can supply validated matches without
  changing the aggregation contract.

### Negative

- No production Hard Gate condition is active in Phase 1; default Findings have
  `hard_gate=false`.
- The synthetic-match seam is trusted scanner input, not a sandbox for
  repository-provided policy plugins.
- The Domain `hard_gate` boolean does not encode enforcement mode, so reporters
  must use gate metadata when explaining “matched but report-only.”
- High and Critical floors use threshold minimums rather than the representative
  `8.0` and `9.5` base-score labels; documentation must preserve this distinction.
- Production combination conditions, policy configuration, waivers, and CI
  enforcement remain later tasks.
