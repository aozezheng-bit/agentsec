# ADR-0111：Semantic Gate Definition / Controlled Qualification

- Date: 2026-09-01
- Status: Accepted for report-only qualification
- Scope: P3-18

## Context

P3-05 through P3-17 provide semantic Provider review, calibration, Rule
candidate staging, replay, Shadow Mode, and human FP/FN feedback. Those reports
are useful evidence but do not define when a semantic signal is sufficiently
qualified for a named Gate. Without a contract, teams could mistake a good
fixture replay or a model score for authorization.

## Decision

Introduce a digest-bound `SemanticGateCandidate` with explicit sample, quality,
coverage, and Evidence Confidence thresholds. Introduce a deterministic
`SemanticGateQualificationRunner` and versioned qualification report with three
outcomes:

- `qualified`: all required evidence is present and passes;
- `conditionally_qualified`: quality evidence passes but required review/input
  evidence is pending;
- `not_qualified`: a required quality or integrity check fails.

The runner may consume P3-05 Provider Promotion, P3-07 calibration/Finding
promotion, and P3-10 Rule staging reports. All source reports remain
report-only. Candidate and qualification objects hard-code `blocks=false`,
`can_block_ci=false`, `can_publish_rule=false`, `can_approve_waiver=false`, and
`can_grant_runtime_authority=false`. Confidence A requires a Runtime Attestation
marker; static evidence cannot claim it.

## Consequences

- Semantic Gate readiness becomes reproducible and reviewable rather than an
  informal Boolean.
- Missing independent review or confidence evidence is visible as pending,
  rather than being counted as a pass.
- P3-05/P3-07/P3-10 remain composable without granting their reports new
  authority.
- Real Provider quality and production authorization remain separate future
  decisions.
