# ADR-0010: NIST-Style Base Risk Model v0 and Risk Model 0.2.0

- Status: Accepted
- Date: 2026-08-19
- Task: P1-21

## Context

P1-19 and P1-20 can produce stable `UnscoredFinding` values with trusted Rule
metadata and validated Evidence. The Domain `Finding` also requires likelihood,
impact, Severity, numeric score, Evidence Confidence, and hard-gate state.
Inventing placeholder values would misrepresent scanner certainty and couple
rules directly to policy.

The project plan requires a NIST-style five-level base score, original
likelihood and impact, and traceable mapping rationale. It also requires
high-water-mark impact, CVSS-compatible Severity ranges, independent Evidence
Confidence, non-dilutable Critical conditions, and versioned scoring semantics.

NIST SP 800-30 Rev. 1 provides qualitative likelihood, impact, and Table I-2
risk levels, but it does not mandate the complete AgentSec rule profile or the
project's final 0–10 representative values. The implementation must distinguish
standards-derived mappings from AgentSec policy.

## Decision

Adopt these P1-21 decisions:

1. Introduce an internal `agentsec.risk` package with a `RiskEngine` Protocol and
   `DeterministicRiskEngine` implementation.
2. Keep `UnscoredFinding` unchanged and produce an intermediate
   `ScoredFinding(unscored, risk)` rather than prematurely constructing the final
   Domain `Finding`.
3. Do not add Confidence or Hard Gate placeholders. P1-22 and P1-23 retain
   ownership of those values.
4. Encode all 25 cells of NIST SP 800-30 Rev. 1 Table I-2 explicitly.
5. Retain five likelihood and five impact ordinals from 1 to 5.
6. Retain the NIST Table I-2 semi-quantitative result
   `0 / 2 / 5 / 8 / 10` in a separate field.
7. Apply the approved AgentSec section 6.7.2 representative mapping
   `0.0 / 2.0 / 5.5 / 8.0 / 9.5` for report compatibility.
8. Map the 0–10 score to FIRST CVSS v4.0 qualitative ranges:
   None, Low, Medium, High, and Critical.
9. Define six impact dimensions: Confidentiality, Integrity, Availability,
   Safety, Business & Compliance, and Downstream Blast Radius.
10. Compute overall impact by high-water mark, never by averaging dimensions.
11. Create one explicit reviewed `RiskProfile` for each production Rule ID.
12. Use Moderate likelihood for direct static declarations and Low likelihood
    for indirect indicators/references because Phase 1 lacks runtime reachability,
    exposure, or reproduction evidence.
13. Store trusted likelihood rationale, per-dimension impact rationale, matrix
    level, both numeric mappings, Severity, and mapping-source identifiers in
    every `RiskAssessment`.
14. Do not use source excerpt wording as a scoring input. Rule ID, category, and
    reviewed profile are the only v0 scoring selectors.
15. Reject unknown Rule IDs and category mismatches instead of silently falling
    back to a broad category score.
16. Score Findings independently and do not introduce aggregation or averaging.
17. Keep risk output deterministic and free of filesystem, shell, network,
    scanned imports, Skill, MCP, or LLM dependencies.
18. Increment `RISK_MODEL_VERSION` from `0.1.0` to `0.2.0`.
19. Keep `DOMAIN_SCHEMA_VERSION` and `RULE_PACK_VERSION` at `0.2.0` because the
    new objects are internal Python pipeline types and rule semantics are
    unchanged.

## Consequences

### Positive

- Every score is reproducible and traceable to a reviewed Rule profile, impact
  vector, exact matrix cell, numeric mapping, and version.
- The implementation reproduces the official NIST matrix while clearly labeling
  the separate AgentSec engineering score mapping.
- A Very High impact dimension cannot be diluted by lower dimensions.
- Rule authors cannot self-assign risk values through attacker-influenced output.
- Static limitations reduce likelihood rather than pretending runtime evidence
  exists, while Evidence Confidence remains independent for P1-22.
- Unknown custom rules fail closed until a reviewed profile is registered.
- P1-22 and P1-23 can extend the pipeline without changing P1-21 semantics.

### Negative

- Rule-specific profiles require review and versioning whenever a Rule ID is
  added or its risk meaning changes.
- Static v0 profiles do not produce Critical for the current built-in rules;
  Critical requires stronger likelihood evidence or later hard-gate/composite
  policy.
- Representative scores are coarse matrix labels, not empirical loss
  probabilities or financial-risk estimates.
- The intermediate objects are not yet emitted by `agentsec scan` or serialized
  in reports.
- Custom rules cannot receive a score without an explicitly supplied reviewed
  profile.
