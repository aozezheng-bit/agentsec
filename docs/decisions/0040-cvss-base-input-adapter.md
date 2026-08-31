# ADR-0040: CVSS Base Input Adapter Boundary

- Status: Accepted
- Date: 2026-08-24
- Task: `P2-17`

## Context

AgentSec already has a deterministic NIST-style static risk model with its own
likelihood, high-water-mark impact, representative score, Evidence Confidence,
and report-only Hard Gate semantics. Traditional vulnerability sources often
arrive with a CVSS Base vector, Base Score, and Base Severity. Reusing those
records is useful, but replacing or averaging the AgentSec score would create
an ambiguous security meaning and would violate the existing risk-score
contract.

The project also has to distinguish a locally verified score from a score
supplied by an upstream calculator. A parser that accepts a v4.0 vector while
silently claiming it recalculated the score would be misleading.

## Decision

1. Introduce an independent `agentsec.risk.cvss` adapter with version `0.1.0`.
2. Accept CVSS v3.1 and v4.0 Base vectors in canonical Base-Metric order.
3. Accept mappings, `CvssBaseInput`, and one strict JSON object.
4. Require all Base Metrics and reject Temporal, Environmental, Threat, and
   Supplemental metrics for this Base-only contract.
5. For CVSS v3.1, calculate the Base Score locally and reject a provided score
   that differs from the calculated value.
6. For CVSS v4.0, validate vector structure, score bounds, and Severity
   consistency, but mark the result `score_verification=provided` because the
   v4.0 calculator is not implemented in this task.
7. Normalize the result into `CvssBaseAssessment` with canonical vector,
   metrics, score, Severity, verification status, and mapping basis.
8. Keep CVSS fields outside `RiskAssessment`, Domain `Finding`, and Capability
   Risk Model versions for this task.
9. Do not use CVSS input to enable a Hard Gate, block CI, or make an
   authorization decision.
10. Reject malformed input with stable, non-sensitive error codes and do not
    echo the complete rejected payload.

## Consequences

### Positive

- Existing CVSS v3.1 vulnerability records can be reused with a locally
  checked score.
- CVSS v4.0 records can be carried through while the verification boundary is
  explicit rather than overstated.
- The existing AgentSec/NIST score contract remains unchanged and regression
  tests remain meaningful.
- Consumers can display conventional CVSS and AgentSec Base Risk side by side.
- The adapter is deterministic, offline, and safe for untrusted input.

### Negative

- CVSS v4.0 scores are not recalculated locally in `0.1.0`; consumers must
  retain the `provided` verification state.
- Base-only input does not include Temporal, Environmental, Threat, or
  Supplemental adjustments.
- A separate integration step is still required to attach a CVSS assessment to
  a vulnerability finding or report artifact.

## Rejected alternatives

### Put CVSS directly in `RiskAssessment.score`

Rejected because `RiskAssessment.score` is the AgentSec project-policy
representative derived from the NIST matrix. Reusing that field would make
provenance and semantics indistinguishable.

### Average CVSS and AgentSec scores

Rejected because averaging can dilute a high or critical signal and has no
standards basis for combining these different assessment objects.

### Trust any caller-supplied score without validation

Rejected because a mismatched score or Severity can silently downgrade a
vulnerability record. v3.1 is checked against the local formula; v4.0 exposes
that its score is upstream-provided.
