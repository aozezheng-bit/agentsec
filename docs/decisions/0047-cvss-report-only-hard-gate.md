# ADR-0047: CVSS Report-only Hard Gate

- Status: Accepted
- Date: 2026-08-24
- Task: `P2-24`
- Depends on: ADR-0040, ADR-0041, ADR-0043, ADR-0044, ADR-0045, ADR-0046

## Context

P2-17 through P2-23 provide local CVSS calculation, extended score views,
Finding integration, vulnerability identity, and source association. A consumer
now needs a deterministic indication that a Finding's current CVSS view reaches
High or Critical severity.

The existing generic `Finding.hard_gate` and `HardGateAssessment` represent
AgentSec policy floors over AgentSec risk. Directly reusing them for CVSS would
silently make CVSS overwrite or raise the AgentSec score, violating the
separation established in the CVSS integration tasks.

## Decision

1. Add a separate `Finding.cvss_hard_gate` field.
2. Add `CvssHardGateMatch` and `CvssHardGateAssessment` domain contracts.
3. Evaluate `CvssBase.effective_score`; Base Score is used when no extended view
   is present.
4. Report High when `effective_score >= 7.0`.
5. Report Critical when `effective_score >= 9.0`.
6. If Critical matches, report only the strongest Critical match.
7. Use stable gate IDs `HG-CVSS-001` for High and `HG-CVSS-002` for Critical.
8. Keep the mode fixed at `report_only` and `blocks=False`.
9. Preserve AgentSec `score`, `severity`, `confidence`, and generic
   `hard_gate` unchanged.
10. Run the deterministic evaluator in `agentsec scan` after explicit and
    source-backed CVSS enrichment.
11. Add `cvss_hard_gate_matches` to the Assessment JSON summary.
12. Increment Domain Schema `0.7.0 -> 0.8.0` and Assessment Output
    `0.6.0 -> 0.7.0`; create independent `CVSS_HARD_GATE_VERSION=0.1.0`.

## Alternatives rejected

### Reuse generic HardGateAssessment and modify AgentSec score

Rejected. It would make CVSS a hidden input to the AgentSec Risk Model and
would make a report-only CVSS view change the meaning of existing score and
Severity fields.

### Use AgentSec Finding.score as the CVSS Gate input

Rejected. CVSS and AgentSec risk are separate score systems. The gate must use
the attached CVSS effective score.

### Block CI when CVSS is Critical

Rejected. P2-24 is report-only. Enforcement requires a separately authorized
policy task with `--fail-on`, waivers, ownership, rollout, and CI tests.

### Treat the CVSS threshold as runtime proof

Rejected. A CVSS score describes a vulnerability record's severity. It does not
prove that the scanned Agent is reachable, exploitable, or vulnerable in its
runtime environment.

## References

- FIRST CVSS v4.0 Specification: <https://www.first.org/cvss/v4.0/specification-document>
- FIRST CVSS v3.1 Specification: <https://www.first.org/cvss/v3.1/specification-document>
- FIPS 199: <https://csrc.nist.gov/pubs/fips/199/final>
