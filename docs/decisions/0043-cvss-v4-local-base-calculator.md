# ADR-0043: Local CVSS v4.0 Base Score Calculator

- Status: Accepted
- Date: 2026-08-24
- Task: `P2-20`
- Depends on: ADR-0040 and ADR-0041

## Context

P2-17 accepted CVSS v4.0 Base Vectors but retained an upstream-provided Score
because a local calculator had not yet been implemented. P2-18 exposed that
result in Finding and Assessment reports. Continuing to trust an unverified
external Score weakens provenance; silently implementing an incomplete formula
would be worse.

The project needs a deterministic, offline, standards-derived Base calculator
without mixing CVSS with AgentSec's NIST-style risk model.

## Decision

1. Upgrade the standalone CVSS Adapter from `0.1.0` to `0.2.0`.
2. Implement CVSS v4.0 Base Score calculation using the Base MacroVector,
   maximum-severity vector, lower-score lookup, distance interpolation, and
   one-decimal rounding method.
3. Keep the CVSS v4.0 input boundary at the 11 Base Metrics.
4. Use CVSS v4.0 Base defaults for omitted scoring-only metrics: `E:A` and
   `CR/IR/AR:H`.
5. Calculate the v4.0 Score locally even when an upstream Score is supplied.
6. Reject a supplied Score or Severity that does not match the local result.
7. Mark successful v4.0 results `score_verification=calculated`.
8. Keep CVSS v3.1 behavior unchanged except for the Adapter version and shared
   provenance wording.
9. Keep CVSS, AgentSec Score, Evidence Confidence, and Hard Gate fields
   independent.
10. Keep the calculator offline, deterministic, and free of scanned-content
    execution, network access, LLM, MCP, or runtime verification.

## Consequences

### Positive

- CVSS v4.0 Base results no longer require an unverified upstream Score.
- Existing upstream v4.0 records can still be imported and checked.
- Score provenance is explicit in reports.
- The implementation is deterministic and suitable for regression testing.

### Negative

- The lookup table adds a maintained standards-derived data dependency to the
  source tree.
- Temporal, Environmental, Threat, and Supplemental metrics remain separate
  future work.
- A local Base Score still does not prove runtime reachability or exploitability.

## Rejected alternatives

### Continue marking every v4.0 Score as upstream-provided

Rejected because the project now has a deterministic local Base calculator.

### Implement only the arithmetic impact/exploitability formula

Rejected because CVSS v4.0 Base scoring requires the MacroVector and lookup/
interpolation behavior, not a v3-style arithmetic shortcut.

### Use CVSS v4.0 to change AgentSec RiskAssessment

Rejected because CVSS and AgentSec risk retain different semantics and
provenance.
