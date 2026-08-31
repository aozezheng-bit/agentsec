# ADR-0041: Integrate CVSS Base into Finding and Assessment Reports

- Status: Accepted
- Date: 2026-08-24
- Task: `P2-18`
- Depends on: ADR-0040

## Context

P2-17 provides a standalone `CvssBaseAssessment` for conventional
vulnerability records. The existing Domain `Finding` only carries AgentSec's
likelihood, impact, score, Severity, Evidence Confidence, and report-only Hard
Gate state. A vulnerability report needs to retain both the conventional CVSS
view and the AgentSec static-analysis view without conflating them.

Adding a public nested object changes the Domain and Assessment JSON contracts,
so the change must be versioned and tested. Existing Findings without CVSS must
remain valid.

## Decision

1. Add an optional `Finding.cvss: CvssBase | None` field.
2. Define `domain.CvssBase` as a strict immutable value object containing the
   adapter version, CVSS version, canonical Base Vector, Base Score, Base
   Severity, normalized metrics, score-verification status, and mapping basis.
3. Add `CvssBaseAssessment.to_domain_cvss()` and
   `CvssBaseAssessment.attach_to_finding()` as the integration seam.
4. Return a new Finding copy from `attach_to_finding()`; do not mutate the
   original Finding.
5. Keep `Finding.score` and `Finding.severity` as AgentSec values. CVSS uses
   the nested `base_score` and `base_severity` fields.
6. Display CVSS Base, Vector, and Verification in the Text Report only when
   `Finding.cvss` exists.
7. Let the existing strict JSON Report serialization carry the nested object and
   regenerate its JSON Schema.
8. Increment `DOMAIN_SCHEMA_VERSION` from `0.3.0` to `0.4.0` and
   `ASSESSMENT_OUTPUT_VERSION` from `0.2.0` to `0.3.0`.
9. Keep `RISK_MODEL_VERSION=0.4.0` and `CAPABILITY_RISK_MODEL_VERSION=0.1.0`
   unchanged.
10. Keep CVSS report-only: it cannot enable a Hard Gate, block CI, authorize an
    action, or prove runtime exploitability.

## Consequences

### Positive

- Vulnerability Findings can carry a standards-based CVSS Base result without
  losing AgentSec evidence and static risk context.
- Text and JSON consumers can distinguish AgentSec Severity from CVSS Severity.
- Existing Finding construction remains source-compatible because `cvss` is
  optional.
- The nested object is schema-backed, deterministic, immutable, and validated
  at the report boundary.
- The adapter provides a safe, explicit seam for future CVE/vulnerability
  source integration.

### Negative

- Domain and Assessment consumers must explicitly support schema versions
  `0.4.0` and `0.3.0` respectively.
- Existing frozen demo artifacts require regeneration because the public report
  version and optional Finding field changed.
- CVSS is not yet connected to a vulnerability database or runtime verifier.

## Rejected alternatives

### Replace AgentSec Finding score with CVSS Base Score

Rejected because the two scores have different provenance and semantics.

### Average the two scores

Rejected because no accepted standards basis combines these scores and averaging
can dilute a high or critical signal.

### Add CVSS only to the top-level Assessment

Rejected because the CVSS record must remain attached to the exact vulnerability
Finding and retain Finding-level provenance.

### Make CVSS mandatory on every Finding

Rejected because the current deterministic AgentSec scan produces capability
findings, not a complete vulnerability inventory.
