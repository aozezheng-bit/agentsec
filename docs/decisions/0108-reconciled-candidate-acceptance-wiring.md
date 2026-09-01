# ADR-0108：Reconciled Candidate Acceptance Wiring

- Date: 2026-08-31
- Status: Accepted for local candidate review
- Scope: P3-REL-02

## Decision

The existing Phase 3 Candidate Acceptance State Machine accepts a P3-REL-01
reconciliation report through the explicit
`--reconciled-candidate-report` input. The report is validated, its declared
Candidate directory is resolved under the repository root, and actual Wheel,
sdist, checksum, report digest, reproducibility, and installed CLI evidence are
rechecked before the acceptance checks can pass.

Legacy `--candidate-verification-report` acceptance remains available for
historical fixtures, but a supplied reconciliation report is the authoritative
verification source for the current source-reconciled Candidate.

The preserved `dist/0.4.0/` artifacts are never modified by this wiring.
Candidate acceptance remains local evidence only and grants no publication,
production, runtime, or CI authority.
