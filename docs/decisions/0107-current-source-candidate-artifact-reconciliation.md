# ADR-0107：Current Source / Candidate Artifact Reconciliation

- Date: 2026-08-31
- Status: Accepted for local candidate construction
- Scope: P3-REL-01

## Context

The source tree advanced beyond the preserved `dist/0.4.0/` candidate. In
particular, the source contains the Attack Graph track and P3-AG-09 Score
context integration, while the preserved Wheel did not contain
`agentsec/attack_graph/`. Overwriting the accepted candidate would destroy an
historical release record and make provenance ambiguous.

## Decision

Build a new candidate under:

```text
dist/candidates/0.4.0-p3-rel-01/
```

The reconciliation tool builds from the current source twice with
`SOURCE_DATE_EPOCH=0`, normalizes sdist metadata, validates source-module and
Schema inclusion, installs the Wheel in an offline temporary environment, and
runs bounded CLI smoke tests. The existing `dist/0.4.0/` candidate is immutable
for this task.

The new candidate retains package metadata `0.4.0`; it is a reconciled local
candidate, not a version publication or automatic replacement of `0.4.0`.

## Consequences

- Source and candidate consistency becomes machine-verifiable.
- P3-AG/P3-AG-09 can be tested from the installed candidate.
- A later release-owner decision is still required before replacing or
  publishing any 0.4.0 artifact.
- Signatures, SLSA provenance, runtime attestation, and production deployment
  remain unclaimed.
