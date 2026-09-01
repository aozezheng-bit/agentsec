# ADR-0109：Byte-level Content Reconciliation

- Date: 2026-08-31
- Status: Accepted for local Candidate verification
- Scope: P3-REL-03

## Context

P3-REL-01 established that the current source modules and Schemas were present
in a newly built Candidate and P3-REL-02 connected that evidence to Candidate
Acceptance. Presence and whole-artifact SHA-256 checks alone do not prove that
each packaged file is the expected current file: an archive can contain a
substituted member while still having a freshly calculated outer checksum.
Release review therefore needs a content-level invariant, not only an
artifact-level digest.

## Decision

For the source-reconciled Candidate, compare archive member bytes directly with
the current source files. The comparison covers Python modules in the Wheel and
sdist, JSON Schemas in the sdist, and `pyproject.toml`/`MANIFEST.in` in the
sdist. Report only relative member paths and Boolean results; never print
contents. Duplicate archive member names fail closed.

The reconciliation report format is advanced to `0.2.0` and the report task is
`P3-REL-03`. Candidate Acceptance requires the byte-level checks and empty
mismatch lists, in addition to the existing source inventory, checksums,
reproducibility, and offline smoke checks. The local candidate directory remains
`dist/candidates/0.4.0-p3-rel-01/` to preserve the P3-REL-01 artifact lineage;
this task does not overwrite `dist/0.4.0/`.

## Consequences

- Stale or substituted packaged modules, Schemas, and release metadata fail
  closed before Candidate Acceptance.
- The reconciliation evidence is independently auditable at both the archive
  member and artifact digest levels.
- Builds remain offline and report-only; no scanned project code or Agent
  content is executed.
- Signatures, SLSA provenance, runtime attestation, exploitability, and
  production or CI authority remain unclaimed.
