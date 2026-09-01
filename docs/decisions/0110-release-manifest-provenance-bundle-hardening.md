# ADR-0110：Release Manifest / Provenance Bundle Hardening

- Date: 2026-08-31
- Status: Accepted for local Candidate evidence
- Scope: P3-REL-04

## Context

P3-REL-03 proves that packaged Python modules, Schemas, and release metadata
match the current source bytes. Candidate Acceptance also has artifact hashes,
reproducible-build evidence, SBOM/license evidence, and an explicit
non-claiming build policy, but those records were separate and not bound into a
single auditable release evidence set.

A release owner needs to answer which artifact, source inventory, reconciliation
report, and supply-chain records belong together without introducing a
self-referential checksum or accidentally claiming signatures and hosted
provenance.

## Decision

Generate three deterministic companion files for the local Candidate:

- `release-manifest.json` binds Candidate identity, artifacts, the P3-REL-03
  report, source inventory, supply-chain evidence, build policy, and explicit
  claims;
- `provenance-bundle.json` binds the release manifest and all evidence records,
  and fixes the authority boundary to evidence-only;
- `PROVENANCE-SHA256SUMS` covers every input plus the bundle itself, excluding
  its own checksum to avoid a cycle.

Candidate Acceptance consumes the explicit bundle path and requires all bound
digests, paths, sizes, source inventory values, file inventory values, and
non-claims to validate. The historical `dist/0.4.0/` Candidate remains
immutable. Manifest and bundle version identifiers are centrally registered in
the interface provenance registry, but they grant no authorization authority.

## Consequences

- Release evidence is portable and cross-file tampering is detected before local
  Candidate Acceptance.
- Re-running bundle generation with identical inputs is byte-deterministic.
- The bundle remains value-minimized and safe to inspect in CI logs or review
  artifacts.
- Signing, SLSA, runtime attestation, remote publication, production, and CI
  authority remain separate future controls.
