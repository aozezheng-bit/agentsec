# P3-REL-04：Release Manifest / Provenance Bundle Hardening

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-REL-03
- Mode: local Candidate evidence; no publication or signing authority

## Objective

Create a deterministic, value-minimized release manifest and provenance bundle
for the source-reconciled Candidate. Bind the package artifacts, P3-REL-03
byte-level reconciliation report, source inventory, supply-chain evidence, and
build boundary into independently verifiable records.

## Deliverables

The command is:

```bash
.venv/bin/python scripts/build-release-provenance-bundle.py --force
```

It writes these files under
`dist/candidates/0.4.0-p3-rel-01/`:

```text
release-manifest.json       Candidate identity and evidence manifest
provenance-bundle.json      Cross-file provenance and authority contract
PROVENANCE-SHA256SUMS       Integrity list for the bundle (self-excluded)
```

The files contain only relative paths, SHA-256 digests, sizes, versioned
contracts, and explicit non-claims. They do not contain source excerpts,
secrets, credentials, or absolute local paths.

## Bound evidence

The manifest and bundle bind:

- the Wheel and sdist digests and sizes;
- the existing `SHA256SUMS` artifact checksum file;
- the P3-REL-03 reconciliation JSON and Markdown reports;
- the current source inventory count and canonical digest;
- runtime/dev lockfiles, SBOM, license inventory, lockfile digest evidence, and
  build-provenance policy;
- fixed `SOURCE_DATE_EPOCH=0`, reproducible-build status, offline boundary,
  and non-execution of scanned content.

`PROVENANCE-SHA256SUMS` covers every bundle input and the provenance bundle
itself, while excluding its own digest to avoid a self-reference cycle.

## Candidate Acceptance integration

When `--reconciled-candidate-report` is supplied, Candidate Acceptance requires
an additional passing `release_manifest_and_provenance_bundle` check. Validation
fails closed if any of the following is stale or inconsistent:

- manifest/bundle identity, version, or candidate directory;
- manifest digest, artifact digest, artifact checksum, or file size;
- P3-REL-03 reconciliation report or source inventory;
- supply-chain evidence digests;
- bundle file inventory or `PROVENANCE-SHA256SUMS`;
- build boundary, authority boundary, or explicit non-claims.

Legacy non-reconciled verification fixtures remain compatible and do not gain a
retroactive P3-REL-04 requirement.

## Security boundary

This task does not create or imply artifact signatures, SLSA provenance,
Runtime Attestation, remote publication, CI blocking, production deployment,
or exploitability. It reads release evidence as inert data and does not execute
scanned Agent files, scripts, hooks, skills, or MCP servers.
