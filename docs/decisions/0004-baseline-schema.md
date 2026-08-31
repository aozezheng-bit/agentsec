# ADR-0004: Phase 1 Baseline Schema

- Status: Accepted
- Date: 2026-08-18
- Task: P1-12

## Context

Phase 1 must compare the current Agent control assets with a trusted local
snapshot. File-level change detection needs stable path and hash identity, while
line-oriented text diff also needs the exact previous UTF-8 content. A baseline
is more trusted than the project being scanned, but remains an untrusted local
input that may be stale, malformed, replaced, or deliberately modified.

Using the public Domain Schema directly would couple baseline compatibility to
report-model changes. Storing only hashes would identify modified files but
could not produce the required before/after text evidence. Storing absolute
project paths would reduce portability and disclose host-specific information.

## Decision

Create a separately versioned Baseline Schema under `agentsec.baselines` with
three public models:

- `Baseline`: top-level `schema_version`, generation metadata, and assets;
- `BaselineMetadata`: scanner version vector, collection-configuration
  fingerprint, generation time, and optional Git provenance;
- `BaselineAsset`: project-relative identity, type, source, exact UTF-8 content,
  size, line count, and SHA-256.

The initial Baseline Schema version remains `0.1.0`, independently from Domain
Schema `0.2.0`.

The format follows these rules:

1. `schema_version` is top-level so readers can reject incompatible data before
   interpreting the remaining payload.
2. Before 1.0, only the same major and minor version is readable; patches must
   preserve structure and meaning.
3. Unknown fields are rejected at every model level.
4. Asset paths are portable, project-relative POSIX paths.
5. Asset paths are unique and sorted lexicographically for deterministic output.
6. `size_bytes`, `line_count`, and `sha256` must match the exact re-encoded UTF-8
   content.
7. The version vector stores package, configuration, domain, rule-pack, and risk
   model versions as provenance. These fields do not make rule or risk output
   part of the baseline.
8. `collection_config_sha256` fingerprints the canonical effective
   configuration fields that affect discovery and collection. The canonical
   hashing procedure is implemented with baseline creation in P1-13.
9. Git provenance is all-or-none: `git_commit` and `git_dirty` are both present
   for a Git-backed snapshot or both absent.
10. Git commits use full lowercase SHA-1 or SHA-256 object identifiers.
11. Full asset content is retained because P1-15 requires before/after text and
    line evidence. Baseline files are therefore sensitive data and must never be
    copied into logs or validation errors.
12. Validation errors expose stable error codes and schema field paths only,
    never rejected values.
13. The baseline has no signature, approval identity, or authenticity claim in
    Phase 1. Those controls remain future work.

## Consequences

### Positive

- P1-14 can deterministically identify added, removed, and modified assets.
- P1-15 can produce exact before/after line evidence without reading Git history.
- A baseline remains portable across checkout locations.
- Content tampering that leaves stale metadata is rejected.
- Compatibility failures can map to the reserved baseline CLI exit code without
  parsing security-significant unknown fields.
- Domain Schema can evolve independently from the baseline file format.

### Negative

- Baselines duplicate the contents of Agent control files and may contain
  sensitive instructions or credentials already present in those files.
- SHA-256 detects inconsistent content but does not prove who approved or wrote
  the baseline; an attacker able to replace the entire file can recompute it.
- Full-content baselines are larger than hash-only manifests.
- Canonical ordering is strict; hand-authored unsorted files are rejected.

## Follow-up

- P1-13 writes bounded baseline files using restrictive local permissions and
  computes the collection-configuration fingerprint.
- P1-14 compares baseline and current asset identity and hashes.
- P1-15 computes bounded line-oriented text differences.
- Later phases may add signatures, approval identity, attestation, or remote
  trusted storage through a new Baseline Schema version.
