# AgentSec Asset Diff

- Task: `P1-14`
- Status: Complete
- Decision date: 2026-08-18
- Depends on: P1-13 Baseline Create

## 1. Purpose

Asset Diff compares a validated Baseline with a complete current collection and
returns deterministic file-level changes. It answers only:

```text
Which supported asset paths were added?
Which supported asset paths were removed?
Which existing asset paths now have different bytes?
Was the current collection scope configured the same way as the Baseline scope?
```

P1-14 does not calculate line changes, interpret instructions, run rules, assign
risk, or create Findings.

## 2. Inputs

`DeterministicAssetDiffer.compare()` requires:

```text
validated Baseline
complete current CollectionResult
current collection_config_sha256
```

The current collection must retain its `ScanCoverage`. Passing only a list of
assets is intentionally unsupported because a missing asset could mean either:

```text
the file was removed
or
the file could not be scanned
```

When current coverage is incomplete, the differ fails safely and emits no
`removed` changes.

## 3. Identity and modification semantics

### Asset identity

The exact normalized project-relative path is the file identity.

```text
old/AGENTS.md → new/AGENTS.md
```

is represented as:

```text
new/AGENTS.md  added
old/AGENTS.md  removed
```

P1-14 does not infer renames from matching content hashes.

### Content modification

For a path present in both sets:

```text
before SHA-256 == after SHA-256 → unchanged
before SHA-256 != after SHA-256 → modified
```

Asset type, source, size, line count, and Git status do not independently create
a P1-14 change when the path and SHA-256 are identical. Capability or metadata
change semantics belong to later stages.

## 4. Output matrix

| Baseline path | Current path | Hash relationship | Change |
|---|---|---|---|
| absent | present | n/a | `added` |
| present | absent | n/a | `removed` |
| present | present | different | `modified` |
| present | present | identical | no output |

Every result uses the existing strict Domain Model:

```python
class AssetChange:
    path: str
    change_type: added | removed | modified
    before_sha256: str | None
    after_sha256: str | None
```

Hash requirements are:

```text
added    → after_sha256 only
removed  → before_sha256 only
modified → before_sha256 and after_sha256, and they must differ
```

## 5. Determinism

The differ:

1. indexes Baseline assets by exact path;
2. indexes current collected assets by exact path;
3. rejects duplicate paths on either side;
4. compares the union of paths;
5. sorts the union lexicographically;
6. emits immutable `AssetChange` objects in that order.

Changing current filesystem or adapter enumeration order cannot change output.
Identical inputs produce identical ordered changes.

## 6. Collection-scope compatibility

`AssetDiffResult.collection_config_matches` compares:

```text
baseline.metadata.collection_config_sha256
current_collection_config_sha256
```

A mismatch is kept separate from file changes:

```text
collection_config_matches = false
changes = ()
```

is valid and means that the observed files did not change, but the configured
collection scope or limits did. P1-16 can render this as a visible warning. The
mismatch does not invent an `AssetChange` and is not a Finding by itself.

The current fingerprint must be a lowercase 64-character SHA-256 value. Missing
or malformed fingerprints fail safely.

## 7. Safe failure codes

| Code | Meaning |
|---|---|
| `invalid_collection_config_hash` | Current collection fingerprint is absent or malformed |
| `incomplete_current_coverage` | Current collection has skipped assets or coverage issues |
| `duplicate_baseline_path` | Baseline path identity is ambiguous |
| `duplicate_current_path` | Current collection path identity is ambiguous |

Errors contain no asset content. Duplicate-path errors intentionally avoid
copying even the offending path into the message so terminal control characters
or sensitive names cannot become output injection.

## 8. Public interface

```python
from agentsec.diffing import DeterministicAssetDiffer

result = DeterministicAssetDiffer().compare(
    baseline=baseline,
    current_collection=current_collection,
    current_collection_config_sha256=current_config_hash,
)

for change in result.changes:
    print(change.path, change.change_type)
```

The public types are:

```text
AssetDiffer
DeterministicAssetDiffer
AssetDiffResult
AssetDiffCode
AssetDiffError
```

## 9. Security boundaries

- Diff never reads or executes asset content.
- Output retains paths and hashes only; full Baseline content is not copied.
- Incomplete current coverage never becomes false deletion evidence.
- Scope mismatch is independent from file changes.
- Asset Diff is evidence of textual file drift, not proof of a risky capability.
- Asset Diff does not affect severity, confidence, hard gates, or CI policy.
- Baseline authenticity remains outside Phase 1 without signatures or approval
  attestation.

## 10. P1-14 acceptance evidence

The implementation and tests verify:

- added, removed, and modified detection;
- exact before/after SHA-256 placement;
- no result for identical path and hash;
- stable lexicographic output regardless of input ordering;
- rename represented as removed plus added;
- empty-side behavior;
- collection-config scope matching;
- malformed fingerprint rejection;
- duplicate current and Baseline path rejection;
- incomplete current coverage fail-closed behavior;
- no full content in result or errors;
- integration from P1-13 Baseline creation through current collection to all
  three Asset Diff change types.

## 11. Deferred work

- P1-15 provides bounded line-oriented Text Diff and before/after line evidence.
- P1-16 loads a Baseline and exposes Diff through terminal and JSON CLI output.
- Later rules decide whether a file or text change is security-relevant.
- Rename inference, similarity matching, capability Diff, and semantic Diff are
  not part of P1-14.
