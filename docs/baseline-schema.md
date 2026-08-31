# AgentSec Baseline Schema

- Task: `P1-12`
- Status: Complete
- Decision date: 2026-08-18
- Schema version: `0.1.0`
- Decision record: `docs/decisions/0004-baseline-schema.md`

## 1. Purpose

A baseline is a versioned local snapshot of the Agent Markdown assets that were
trusted at a specific point in time. It is the input to later file-level and
line-level diff stages. It is not a scan report, an approval signature, or proof
that the captured Agent was safe.

P1-12 defines the models, deterministic JSON codec, compatibility gate, and JSON
Schema export. P1-13 adds explicit CLI creation, hardened Git provenance, and
bounded atomic filesystem delivery as documented in `docs/baseline-create.md`.

## 2. Top-level shape

```json
{
  "schema_version": "0.1.0",
  "metadata": {
    "scanner_version": "0.1.0",
    "config_schema_version": "0.1.0",
    "domain_schema_version": "0.2.0",
    "rule_pack_version": "0.1.0",
    "risk_model_version": "0.1.0",
    "collection_config_sha256": "<64 lowercase hex characters>",
    "generated_at": "2026-08-18T12:00:00Z",
    "git_commit": "<40 or 64 lowercase hex characters>",
    "git_dirty": false
  },
  "assets": [
    {
      "path": "AGENTS.md",
      "asset_type": "agents",
      "source": "discovered",
      "sha256": "<64 lowercase hex characters>",
      "size_bytes": 42,
      "line_count": 3,
      "encoding": "utf-8",
      "content": "# Agent instructions\n...\n"
    }
  ]
}
```

Example digests are placeholders. Tests and documentation must not contain real
secret values.

## 3. Model invariants

### 3.1 Baseline

- `schema_version`, `metadata`, and `assets` are required;
- assets may be empty only when collection completed with no selected assets;
- asset paths must be unique;
- assets must be sorted lexicographically by path;
- unknown top-level fields are rejected.

`baseline create` refuses to create a trusted snapshot from incomplete collection
or parsing coverage.

### 3.2 BaselineMetadata

- all interface versions use exact `MAJOR.MINOR.PATCH` syntax;
- `scanner_version` stores the exact package version;
- `generated_at` must be timezone-aware;
- `collection_config_sha256` identifies the canonical effective discovery and
  resource-limit configuration used to collect the snapshot;
- `git_commit` accepts a full Git SHA-1 or SHA-256 object identifier;
- `git_commit` and `git_dirty` must be present together or absent together;
- Git fields are provenance, not an authenticity guarantee.

### 3.3 BaselineAsset

- paths are normalized project-relative POSIX paths;
- absolute paths, drive prefixes, and `..` traversal are rejected;
- Phase 1 content encoding is exactly UTF-8;
- content must be UTF-8 encodable without normalization;
- `size_bytes` equals the exact UTF-8 byte length;
- `line_count` uses the same `str.splitlines()` behavior as the collector;
- `sha256` equals SHA-256 over the exact UTF-8 bytes;
- unknown asset fields are rejected.

## 4. Compatibility behavior

The safe validator performs these steps in order:

1. require a JSON object;
2. read only `schema_version`;
3. reject a missing or malformed version;
4. reject an unsupported version;
5. validate the remaining strict payload;
6. return only safe error codes and field paths on failure.

For the pre-1.0 `0.1.x` format:

```text
0.1.0 reader + 0.1.9 baseline = compatible
0.1.0 reader + 0.2.0 baseline = incompatible
1.0.0 baseline               = incompatible
```

Stable validation codes are:

```text
invalid_json
invalid_root
missing_schema_version
invalid_schema_version
unsupported_schema_version
invalid_payload
```

## 5. Deterministic serialization

`encode_baseline_json()` serializes validated models using:

- UTF-8-capable JSON (`ensure_ascii=False`);
- two-space indentation;
- lexicographically sorted object keys;
- exactly one final newline;
- the already validated canonical asset order.

Repeated decode/encode cycles must produce identical text.

## 6. JSON Schema export

The current standalone schema is generated with:

```python
from pathlib import Path

from agentsec.baselines import export_baseline_json_schema

export_baseline_json_schema(Path("schemas"))
```

This writes:

```text
schemas/baseline.schema.json
```

The generated document uses JSON Schema Draft 2020-12 and includes:

```text
x-agentsec-baseline-schema-version: 0.1.0
```

## 7. Security boundaries

- Baseline JSON is untrusted input even when it is expected to be approved.
- Decoding does not execute asset content, links, code blocks, skills, or tools.
- Full asset content may contain secrets and must not appear in errors or logs.
- The in-memory JSON decoder assumes the caller has already enforced a file-size
  limit; `baseline create` enforces a 256 MiB hard filesystem limit.
- SHA-256 provides content consistency, not approval authenticity.
- Baselines are never updated implicitly by `scan` or `diff`.
- Signatures and approval identity are not part of Phase 1.

## 8. Public Python interface

```python
from agentsec.baselines import (
    Baseline,
    BaselineAsset,
    BaselineMetadata,
    BaselineValidationCode,
    BaselineValidationError,
    decode_baseline_json,
    encode_baseline_json,
    export_baseline_json_schema,
    validate_baseline_payload,
)
```

## 9. P1-12 acceptance evidence

- the baseline has an independent `0.1.0` schema version;
- scanner/config/domain/rule/risk versions are retained;
- Git commit and dirty state are representable;
- every asset retains path, type, source, exact content, byte size, line count,
  encoding, and SHA-256;
- content and metadata consistency is enforced;
- version compatibility is checked before payload parsing;
- JSON serialization and schema export are deterministic;
- invalid values are not copied into user-facing validation errors.
