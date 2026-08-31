# AgentSec Collector Resource Limits

- Task: `P1-08`
- Status: Complete
- Decision date: 2026-08-18
- Domain Schema: `0.2.0`

## Purpose

The target repository is untrusted and may contain very large files, deep
directory structures, or large numbers of matching Agent assets. The collector
must bound memory use and traversal work while making every limit-triggered gap
visible in `ScanCoverage`.

## Limits

| Configuration | Default | Enforcement |
|---|---:|---|
| `max_file_size_bytes` | 1,048,576 | Maximum bytes read from one selected asset |
| `max_depth` | 20 | Maximum logical directory depth below the project root |
| `max_assets` | 1,000 | Maximum selected assets processed before global stop |

## File-size semantics

A selected regular file is checked using its revalidated size metadata. Files
already larger than the configured maximum are skipped without opening their
content.

To handle growth between metadata validation and reading, the collector reads
at most `max_file_size_bytes + 1` bytes. Receiving the extra byte proves the
file is oversized, so it is skipped with a `too_large` coverage issue. The
collector never uses an unbounded `read()` for asset content.

A file exactly equal to the configured maximum is accepted.

## Depth semantics

The project root has logical directory depth `0`. Therefore:

- root files are always within the depth boundary;
- `max_depth: 1` permits files in the root and in immediate child directories;
- a directory at depth `2` is not traversed and receives `depth_exceeded`.

Depth is measured using the logical evidence path. Internal directory links
still pass P1-07 canonical containment and cycle checks before depth policy is
applied. Excluded directories are pruned before depth accounting and do not
create coverage issues.

Assets hidden below a depth-pruned directory are not enumerated, so they cannot
be counted individually. The directory-level issue makes coverage incomplete.

## Asset-count semantics

Every selected asset candidate that reaches asset processing consumes one
slot, including a candidate later skipped because it is unreadable, unsafe,
oversized, malformed, or non-regular.

When the first candidate beyond `max_assets` is encountered:

1. it is counted as discovered and skipped;
2. an `asset_limit_exceeded` issue records its logical path;
3. collection stops globally without inspecting later paths.

As a result, the reported discovered count may be `max_assets + 1`: the extra
entry is the deterministic sentinel proving that more selected assets existed.

## Coverage behavior

| Limit | Issue code | Count effect |
|---|---|---|
| File size | `too_large` | Asset is discovered and skipped |
| Directory depth | `depth_exceeded` | Directory issue; unknown descendants are not counted |
| Asset count | `asset_limit_exceeded` | First overflow asset is discovered and skipped; scan stops |

Any triggered limit sets `coverage.complete` to `false`, which maps to CLI exit
code `2`.
