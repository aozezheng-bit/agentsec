# AgentSec Diff CLI

- Task: `P1-16`
- Status: Complete
- Decision date: 2026-08-18
- Diff output version: `0.1.0`
- Decision record: `docs/decisions/0005-diff-cli-output.md`

## 1. Purpose

`agentsec diff` connects the Phase 1 snapshot and deterministic comparison
pipeline to safe terminal and JSON delivery:

```text
bounded Baseline read
→ current project configuration
→ bounded current collection
→ Asset Diff
→ bounded Text Diff
→ secret redaction
→ control-character escaping
→ Text or JSON output
```

The command reports textual drift. It does not run rules, assign severity, or
fail solely because changes exist.

## 2. Commands

Use the conventional Baseline path:

```bash
agentsec diff <project-root>
```

which reads:

```text
<project-root>/.agentsec/baseline.json
```

Choose explicit inputs:

```bash
agentsec diff <project-root> \
  --baseline path/to/baseline.json \
  --config path/to/config.yaml
```

Choose output format:

```bash
agentsec diff <project-root> --format text
agentsec diff <project-root> --format json
```

Format precedence is:

```text
CLI --format
→ project config output.format
→ built-in text default
```

## 3. Bounded Baseline Reader

`BaselineFileReader` applies these controls before payload use:

- filename must end in `.json`;
- final symbolic links are rejected;
- input must be a regular file;
- hard maximum size is 256 MiB;
- reads stop at maximum plus one byte;
- UTF-8 decoding is mandatory;
- JSON is parsed only after the bounded read;
- Baseline Schema version is checked before remaining payload validation;
- validation errors never copy rejected values.

Stable read errors distinguish missing, invalid path, symlink, oversized,
invalid UTF-8, invalid Baseline, and generic read failure internally. The CLI
maps all Baseline input failures to exit code `4`.

## 4. Application pipeline

`CollectionProjectDiffEngine` composes:

```text
BaselineFileReader
MarkdownAssetCollector
fingerprint_collection_config
DeterministicAssetDiffer
DeterministicTextDiffer
```

It returns one internal `ProjectDiffResult` containing:

```text
validated Baseline and path
complete current CollectionResult
AssetDiffResult
TextDiffResult
current VersionSet
Baseline/current version comparison
```

Current collection must be complete. Invalid UTF-8, path-safety failures,
resource limits, and unreadable selected assets return incomplete coverage
rather than false removed-file evidence.

## 5. Version provenance

Successful output compares stored Baseline metadata with the current:

```text
package/scanner version
config schema version
domain schema version
rule-pack version
risk-model version
```

Version provenance differences are warnings. Baseline Schema compatibility is
already enforced by the reader. Collection configuration mismatch is stronger:
it means the compared asset scope differs and maps to exit code `4`.

The JSON delivery format has an independent source-of-truth constant:

```text
DIFF_OUTPUT_VERSION = 0.1.0
```

This version is included in `VersionSet` and emitted as `format_version`.

## 6. Secret redaction

Before any path or retained line reaches Text or JSON output, the shared
`SecretRedactor` performs deterministic replacement. P1-26 hardens it to cover:

- vendor/namespace-prefixed token, API/access key, password, passphrase,
  credential, connection-string, database URL, client/signing/webhook secret,
  and private-key assignments;
- Authorization, Proxy-Authorization, API/auth/access/session headers, Cookie,
  and Set-Cookie values;
- sensitive long CLI options;
- passwords embedded in URL user-info and sensitive query/fragment parameters;
- common AWS, GitHub, GitLab, Slack, Stripe, OpenAI/Anthropic, Google, npm, PyPI,
  and JWT-shaped values;
- complete and unterminated private-key blocks;
- zero-width, control-character, and fullwidth-key bypass attempts;
- ambiguous multiline values through fail-closed remaining-input redaction.

The deterministic placeholder is:

```text
<redacted>
```

Detection uses a normalized private view mapped back to original source spans.
Redaction is idempotent and may intentionally over-match benign values in a
sensitive context. This is preferred to printing a possible full secret value.
Generic Base64, entropy, and hexadecimal matching is intentionally excluded so
SHA-256 and encoded-looking Evidence remain reviewable. See
`docs/secret-redaction.md`.

## 7. Output escaping

After redaction, renderers escape:

```text
backslash
newline
carriage return
tab
C0/C1 controls
ANSI ESC
Unicode surrogate characters
zero-width format characters
bidi controls
other Unicode Cf controls
Unicode line and paragraph separators
```

Examples:

```text
newline       → \n
ESC           → \u001b
zero-width    → \u200b
bidi override → \u202e
```

Paths use the same sanitizer as retained line text. Raw `TextDiffLine.text` is
never printed directly.

## 8. Text output

Text output includes:

- safe Baseline path;
- total and per-type AssetChange counts;
- collection-scope match state;
- Text Diff completeness;
- current scanner/domain/Baseline versions;
- stored version-vector comparison;
- file-level before/after hashes;
- per-asset Text Diff status and line counts;
- bounded Hunk ranges;
- redacted and escaped context/added/removed lines;
- omitted asset/Hunk/line counts and line truncation notices.

Changes alone do not cause a nonzero exit before policy tasks are implemented.

## 9. JSON output

Every JSON document contains:

```text
format: agentsec-diff
format_version: 0.1.0
status
versions
baseline
version_comparison
collection
summary
changes
```

JSON uses:

- sorted keys;
- two-space indentation;
- UTF-8 Unicode;
- one trailing newline;
- sanitized paths and line values;
- explicit nulls for absent before/after hashes and line numbers.

Operational JSON errors retain the same format and include:

```text
status: error
error.code
error.message
error.exit_code
coverage, when current collection was incomplete
```

P1-25 introduces a separate `agentsec-assessment` format and Assessment Output
version. It does not reuse or silently change the `agentsec-diff` `0.1.x` field
meaning.

## 10. Exit codes

| Condition | Exit code |
|---|---:|
| Comparable, complete Diff with zero or more changes | `0` |
| Current collection incomplete | `2` |
| Text Diff truncated, input-limited, or omitted assets | `2` |
| Invalid project configuration | `3` |
| Missing, unsafe, oversized, invalid, or incompatible Baseline | `4` |
| Collection configuration fingerprint mismatch | `4` |
| Asset/Text Diff internal consistency failure | `5` |
| Invalid CLI syntax through installed entry point | `64` |

Priority for a successful internal result is:

```text
scope mismatch → 4
else incomplete Text Diff → 2
else → 0
```

Version-vector mismatch alone is a warning and does not change the exit code.

## 11. Security boundaries

- Baseline and current content remain untrusted data.
- No scanned code, link, script, hook, skill, or tool is executed.
- No network access is performed.
- Baseline reads are bounded and reject final symlinks.
- Current collection keeps existing path and resource controls.
- Incomplete current coverage never becomes deletion evidence.
- Text matching and retained output remain bounded by P1-15 limits.
- Text and JSON receive identical redaction and escaping.
- Output contains textual drift evidence, not a confirmed vulnerability.
- CI risk blocking remains disabled.

## 12. Public implementation seams

```python
from agentsec.application import (
    CollectionProjectDiffEngine,
    ProjectDiffEngine,
    ProjectDiffRequest,
    ProjectDiffResult,
)
from agentsec.baselines import BaselineFileReader
from agentsec.reporting import DiffJsonRenderer, DiffTextRenderer
```

The CLI can inject alternative engines or renderers in tests without executing
project content.

## 13. Acceptance evidence

Tests cover:

- valid, missing, non-JSON, symlink, directory, oversized, invalid UTF-8, invalid
  JSON, and incompatible Baseline reads;
- complete Baseline→Collection→Asset Diff→Text Diff composition;
- safe collection, Asset Diff, and Text Diff failure boundaries;
- scope and version-vector mismatch;
- assignment, Authorization, URL credential, token-shape, and private-key
  redaction;
- ANSI, newline, backslash, zero-width, and bidi escaping;
- deterministic Text and JSON rendering;
- default and explicit Baseline paths;
- config and CLI format precedence;
- Text and JSON errors;
- incomplete current coverage;
- Scope Mismatch exit `4`;
- Text truncation exit `2`;
- secret/control safety in both formats;
- installed runner exit-code behavior.

## 14. Deferred work

- P1-17 introduces the deterministic Rule interface.
- P1-18 adds keyword and context matching.
- P1-24/P1-25 now implement direct general Assessment Text and JSON reporters.
- Diff JSON does not yet include Findings, severity, confidence, or policy.
- SARIF, HTML, semantic Diff, capability Diff, and LLM analysis remain later
  work.
