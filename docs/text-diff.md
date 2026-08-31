# AgentSec Text Diff

- Task: `P1-15`
- Status: Complete
- Decision date: 2026-08-18
- Depends on: P1-14 Asset Diff

## 1. Purpose

Text Diff converts a coherent P1-14 Asset Diff into bounded line-oriented
before/after evidence. It preserves exact source line numbers and line endings
for retained evidence without executing or interpreting Agent instructions.

P1-15 supports modified, added, and removed files:

- modified files compare Baseline exact content with current collected content;
- added files produce one-sided added-line evidence;
- removed files produce one-sided removed-line evidence.

Text Diff is not semantic Diff, a Finding, a severity decision, or proof that a
change is unsafe.

## 2. Inputs

`DeterministicTextDiffer.compare()` requires:

```text
validated Baseline
complete current CollectionResult
complete coherent AssetDiffResult
```

Before producing evidence, the differ independently verifies:

- current collection coverage is complete;
- Baseline paths are unique;
- current collection paths are unique;
- AssetChange paths are unique;
- the complete AssetChange set exactly matches the Baseline/current path and
  SHA-256 comparison;
- each change's before/after presence matches added/removed/modified semantics;
- each change hash matches the corresponding asset metadata;
- retained input content matches UTF-8 byte size, line count, and SHA-256.

A caller cannot suppress a real modified asset by passing an incomplete
`AssetDiffResult`; the complete change set is recalculated and compared before
line evidence is created.

## 3. Line model

Each retained `TextDiffLine` contains:

```text
kind: context | added | removed
before_line_number: int | null
after_line_number: int | null
text: bounded exact line text
original_character_count: int
truncated: bool
```

Number semantics are:

```text
context → before and after line numbers
added   → after line number only
removed → before line number only
```

Line text uses `splitlines(keepends=True)`, so retained evidence distinguishes:

```text
"line\n"
"line"
"line\r\n"
```

Line endings remain part of `text` unless the line itself reaches the character
limit. Renderers must escape them rather than printing raw untrusted text.

## 4. Hunk model

Each `TextDiffHunk` contains:

```text
before_start_line
before_line_count
after_start_line
after_line_count
lines
omitted_line_count
truncated
```

Hunks are generated with deterministic `difflib.SequenceMatcher` grouped
opcodes and three lines of context by default. A replace operation is represented
as removed lines followed by added lines, matching unified-diff semantics.

The hunk range counts describe the complete source region even when retained
line evidence is truncated.

## 5. Asset and aggregate status

Each changed asset has one status:

| Status | Meaning |
|---|---|
| `complete` | All generated Hunk and line evidence was retained |
| `truncated` | Matching completed, but some assets, Hunks, lines, or line characters were omitted by output limits |
| `input_limit_exceeded` | Matching was not attempted because input size, line count, or complexity exceeded a hard limit |

`AssetTextDiff` also retains:

```text
AssetChange
before_line_count
after_line_count
hunks
omitted_hunk_count
```

`TextDiffResult` contains:

```text
assets
omitted_asset_count
complete
```

`complete` is false when any asset is truncated, input-limited, or omitted by the
global asset limit.

## 6. Default resource limits

### Input limits per side

```text
maximum UTF-8 bytes:           1,048,576
maximum source lines:          10,000
maximum before×after product: 25,000,000
```

The line-product limit bounds pathological quadratic SequenceMatcher cases. For
added or removed files one side has zero lines, so whole-file one-sided evidence
can still be produced subject to output limits.

Inputs beyond these limits return `input_limit_exceeded` with no Hunk data. This
is a visible evidence-coverage limitation, not a silent success.

### Output limits

```text
context lines around a change:       3
maximum changed assets retained:    25
maximum Hunks per retained asset:   25
maximum evidence lines per Hunk:    40
maximum characters per retained line: 500
```

These defaults bound retained line text to roughly 12.5 million characters in
the theoretical maximum result, before object overhead.

## 7. Truncation policy

When the asset or Hunk count exceeds a limit, evidence is retained from both the
beginning and end rather than only from the beginning.

Within a large Hunk:

1. changed lines are prioritized over context lines;
2. when changed lines exceed the limit, head and tail changed lines are kept;
3. remaining capacity is used for head and tail context;
4. original order is restored in the retained output;
5. `omitted_line_count` records how many logical evidence lines were excluded.

Long retained lines keep:

```text
text[:max_characters_per_line]
original_character_count
truncated = true
```

No ellipsis is inserted into raw evidence. P1-16 renderers can add a display
marker while preserving the distinction between source text and UI decoration.

## 8. Stable safe failure codes

| Code | Meaning |
|---|---|
| `incomplete_current_coverage` | Current CollectionResult is incomplete |
| `duplicate_baseline_path` | Baseline path identity is ambiguous |
| `duplicate_current_path` | Current collection path identity is ambiguous |
| `duplicate_asset_change_path` | Asset Diff contains duplicate change identity |
| `incoherent_asset_change` | Asset Diff is missing, inventing, or misrepresenting a path/hash change |
| `content_integrity_mismatch` | Retained content does not match validated metadata |

Errors contain no asset paths or content. Input and output limit conditions are
represented as explicit result status rather than exceptions.

## 9. Public Python interface

```python
from agentsec.diffing import (
    AssetTextDiff,
    DeterministicTextDiffer,
    TextDiffCode,
    TextDiffError,
    TextDiffHunk,
    TextDiffLimits,
    TextDiffLine,
    TextDiffLineKind,
    TextDiffResult,
    TextDiffStatus,
)

text_diff = DeterministicTextDiffer().compare(
    baseline=baseline,
    current_collection=current_collection,
    asset_diff=asset_diff,
)
```

The P1-15 objects are internal immutable dataclasses. They are not added to the
public Domain JSON Schema. P1-16 and later report tasks will define the
versioned delivery representation.

## 10. Security boundaries

- Source content remains untrusted data and is never executed.
- Text Diff performs no imports, shell commands, hooks, links, tools, or network
  access.
- Incomplete current coverage never becomes deleted-line evidence.
- The complete AssetChange set is independently verified before evidence use.
- Input limits apply before SequenceMatcher.
- Output limits apply at asset, Hunk, line, and character levels.
- Truncation and input-limit states are always visible.
- Raw retained lines may contain secrets or terminal control characters.
- `TextDiffLine.text` must not be rendered directly; P1-16/reporters must apply
  secret redaction and output-specific escaping.
- Text Diff remains evidence of textual drift, not a vulnerability or Finding.

## 11. Acceptance evidence

Tests cover:

- replacement with context;
- before/after line numbers;
- insertion and deletion;
- added and removed whole-file evidence;
- final-newline-only changes;
- empty unchanged result;
- long-line truncation and original length;
- Hunk line limits with changed-line prioritization;
- Hunk head/tail retention;
- byte, line, and comparison-product limits;
- incomplete current coverage;
- incoherent AssetChange presence;
- current content-integrity mismatch without content leakage;
- duplicate AssetChange paths;
- omitted real AssetChange detection;
- invalid limits;
- global changed-asset output bound;
- P1-13 Baseline → P1-14 Asset Diff → P1-15 Text Diff integration.

## 12. Deferred work

- P1-16 loads a Baseline and renders Asset/Text Diff in redacted, escaped
  terminal and versioned JSON output.
- P1-17 and later rules may use Diff evidence but must not assume every text
  change is risky.
- LLM semantic Diff, capability Diff, rename inference, and natural-language
  equivalence are not part of P1-15.
