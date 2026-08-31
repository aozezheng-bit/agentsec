# AgentSec Safe Markdown Parser

- Tasks: `P1-09`, `P1-10`, `P1-11`
- Status: Complete
- Decision date: 2026-08-18
- Parser: `markdown-it-py` CommonMark tokenizer

## Purpose

P1-09 converts bounded, UTF-8 Markdown collected by P1-05 through P1-08 into a
small deterministic block model for later rules. P1-10 adds safe frontmatter
and target-reference structures. Parsing remains data-only: it does not render
HTML, execute code or YAML tags, dereference links, import target code, or
connect to tools and MCP servers.

## Dependency and configuration

AgentSec declares `markdown-it-py>=4,<5` as a direct runtime dependency. The
parser uses the CommonMark preset with raw HTML parsing disabled and no plugins.
Only tokenization is used; the renderer is never called.

The collector has already enforced path safety, file-size, depth, asset-count,
and UTF-8 constraints before parser input is created.

## Output model

`ParsedMarkdown` contains an ordered tuple of immutable `MarkdownBlock`
instances. P1-09 emits:

| Block kind | Metadata |
|---|---|
| `heading` | level and complete heading path |
| `paragraph` | normalized visible text |
| `list_item` | ordered/unordered flag and nesting depth |
| `fenced_code` | code content and fence info string |
| `indented_code` | code content |

List-item paragraphs are represented by the list-item block instead of a
second duplicate paragraph block. Nested list items receive independent blocks.
Code blocks inside list items may overlap the parent list-item source range,
which preserves their structural relationship.

## Source evidence convention

markdown-it reports zero-based half-open line maps. AgentSec converts them to:

```text
start_line: 1-based inclusive
end_line:   1-based inclusive
```

For example, a token map `[2, 4]` becomes lines `3` through `4`.

Every block stores two separate representations:

- `raw_text`: the exact source slice, including Markdown syntax and retained
  line endings;
- `text`: normalized visible analysis text with emphasis/link wrappers removed.

This separation lets future rules analyze normalized text while findings use
raw source-backed evidence.

## Heading context

The parser maintains a heading stack. Every block receives a `heading_path`:

```text
# Root
## Deployment
paragraph
```

produces:

```text
("Root", "Deployment")
```

for the paragraph. A new heading removes headings at the same or deeper level.

## Malformed Markdown

CommonMark intentionally tolerates many malformed constructs. An unclosed code
fence, for example, becomes a fenced-code block extending to end-of-document;
it is not executed and does not crash the scan.

Unexpected parser or adapter exceptions are isolated per asset. The affected
asset moves from scanned to skipped coverage, receives a `parse_error` issue,
and other collected assets continue. Error messages never include source text
or dependency exception details.

## Frontmatter and references

P1-10 recognizes first-line YAML frontmatter, safely loads JSON-like mapping
values, masks the region before CommonMark parsing, and preserves malformed
regions without partial trust. It also extracts Markdown links, images,
autolinks, and reference definitions without dereferencing targets.

The full policy, malformed codes, target classification, and line-range
semantics are defined in `docs/frontmatter-references.md`.

## Obfuscation indicators

P1-11 attaches deterministic `ObfuscationIndicator` structures for Base64-like
tokens, long lines/blocks, zero-width and bidirectional controls, other control
characters, and mixed Latin/Cyrillic/Greek word-like tokens. Indicators remain
separate from Findings and do not affect coverage or exit codes.

Thresholds, Unicode code points, false-positive boundaries, and evidence
semantics are defined in `docs/obfuscation-indicators.md`.

## Deferred behavior

The parser still does not assign semantic security intent, likelihood, impact,
severity, or confidence. Deterministic security rules begin later in the Phase
1 sequence.
