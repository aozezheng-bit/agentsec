# AgentSec Frontmatter and Reference Extraction

- Task: `P1-10`
- Status: Complete
- Decision date: 2026-08-18

## Purpose

P1-10 extracts YAML frontmatter and Markdown target declarations as bounded,
source-backed data. It never executes YAML constructors, renders links, opens a
referenced file, performs DNS or HTTP requests, or connects to an MCP server or
tool.

The structures are internal Parser API types and do not change the public
Domain Schema.

## Frontmatter boundary

Frontmatter is recognized only when the first source line contains a
column-zero `---` marker, with optional UTF-8 BOM or trailing spaces. The first
subsequent column-zero `---` or `...` line closes the region.

A closed region is masked with whitespace before CommonMark tokenization while
preserving every line ending. This prevents frontmatter fields from becoming
false setext headings and keeps all later Markdown token line numbers aligned
with the original file.

If the opening delimiter has no closer:

- `frontmatter.status` is `malformed`;
- `issue_code` is `unclosed`;
- the complete raw region remains available as evidence;
- only the opening delimiter is masked;
- remaining lines are recovered as ordinary Markdown blocks;
- coverage remains complete because the content was preserved and analyzed.

## YAML safety policy

Frontmatter uses `yaml.SafeLoader`, but P1-10 applies stricter policy before
trusting values:

- the root must be a mapping;
- all mapping keys must be non-empty strings;
- duplicate keys are rejected at every mapping level;
- explicit YAML tags are rejected, including otherwise safe `!!str` tags;
- anchors and aliases are rejected;
- timestamps, sets, binary values, non-finite floats, and other YAML-specific
  value types are rejected;
- accepted values are null, bool, integer, finite float, string, sequence, and
  string-keyed mapping;
- sequences and mappings are converted to immutable tuples.

Malformed YAML is not partially trusted. It produces a `MarkdownFrontmatter`
with no fields and one of:

```text
unclosed
invalid_yaml
non_mapping
unsafe_yaml
duplicate_key
unsupported_value
```

These are Parser signals, not coverage failures. Later rules/reporters may turn
them into `malformed_content` findings.

Each valid top-level field records its name, immutable value, exact raw source,
and 1-based inclusive line range.

## Reference extraction

P1-10 extracts:

- inline Markdown links;
- images;
- CommonMark autolinks;
- reference-style link usages;
- reference definitions, including definitions not used elsewhere.

References inside fenced or indented code and inline-code spans are not treated
as active references.

Each `MarkdownReference` contains:

```text
kind
target_kind
target
label
title
start_line
end_line
raw_text
heading_path
```

Because markdown-it inline child tokens do not expose character offsets, an
inline reference uses the containing inline block's exact line range and raw
source slice. Reference definitions use their own definition-line map.

## Target classification

Target strings are classified without resolving them:

| Target kind | Examples |
|---|---|
| `external_url` | `https://example.com`, `//example.com/path` |
| `email` | `mailto:security@example.com` |
| `anchor` | `#approval` |
| `relative_path` | `docs/policy.md`, `../shared/SKILL.md` |
| `absolute_path` | `/etc/passwd`, `C:\\secrets.txt`, `file:///tmp/a` |
| `uri` | `custom:capability`, `javascript:alert(1)` |
| `empty` | `[]()` |

AgentSec intentionally overrides markdown-it's renderer-oriented dangerous-link
filter so schemes such as `javascript:` remain visible to security analysis.
This is safe because AgentSec never renders or opens the destination.

Plain text that only resembles a URL or path is not promoted to a reference in
P1-10 unless it uses Markdown link, image, autolink, or definition syntax. It
remains available in block `raw_text` and normalized `text` for later rules.

## Non-goals

P1-10 does not:

- follow relative paths;
- verify that referenced files exist;
- download URLs or images;
- resolve redirects, DNS, or repository links;
- infer tool availability from a path;
- execute YAML values, code blocks, or URI schemes;
- flag obfuscation or assign security severity.

Obfuscation indicators are P1-11. Deterministic reference-risk rules are later
Phase 1 tasks.
