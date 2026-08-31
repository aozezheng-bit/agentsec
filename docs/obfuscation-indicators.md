# AgentSec Obfuscation Indicators

- Task: `P1-11`
- Status: Complete
- Decision date: 2026-08-18

## Purpose

P1-11 adds deterministic anomaly metadata to `ParsedMarkdown`. An
`ObfuscationIndicator` is not a vulnerability, Finding, severity, or proof of
malicious intent. It records source location and an explainable metric so later
rules can combine it with instruction context and other evidence.

Indicators do not change `ScanCoverage`, CLI exit codes, or finding counts.

## Indicator structure

Each indicator contains:

```text
kind
start_line
end_line
character_count
codepoints
scripts
heading_path
```

The matched token is not copied into the indicator. Base64-like candidates and
mixed-script words remain available only in the already collected source and
parsed blocks. This reduces accidental duplication of secret-shaped text into
future logs or reports.

## Deterministic thresholds

| Indicator | Threshold or condition |
|---|---|
| `base64_like` | At least 40 characters, decodable to at least 24 bytes, at least two character classes, Shannon entropy at least 3.5, not pure hexadecimal |
| `long_line` | At least 1,000 Unicode characters on one source line |
| `long_block` | At least 4,000 characters in one Markdown block or frontmatter region |
| `zero_width` | One or more selected zero-width code points |
| `bidi_control` | One or more Unicode bidirectional control code points |
| `control_character` | Other `Cc` or `Cf` characters after zero-width/bidi separation |
| `mixed_script_confusable` | One word-like token with at least four letters, containing Latin plus Cyrillic or Greek |

The constants are exported by `agentsec.parsers` so regression tests and later
rules can reference the exact active values.

## Base64-like heuristic

The detector supports standard and URL-safe Base64 alphabets. It transiently
decodes a bounded candidate only to confirm structural validity and decoded
length; decoded bytes are never retained, interpreted, executed, imported, or
reported.

Pure 40+ character strings are not automatically flagged. The heuristic rejects
pure hexadecimal values, low-entropy repetition, invalid padding, and candidates
that decode below the minimum byte length.

False positives remain possible for legitimate encoded configuration, images,
certificates, hashes using a non-hex alphabet, or generated identifiers. The
indicator must therefore remain separate from a risk Finding.

## Unicode indicators

Zero-width detection includes:

```text
U+200B ZERO WIDTH SPACE
U+200C ZERO WIDTH NON-JOINER
U+200D ZERO WIDTH JOINER
U+2060 WORD JOINER
U+FEFF ZERO WIDTH NO-BREAK SPACE
```

A single U+FEFF at the beginning of the file is treated as a UTF-8 BOM and is
not flagged. The same code point elsewhere is flagged.

Bidirectional controls include LRM/RLM, embedding/override controls, isolates,
and Arabic Letter Mark. Other Unicode `Cc`/`Cf` characters are grouped under
`control_character`. Evidence stores safe `U+XXXX` labels rather than copying
invisible source characters.

## Mixed-script heuristic

The detector examines individual word-like tokens. It flags only these script
combinations:

```text
Latin + Cyrillic
Latin + Greek
```

Normal separated multilingual prose such as `English 中文` is not flagged, and
a token written entirely in Cyrillic or Greek is not flagged. The heuristic is
intended to expose possible homoglyph usage such as a Cyrillic `а` embedded in
an otherwise Latin identifier.

This is not full Unicode confusable analysis. It does not use the Unicode
confusables table, normalize identifiers, or claim that two strings are
visually equivalent.

## Source scope

The analyzer scans the original bounded source, including frontmatter and code
blocks. Encoded data inside a code block remains an indicator because code may
still declare an Agent capability, but the content is never executed.

Long-block detection uses Parser block ranges. Long frontmatter is treated as a
block-like region. Every indicator receives the heading context active at its
source line when one exists.

## Failure isolation

The analyzer runs inside `MarkdownItParser`. Unexpected analyzer exceptions are
wrapped as the fixed `MarkdownParseError` message. The AssessmentEngine then
moves only the affected asset from scanned to skipped coverage and continues
with remaining assets. Source text and dependency exception details are not
included in the coverage issue.

## Deferred behavior

P1-11 does not:

- decode or interpret an instruction payload;
- use Unicode confusables data for exhaustive visual comparison;
- decide that an indicator is malicious;
- assign likelihood, impact, severity, or confidence;
- create a Finding or block CI;
- normalize evidence before preserving the raw source.

Later deterministic rules decide when an indicator is relevant to a security
finding.
