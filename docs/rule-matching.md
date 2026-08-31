# AgentSec Deterministic Text Rule Matching

- Task: `P1-18`
- Status: Complete
- Decision date: 2026-08-18
- Rule-pack version: `0.1.0`
- Decision record: `docs/decisions/0007-bounded-text-matching.md`

## 1. Purpose

P1-18 implements reusable deterministic adapters for the P1-17 `Rule`
Protocol:

```text
KeywordRule
RegexRule
KeywordCondition
RegexCondition
ContextWindow
MatchMode
```

They detect trusted literal or restricted-regex patterns in safely parsed
Markdown source lines, preserve exact 1-based evidence locations, and optionally
require supporting terms within a bounded context window.

P1-18 does not register the first production security rule pack, calculate risk,
assign confidence, render Findings, or change CI policy. P1-19 now implements
multi-rule execution, isolation, and unscored Finding deduplication; the remaining
work begins with P1-20.

## 2. Matching pipeline

One adapter evaluation follows:

```text
RuleContext consistency already validated
→ check RuleScope asset applicability
→ choose configured MarkdownBlockKind values
→ expand blocks to unique physical source-line numbers
→ evaluate primary keyword or safe-regex condition per line
→ evaluate optional bounded supporting context
→ retain an exact bounded source excerpt
→ return source-ordered RuleFindingCandidate objects
```

The implementation reads only the in-memory `RuleContext`. It never opens a
file, resolves a reference, reads an environment variable, executes source,
uses the shell, accesses the network, invokes a Skill, or connects to MCP.

## 3. Why matching uses physical source lines

P1-18 matches exact physical source lines covered by selected Markdown blocks,
not rendered HTML or a reconstructed semantic document.

This decision provides:

- exact source line numbers without approximate offset mapping;
- direct excerpt verification through `RuleEvidenceCandidate.materialize`;
- deterministic behavior across parser/rendering changes;
- one candidate per matching source line;
- deduplication of lines that belong to overlapping list/code blocks;
- no rendering or dereferencing step.

The tradeoff is that Markdown syntax remains present. For example:

```markdown
shell **command**
```

will not match the literal phrase `shell command`, although separate keywords or
an approved safe regex may match it. Semantic text normalization remains a
future enhancement and must not weaken evidence location accuracy.

## 4. Keyword conditions

`KeywordCondition` and `KeywordRule` support:

```text
one to 32 keywords
one to 128 characters per keyword
case-sensitive or case-insensitive matching
optional Unicode-aware whole-word boundaries
ANY or ALL combination mode
```

Keywords are trusted rule-pack configuration, not project configuration and not
read from scanned Markdown.

Keywords are escaped before compilation, so regex metacharacters inside a
keyword have literal meaning. Case-insensitive duplicate keywords such as
`Shell` and `shell` are rejected.

### 4.1 ANY

`MatchMode.ANY` accepts the earliest occurrence of any configured keyword on the
source line. Pattern declaration order does not determine the candidate.

### 4.2 ALL

`MatchMode.ALL` requires every configured keyword on the same primary source
line. One candidate is emitted for that line.

### 4.3 Whole-word option

`whole_word=True` requires both ends of a literal match to be outside a Unicode
alphanumeric or underscore character. It is implemented without regex
lookaround.

Whole-word mode is useful for English identifiers such as `exec`. It should be
used cautiously for languages whose words are not separated by spaces.

## 5. Conservative safe-regex dialect

`RegexCondition` and `RegexRule` use Python `re`, but do not accept arbitrary
Python regex syntax. Patterns are trusted built-in rule definitions and must pass
a conservative validator before compilation.

Supported building blocks include:

```text
literal text
escaped literals and classes such as \b, \s, \d and \w
anchors ^ and $
character classes such as [A-Za-z0-9_-]
non-capturing alternatives such as (?:exec|eval)
optional single atoms with ?
fixed repetition such as {4}
finite repetition such as {1,8}
```

The dialect rejects:

```text
unescaped wildcard .
unbounded * and +
open-ended {m,}
lookahead and lookbehind
capturing groups
backreferences
inline flags
conditional and named groups
quantified groups
lazy quantifiers
empty-match patterns
more than one variable repetition per pattern
invalid, empty, multiline, NUL-containing, duplicate, or oversized patterns
```

Limits are:

| Limit | Value |
|---|---:|
| Regex patterns per condition | `16` |
| Pattern characters | `256` |
| Fixed repetition upper bound | `64` |
| Variable repetition upper bound | `32` |
| Variable repetitions per pattern | `1` |
| Physical regex subject line | `65,536` characters |

This is intentionally more restrictive than Python `re`. New syntax must not be
added merely to make one rule shorter. Rule authors should prefer multiple
literal conditions or a bounded context clause when that is clearer and safer.

Regex failures use fixed messages and never copy a rejected pattern or scanned
source value into an exception.

## 6. Context windows

`ContextWindow` attaches one `KeywordCondition` or `RegexCondition` to a primary
rule. It supports:

```text
before_lines: 0 through 20
after_lines: 0 through 20
include_match_line: true or false
```

At least one source line must be searchable. A window with zero lines and
`include_match_line=False` is rejected.

Context lines are physical lines from the same bounded `RuleContext`. They do
not need to belong to the same Markdown block, but they never cross into another
asset.

### 6.1 ANY context

For `MatchMode.ANY`, the nearest supporting line wins. Ties prefer the lower
source line, then the earliest character span. This makes output independent of
pattern declaration order.

### 6.2 ALL context

For `MatchMode.ALL`, every context pattern must occur somewhere in the bounded
window. Different terms may be supported by different lines. The nearest match
for each pattern is retained, then Evidence is sorted by source line.

### 6.3 Evidence

The primary match line and selected supporting lines become one
`RuleFindingCandidate`. Materialization binds the authoritative asset path and
SHA-256 from `RuleContext`.

## 7. Markdown block selection

Text rule adapters require `RuleTarget.MARKDOWN_BLOCK` in `RuleMetadata.scope`.
A rule may select any non-empty frozen set of:

```text
heading
paragraph
list_item
fenced_code
indented_code
```

The secure default includes all Phase 1 block kinds. A concrete rule can exclude
code blocks to reduce example-related false positives, or target only code
blocks when executable declarations are the intended signal.

Because list and code structures may overlap, source lines are placed in a set
and scanned once in ascending order.

## 8. Evidence excerpt bounds

Evidence line numbers always identify the exact physical source line. The
optional excerpt is an exact substring of that line and is never synthesized.

Limits are:

| Limit | Value |
|---|---:|
| Evidence excerpt | `512` characters |
| Candidates per rule per asset | `256` |
| Keyword subject line | `65,536` characters |
| Regex subject line | `65,536` characters |

For a long line, the excerpt window is positioned around the selected match.
No ellipsis is inserted because an ellipsis would not be exact source content.
The later reporter still must apply secret redaction and control-character
escaping before display.

If candidate count or physical line limits are exceeded, evaluation raises the
fixed safe `RuleEvaluationError` rather than silently truncating results. The
P1-19 runner converts that per-rule failure into visible `RULE_ERROR` coverage.

## 9. Determinism

For identical metadata, patterns, block selection, context, RuleContext, and
rule-pack version, evaluation returns identical candidates.

Determinism is maintained by:

- immutable pattern tuples and block-kind frozensets;
- validated unique pattern declarations;
- sorted physical line numbers;
- one scan per physical line;
- source/proximity-based selection rather than declaration order;
- source-ordered unique candidate Evidence;
- no clock, randomness, environment, I/O, network, or process state.

## 10. Version decision

P1-18 originally added generic matching adapters without production Rule IDs. At
that task boundary:

```text
DOMAIN_SCHEMA_VERSION = 0.2.0  (unchanged)
RULE_PACK_VERSION = 0.1.0      (unchanged)
RISK_MODEL_VERSION = 0.1.0     (unchanged)
```

The adapters are Python implementation modules, not serialized report fields.
ADR-0007 records their safety and matching semantics. P1-20 now defines the first
15 production Rule IDs and Rule Pack `0.2.0` in `docs/rule-pack.md`. Any later
material change to their trigger meaning follows the Rule ID and Rule Pack policy.

## 11. Deferred behavior

P1-18 intentionally does not implement:

- P1-20 production rules are now implemented in `docs/rule-pack.md`;
- P1-19 multi-rule execution, exception isolation, Finding identity, and
  deduplication are now implemented in `docs/rule-pipeline.md`;
- parser failure integration;
- risk likelihood, impact, severity, or score;
- evidence confidence;
- hard-gate metadata;
- terminal or JSON Finding output;
- repository-local executable rules;
- cross-asset context or semantic/LLM matching.
