# ADR-0007: Physical-Line Matching and a Bounded Regex Dialect

- Status: Accepted
- Date: 2026-08-18
- Task: P1-18

## Context

P1-18 must provide reusable keyword, regex, and limited context-window matching
for future Markdown rules. The matcher processes attacker-controlled source.
Arbitrary regular expressions can exhibit catastrophic backtracking, unbounded
output can exhaust memory, and matching normalized Markdown text can make exact
source-line evidence difficult or ambiguous.

Adding a timeout around Python `re` is not a dependable in-process control. A
thread timeout cannot preempt every regex execution, while a process-based regex
sandbox would add substantial execution and lifecycle complexity to the Phase 1
scanner. A third-party regex engine would add a new supply-chain dependency.

The matcher must also remain below the P1-19 seam: this task should not implement
a rule registry, multi-rule failure isolation, Finding deduplication, scoring,
or reporting.

## Decision

Implement `KeywordRule` and `RegexRule` as adapters satisfying the P1-17 `Rule`
Protocol, with these semantics:

1. Match exact physical source lines covered by selected `MarkdownBlockKind`
   values.
2. Expand overlapping blocks to unique ascending line numbers so one physical
   line is evaluated once.
3. Preserve exact 1-based line evidence and use only exact source substrings as
   excerpts.
4. Support finite literal keyword tuples with `ANY` or `ALL`, optional case
   sensitivity, and optional Unicode-aware word boundaries.
5. Support a conservative regex dialect rather than arbitrary Python `re`.
6. Regex allows literals, escapes, anchors, character classes, non-capturing
   alternatives, `?`, and finite `{m}` / `{m,n}` repetition.
7. Regex rejects wildcard `.`, `*`, `+`, open-ended repetition, capturing groups,
   quantified groups, lookaround, backreferences, inline flags, empty matching,
   and more than one variable repetition.
8. Bound regex pattern count, pattern length, repetition, and physical subject
   line length.
9. Bound keyword count, keyword length, and physical subject line length.
10. `ContextWindow` accepts one keyword or regex condition and at most 20 lines
    before and 20 lines after the primary match.
11. `ANY` context keeps the nearest support. `ALL` context may be satisfied by
    separate lines and keeps the nearest occurrence of each pattern.
12. Bind primary and supporting source lines into one unscored
    `RuleFindingCandidate`.
13. Bound retained excerpts to 512 exact source characters and candidates to 256
    per rule per asset.
14. Exceeding runtime line or candidate bounds raises fixed safe
    `RuleEvaluationError`; no result is silently truncated.
15. Matchers use no filesystem, environment, shell, network, Skill, MCP, Agent,
    or model dependency.
16. Do not register production Rule IDs or integrate matchers into `scan` in
    P1-18.

The physical-line model intentionally retains Markdown syntax. This accepts some
false negatives for phrases interrupted by markup in exchange for exact,
verifiable evidence. A future normalized-text matcher requires a separately
reviewed offset-mapping design.

P1-18 adds reusable implementations but no production rule-pack content, so
`RULE_PACK_VERSION` remains `0.1.0`. Domain and risk schemas are unchanged.

## Consequences

### Positive

- Every match has exact source-line provenance without approximate rendering
  offsets.
- The regex attack surface is substantially smaller and statically reviewable.
- Context matching supports common combinations such as action plus approval,
  production, secret, or network terms.
- Resource-limit failures can become visible coverage issues at the P1-19
  isolation seam.
- Concrete P1-20 rules can be small trusted metadata/pattern declarations.
- Matching remains deterministic and side-effect free.

### Negative

- The regex dialect is intentionally less expressive than Python `re`.
- Markdown markup can interrupt a literal phrase match.
- Rules may need multiple simple patterns instead of one complex regex.
- A physical line longer than 65,536 characters causes the affected matcher to
  fail rather than partially inspect it.
- A Python implementation and validator are not a formal regex complexity proof;
  future syntax additions require adversarial tests and review.
