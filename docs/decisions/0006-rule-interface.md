# ADR-0006: Data-Only Deterministic Rule Interface

- Status: Accepted
- Date: 2026-08-18
- Task: P1-17

## Context

Phase 1 needs 10–15 deterministic Markdown rules, but a rule that receives the
project root, open filesystem access, environment data, tool clients, or report
objects can accidentally cross scanner trust boundaries. A rule that directly
constructs a complete `Finding` must also invent score, confidence, path, hash,
and identity before the corresponding risk and deduplication tasks exist.

Rule failures and malicious source text are additional risks. One crafted asset
must not crash all analysis, leak its contents through an exception, or cause a
scan to be represented as complete. Evidence must be bound to the exact asset
that was collected and parsed rather than to a path/hash selected by rule code.

The interface must remain small enough that P1-18 can implement keyword, regex,
and bounded context matchers without coupling matching logic to CLI, scoring,
reporting, or policy.

## Decision

Create a public `agentsec.rules` Python seam with one structural `Rule` Protocol:

```python
class Rule(Protocol):
    @property
    def metadata(self) -> RuleMetadata: ...

    def evaluate(self, context: RuleContext) -> RuleEvaluation: ...
```

Adopt these contracts:

1. Rule IDs use stable uppercase `FAMILY-TOPIC-NNN` identity.
2. `RuleMetadata` owns trusted title, description, category, recommendations,
   applicability, and the mandatory deterministic flag.
3. `RuleScope` declares non-empty Markdown asset types and parsed target kinds.
4. `RuleContext` contains only `AgentAsset`, exact decoded content, and
   `ParsedMarkdown`; it contains no project root, I/O, environment, command,
   network, Skill, MCP, or model dependency.
5. Context construction verifies UTF-8 byte size, SHA-256, source line count,
   and parser line count against authoritative asset metadata.
6. Rules return an immutable `RuleEvaluation` of source-ordered, unique,
   unscored Finding candidates.
7. Candidate evidence contains only local line coordinates, optional exact
   excerpt, and optional field. It cannot select asset path, hash, or evidence
   source type.
8. Materialization verifies the excerpt against the exact source range and
   binds project-relative path, SHA-256, and `EvidenceSource.FILE` from context.
9. Severity, score, likelihood, impact, confidence, hard gate, Finding ID, and
   deduplication remain outside the Rule interface.
10. `RuleEvaluationError` has a fixed safe message. `RuleContractError` uses
    fixed messages that do not copy untrusted input.
11. P1-19 will invoke every rule behind an independent exception-isolation
    boundary and convert failures into visible `RULE_ERROR` coverage.
12. Concrete Phase 1 rule adapters are trusted scanner code and must be pure,
    bounded computations over the context. They may not use shell, filesystem,
    environment, network, scanned imports, Skills, MCP, sub-Agents, or LLMs.
13. Repository-local executable rule plugins remain unsupported in Phase 1.
14. Candidate/evaluation containers use immutable tuples with source ordering
    and uniqueness as part of deterministic output.

The Rule Protocol is a Python execution seam, not a new serialized Domain Schema.
`DOMAIN_SCHEMA_VERSION` therefore remains `0.2.0`, and the still-empty production
rule pack remains `0.1.0` until matching adapters are added.

## Consequences

### Positive

- Matching logic remains independent from collection, scoring, reporting, and
  policy.
- Rules cannot spoof path or content-hash evidence through their output model.
- P1-19 has an explicit per-rule failure seam without P1-17 implementing the
  future runner.
- P1-21 can assign risk without trusting a rule-supplied score.
- Tests can use small adapters against the same structural interface as
  production rules.
- The absence of I/O dependencies makes prohibited side effects visible in code
  review and easier to test.

### Negative

- A Python Protocol is not a security sandbox; a malicious built-in rule could
  still import standard-library I/O directly. Packaging trust and code review
  remain required.
- Rules must return exact source-backed excerpts rather than normalized text that
  cannot be located in the declared source range.
- Multi-asset and semantic rules need a later, separately reviewed context
  instead of expanding the Phase 1 Markdown seam implicitly.
- Source-order and uniqueness validation adds authoring constraints to concrete
  rules.
