# AgentSec Deterministic Rule Interface

- Task: `P1-17`
- Status: Complete
- Decision date: 2026-08-18
- Rule-pack version: `0.1.0`
- Decision record: `docs/decisions/0006-rule-interface.md`

## 1. Purpose

P1-17 defines the seam between safely parsed Phase 1 Markdown and future
deterministic security rules. It fixes the vocabulary, invariants, inputs,
outputs, applicability, and failure expectations that P1-18 through P1-20 use.

It does **not** implement keyword or regular-expression matching, a rule runner,
Finding deduplication, scoring, confidence, reporting, or CI policy.

The interface is intentionally small:

```python
class Rule(Protocol):
    @property
    def metadata(self) -> RuleMetadata: ...

    def evaluate(self, context: RuleContext) -> RuleEvaluation: ...
```

Each adapter has one data-only evaluation method. The future host owns
collection, parsing, applicability checks, exception isolation, candidate
validation, scoring, Finding identity, deduplication, reporting, and policy.

## 2. Module and seam

The public module is:

```text
agentsec.rules
```

It exports:

```text
Rule
RuleMetadata
RuleScope
RuleTarget
RuleContext
RuleEvaluation
RuleFindingCandidate
RuleEvidenceCandidate
RuleContractError
RuleEvaluationError
```

Concrete Phase 1 rules will be adapters satisfying `Rule`. They do not inherit
scanner implementation and cannot replace collector, parser, scoring, or report
behavior.

## 3. Stable Rule identity

Every rule has a stable identifier using:

```text
FAMILY-TOPIC-NNN
```

Examples:

```text
MD-INSTR-001
MD-EXEC-001
MD-SECRET-001
```

The runtime validation pattern is:

```text
^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$
```

The fields mean:

- `FAMILY`: the input/rule family, such as `MD`;
- `TOPIC`: the stable detection topic, such as `EXEC`;
- `NNN`: a zero-padded identity within the family and topic.

A Rule ID is not a display name. It must not be reused for a materially different
risk. Editorial title, description, or remediation changes do not create a new
identity when trigger meaning is unchanged. Material trigger changes follow the
rule identity and version policy in `docs/versioning.md`.

## 4. Rule metadata

`RuleMetadata` contains trusted, immutable rule-author information:

```text
rule_id
stable title
description
FindingCategory
one or more recommendations
RuleScope
deterministic = true
```

It deliberately excludes:

```text
likelihood
impact
severity
numeric score
confidence
hard gate
```

These values remain outside the Rule interface. P1-21 now assigns likelihood,
impact, Severity, and numeric score in the downstream Risk Engine. P1-22 now
assigns Confidence in a separate downstream Confidence Engine. P1-23 now adds
report-only Hard Gate metadata downstream. A matching rule reports evidence and
cannot assign or silently lower risk, self-upgrade Confidence, or self-trigger a
Hard Gate.

Recommendations are non-empty and unique. Rule metadata must be independent of
the scanned project and cannot be populated from untrusted Markdown.

## 5. Applicability and analysis targets

`RuleScope` requires a non-empty immutable set of `AssetType` values and a
non-empty immutable set of analysis targets.

Phase 1 targets are:

| Target | Meaning |
|---|---|
| `document` | complete bounded document or cross-block context |
| `markdown_block` | heading, paragraph, list item, or code block |
| `frontmatter` | safely decoded or malformed frontmatter metadata |
| `reference` | static link, image, definition, or URI declaration |
| `obfuscation_indicator` | deterministic parser anomaly metadata |

The future rule runner must call `scope.applies_to(asset_type)` before invoking a
rule. `targets` documents which parsed structures the adapter examines and lets
rule listings, review, and later execution planning remain explicit.

A scope is not permission to dereference a reference, execute a code block, or
interpret frontmatter as executable configuration.

## 6. Rule input context

A rule receives one `RuleContext`:

```text
AgentAsset asset
str content
ParsedMarkdown document
```

The constructor verifies:

- `content` is UTF-8 encodable;
- encoded byte length equals `AgentAsset.size_bytes`;
- SHA-256 equals `AgentAsset.sha256`;
- logical line count equals `AgentAsset.line_count`;
- parsed-document line count equals the same source line count.

This prevents a rule from evaluating one document while evidence is attributed
to stale or different asset provenance.

`source_text(start_line, end_line)` returns an exact 1-based inclusive source
slice with original line endings. It rejects invalid and out-of-range locations
using fixed messages that do not copy source content.

`RuleContext` deliberately contains no:

```text
absolute project root
filesystem handle
write capability
environment mapping
secret provider
command or subprocess runner
Python import hook
HTTP/network client
Skill executor
MCP client
LLM client
```

`content` and `document` remain untrusted data. Their generated representations
omit raw text to reduce accidental logging.

## 7. Candidate Finding and Evidence

A rule returns `RuleEvaluation`, containing zero or more
`RuleFindingCandidate` objects. An empty tuple means no match.

Each Finding candidate contains one or more `RuleEvidenceCandidate` objects.
Candidate evidence may declare only:

```text
start_line
end_line
optional exact excerpt
optional field name
```

Rules cannot choose:

```text
asset path
content hash
evidence source type
Finding ID
Rule ID
category
severity
score
confidence
hard gate
```

This split prevents evidence spoofing. During candidate validation,
`RuleEvidenceCandidate.materialize(context)`:

1. verifies that the line range exists in the current source;
2. verifies that an optional excerpt is contained in the exact declared source
   range;
3. binds `EvidenceSource.FILE`;
4. binds the authoritative project-relative asset path;
5. binds the authoritative content SHA-256;
6. creates the existing Domain `Evidence` object.

The Finding pipeline combines:

```text
trusted RuleMetadata
+ validated candidate Evidence
+ deterministic Finding identity
+ downstream risk/confidence output
```

P1-17 did not perform that combination. P1-19 binds trusted metadata and
materializes and deduplicates `UnscoredFinding` values. P1-21 now adds a separate
versioned `RiskAssessment` without changing Rule output or Evidence.

## 8. Deterministic output contract

All Phase 1 rules are deterministic. `RuleMetadata.deterministic` is fixed to
`true`; adapters cannot opt out.

For identical:

```text
Rule implementation and Rule ID
rule-pack version
RuleContext asset/content/document
scanner configuration
```

an adapter must return identical candidates and evidence.

The interface requires immutable tuples. Evidence inside one candidate and
candidates inside one evaluation must be source-ordered and unique. Filesystem
order, set order, locale, clock time, randomness, environment values, network
responses, and process state must not affect results.

## 9. Exception-isolation seam

P1-17 defines two safe exception types:

| Type | Purpose |
|---|---|
| `RuleEvaluationError` | expected rule failure with one fixed safe message |
| `RuleContractError` | incoherent context, range, or candidate evidence |

The fixed `RuleEvaluationError` message is:

```text
Rule evaluation failed safely.
```

A concrete rule must not copy source content, secrets, paths, regex input, or
dependency exception text into an exception.

The P1-19 runner now implements the isolation behavior:

```text
for each applicable Rule:
    try:
        evaluate and validate candidate output
    except Exception:
        record RULE_ERROR coverage
        continue with other rules
```

P1-17 intentionally did not implement that runner. P1-19 now executes each
applicable rule×asset pair atomically, materializes unscored Findings, and converts
failures to visible `RULE_ERROR` coverage as documented in
`docs/rule-pipeline.md`.

## 10. Prohibited Rule behavior

A Phase 1 Rule adapter must be a pure, bounded computation over `RuleContext`.
It must never:

- read additional files or follow references;
- write to the project, cache, baseline, or report directories;
- inspect environment variables or credential stores;
- execute shell commands, code blocks, `exec`, `eval`, hooks, or scripts;
- import modules from the scanned project;
- install or load dependencies declared by scanned content;
- access external or loopback network services;
- execute a Skill or delegate to a sub-Agent;
- connect to an MCP server;
- invoke an LLM;
- mutate input models or global scanner state;
- use unbounded regular expressions or unbounded output.

The Python Protocol cannot sandbox arbitrary malicious Python by itself.
Therefore built-in rule code is trusted scanner code subject to review, tests,
packaging integrity, and rule-pack versioning. Repository-local executable rule
plugins remain out of Phase 1 scope.

## 11. Version decision

P1-17 does not change the public Domain JSON Schema because its dataclasses and
Protocol are an internal Python execution seam, not a serialized report format.
`DOMAIN_SCHEMA_VERSION` remains `0.2.0`.

At P1-17 through P1-19, `RULE_PACK_VERSION` remained `0.1.0` while the pack had
no production Rule IDs. P1-20 now publishes 15 concrete rules and increments the
pack to `0.2.0`; see `docs/rule-pack.md` and ADR-0009. Changes to match meaning
follow the Rule ID and rule-pack policy. Breaking Python interface changes before
a public plugin model require release notes and an ADR.

## 12. Deferred work

P1-17 explicitly defers:

- P1-18 matcher semantics are now implemented and documented in
  `docs/rule-matching.md`;
- P1-19 isolation and Finding deduplication are now implemented in
  `docs/rule-pipeline.md`;
- P1-20 now provides the first 15 rules in `docs/rule-pack.md`;
- P1-21 likelihood, high-water-mark impact, Severity, and score are now
  implemented in `docs/risk-model.md`;
- P1-22 Evidence Confidence is now implemented in
  `docs/confidence-model.md`;
- P1-23 report-only Hard Gate metadata is now implemented in
  `docs/hard-gate.md`;
- scan Text/JSON rendering to P1-24 and P1-25;
- repository-local or third-party executable rule plugins;
- semantic/LLM rules to Phase 3.
