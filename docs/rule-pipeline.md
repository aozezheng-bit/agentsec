# AgentSec Rule Execution and Finding Pipeline

- Task: `P1-19`
- Status: Complete
- Decision date: 2026-08-19
- Rule-pack version: `0.1.0`
- Decision record: `docs/decisions/0008-rule-isolation-finding-identity.md`

## 1. Purpose

P1-19 implements the deterministic host around the P1-17 Rule Protocol and the
P1-18 matcher adapters:

```text
validated Rule registry
→ stable rule and asset ordering
→ one isolated rule × asset evaluation
→ candidate contract validation
→ authoritative Evidence materialization
→ trusted metadata binding
→ unscored Finding identity
→ deterministic Finding deduplication
→ visible RULE_ERROR coverage
```

The public Python types are:

```text
DeterministicRuleRunner
RuleRunResult
RuleFailure
UnscoredFinding
RuleRegistryError
RulePipelineError
merge_rule_coverage
```

P1-19 deliberately stops before the final Domain `Finding`. That model already
requires likelihood, impact, severity, score, confidence, and hard-gate state.
Those values belong to P1-21 through P1-23 and must not be invented by the rule
runner.

## 2. Rule registry validation

`DeterministicRuleRunner` accepts an immutable tuple of built-in `Rule`
adapters. During construction it snapshots each rule's trusted `RuleMetadata`.

The registry requires:

- a tuple rather than a mutable list;
- valid `RuleMetadata` from every adapter;
- a callable `evaluate` method;
- one and only one adapter for each stable Rule ID;
- deterministic Rule ID sorting before evaluation.

A duplicate Rule ID is not treated as two findings and is not silently ignored.
It indicates an ambiguous or corrupted trusted rule pack and raises the fixed
safe `RuleRegistryError`:

```text
Rule registry validation failed safely.
```

Original exceptions and metadata values are not copied into the error.
Repository-local executable rule loading remains unsupported.

## 3. Context validation and ordering

`run()` accepts an immutable tuple of coherent `RuleContext` instances.
Contexts are sorted by project-relative asset path before evaluation.

Each path must occur once. Duplicate contexts for the same asset are rejected
because they would make coverage counts, rule failure attribution, and Finding
identity ambiguous.

The result records sorted `evaluated_asset_paths`. This lets coverage merging
verify that the Rule pipeline received every asset still counted as scanned by
the collector/parser stages.

## 4. Per-rule, per-asset isolation

The isolation unit is one applicable:

```text
Rule ID × Asset Path
```

For each pair, the runner performs the following inside one exception boundary:

1. call `rule.evaluate(context)`;
2. require an actual `RuleEvaluation`;
3. reconstruct the evaluation to re-check tuple, type, order, and uniqueness
   contracts;
4. materialize every candidate Evidence against the authoritative context;
5. bind trusted metadata and create local `UnscoredFinding` objects.

Only after all candidates from that pair succeed are its Findings added to the
result. Therefore evaluation is atomic per rule and asset:

```text
all candidates valid → retain all local Findings
any candidate invalid → retain none from that rule × asset
```

The runner catches ordinary Python `Exception` failures. It does not swallow
process-level control signals such as `KeyboardInterrupt` or `SystemExit`.
Built-in rule code remains trusted scanner code; the Python seam is not a
sandbox against arbitrary malicious package code.

A failure:

- does not stop later rules;
- does not disable the same rule on another asset;
- does not discard successful Findings from other rules on the same asset;
- does not expose the original exception or scanned source;
- creates one structured `RuleFailure`.

## 5. Structured Rule failures

`RuleFailure` contains only:

```text
trusted rule_id
validated project-relative asset_path
```

It converts to the existing Domain coverage model as:

```text
code: RULE_ERROR
message: Rule <RULE_ID> failed safely.
asset_path: <project-relative path>
```

The message contains a trusted stable Rule ID but no source excerpt, regex
subject, secret, stack trace, dependency message, or absolute path.

Failures are sorted and unique by Rule ID and asset path. Multiple failed rules
on one asset remain separate coverage issues so a reviewer can identify every
missing analysis, while coverage counts the affected asset only once.

## 6. Unscored Finding

`UnscoredFinding` is an internal immutable Python pipeline object with:

```text
finding_id
rule_id
category
title
description
evidence
recommendations
```

It binds:

```text
trusted RuleMetadata
+ validated Domain Evidence
```

It intentionally has no:

```text
likelihood
impact
severity
score
confidence
hard_gate
```

This preserves the separation:

```text
Rule match ≠ risk score
Evidence confidence ≠ severity
UnscoredFinding ≠ final Domain Finding
```

The Evidence field is excluded from generated object representations so an
accidental `repr()` of a Finding or `RuleRunResult` does not copy an unredacted
excerpt. Reporters still must apply secret redaction and output escaping before
any eventual display.

## 7. Finding ID

The deterministic ID format is:

```text
finding-sha256:<64 lowercase hexadecimal characters>
```

The SHA-256 input is canonical compact JSON containing:

```text
rule_id
ordered Evidence locators
```

Each Evidence locator includes:

```text
source_type
asset_path
start_line
end_line
field
content_sha256
```

The plaintext excerpt is excluded from the ID input. This provides:

- no secret or source text in the visible identifier;
- identical IDs when only the retained excerpt representation changes;
- different IDs for different Rule meanings;
- different IDs when authoritative content hash or evidence location changes;
- stable IDs for identical input, rule version, and evidence.

The ID is an occurrence fingerprint, not a cross-revision waiver key or proof of
approval. Because the content SHA-256 is included, a source-content change
creates a new Finding ID even when the same path and line remain. Long-term issue
tracking and waivers require a later explicitly designed identity.

## 8. Finding deduplication

Deduplication occurs by `finding_id`, which means:

```text
same Rule ID
+ same authoritative Evidence locators
= same unscored Finding
```

Different Rule IDs at the same source location remain separate Findings because
they represent different stable detection meanings.

Evidence excerpts are presentation/support data rather than identity. If
multiple candidates refer to the same locator with different excerpt
representations, the pipeline retains:

1. a present excerpt over an absent excerpt;
2. the shorter present excerpt to minimize retained source;
3. lexical order as a deterministic final tie-breaker.

Evidence locators inside a Finding are unique and source ordered. Findings are
ordered by Rule ID, first Evidence path, first start line, and Finding ID.

A cryptographic ID collision combined with incompatible trusted metadata is
reported as a safe pipeline error rather than silently merging findings.

## 9. Coverage merge semantics

`merge_rule_coverage(base_coverage, result)` applies rule failures to the
existing collector/parser coverage.

Before merging, it requires:

```text
len(result.evaluated_asset_paths) == base_coverage.scanned_assets
```

This prevents a caller from evaluating only a convenient subset and then
claiming complete Rule coverage.

For failed assets:

```text
scanned_assets -= number of unique failed asset paths
skipped_assets += number of unique failed asset paths
complete = false
issues += every unique RULE_ERROR issue
```

An asset with two failed rules moves from scanned to skipped once but retains two
`RULE_ERROR` issues. Existing collector and parser issues remain present.

Successful Findings from other rules on a failed asset are retained. They are
partial evidence, while the merged coverage clearly states that the asset did
not receive complete Rule analysis.

When there are no rule failures, the original `ScanCoverage` is returned
unchanged.

## 10. Determinism

Identical rules, contexts, versions, and configuration produce identical:

```text
evaluated_asset_paths
UnscoredFinding values
Finding IDs
Finding order
RuleFailure values
CoverageIssue values
merged coverage counts
```

The runner enforces deterministic behavior through:

- Rule ID ordering;
- asset-path ordering;
- immutable tuples;
- unique registry and context identity;
- revalidation of `RuleEvaluation` output;
- canonical JSON hashing;
- source-ordered Evidence;
- stable exact deduplication;
- stable issue ordering;
- no time, randomness, environment, network, shell, filesystem, Skill, MCP, or
  LLM dependency.

## 11. Version decision

P1-19 introduces internal Python execution and materialization objects, not a
new serialized Domain report model. Therefore:

```text
DOMAIN_SCHEMA_VERSION = 0.2.0  (unchanged)
RULE_PACK_VERSION = 0.1.0      (unchanged at the P1-19 boundary)
RISK_MODEL_VERSION = 0.1.0     (unchanged at the P1-19 boundary)
```

At the P1-19 task boundary the production pack was empty. P1-20 now publishes 15
Rule IDs as Rule Pack `0.2.0`. The `UnscoredFinding` type remains outside Domain
JSON Schema and cannot be mistaken for a fully scored report Finding.

ADR-0008 records the isolation, ID, deduplication, and coverage decisions.

## 12. Current integration boundary

P1-19 provides the Rule Runner but does not wire Findings into `agentsec scan`.
P1-21 through P1-23 provide every value required by the existing final Domain
`Finding`. P1-24 provides a safe direct Assessment Text delivery seam, and
P1-25 now provides the independently versioned Assessment JSON delivery seam.

The integration sequence is now:

```text
P1-20 concrete rule pack                       (complete)
→ P1-21 base risk scoring / ScoredFinding         (complete)
→ P1-22 Confidence / ConfidenceFinding            (complete)
→ P1-23 Hard Gate / final Domain Finding             (complete)
→ P1-24 safe Rich Assessment Text Reporter              (complete)
→ P1-25 versioned Assessment JSON Reporter             (complete)
→ P1-26 hardened shared SecretRedactor                 (complete)
→ P1-27 cross-format Coverage reporting                (complete)
```

P1-21 preserves the `UnscoredFinding` and pairs it with a versioned
`RiskAssessment`; it does not modify this runner's Evidence or Finding ID.
P1-22 preserves `ScoredFinding` and adds a separate versioned
`ConfidenceAssessment`; D Confidence never lowers Severity. P1-23 now adds
report-only Hard Gate metadata and can assemble the final Domain `Finding`.
P1-24 through P1-27 can safely render a supplied final Assessment as Rich Text
or strict JSON, including Evidence, report-only gate state, and explicit Coverage
Issue details/counts. `agentsec scan`
continues to report zero Findings until
later application orchestration connects collection, Rule, Risk, Confidence,
Hard Gate, and reporter stages.

## 13. Deferred behavior

P1-19 itself does not implement:

- P1-20 now provides the first 15 production rules;
- P1-21 now provides likelihood, high-water-mark impact, Severity, and numeric
  score in a separate Risk Engine;
- P1-22 now provides independent A/B/C/D Evidence Confidence in a separate
  Confidence Engine;
- P1-23 now provides report-only Hard Gate state and final Domain Finding
  assembly in a separate Hard Gate Engine;
- P1-24 through P1-27 now provide safe Text/JSON Assessment and Coverage
  reporting;
- CI risk threshold policy;
- cross-revision Finding tracking or waiver identity;
- process isolation for third-party executable rules.
