# ADR-0008: Atomic Rule Isolation and Unscored Finding Identity

- Status: Accepted
- Date: 2026-08-19
- Task: P1-19

## Context

Phase 1 requires one failed rule to remain visible without stopping other rule
analysis or producing a false clean result. Candidate Evidence may also be
invalid, spoofed, duplicated, or represented with different excerpts. The host
must bind trusted Rule metadata and authoritative source provenance rather than
accepting identity or risk values from adapters.

The existing Domain `Finding` requires likelihood, impact, severity, score,
confidence, and hard-gate fields. P1-19 precedes all of those tasks. Filling them
with placeholder values would create misleading reports and couple the Rule
runner to a risk model that has not been implemented.

Coverage counts are asset based, while failure attribution is rule-and-asset
based. Two failed rules on one asset must produce two visible issues but must not
count the asset as skipped twice.

Finding IDs must be deterministic, must not expose source excerpts, and must not
collapse different Rule IDs at the same location.

## Decision

Create `DeterministicRuleRunner` and an internal immutable `UnscoredFinding`
pipeline with these rules:

1. Registry construction snapshots trusted `RuleMetadata`, sorts by Rule ID, and
   rejects duplicate IDs with a fixed safe `RuleRegistryError`.
2. Contexts are immutable, sorted by project-relative asset path, and unique by
   path.
3. The isolation unit is one applicable Rule ID × asset path.
4. Evaluation, output revalidation, Evidence materialization, and local Finding
   construction occur inside one atomic `Exception` boundary.
5. If any candidate from a pair fails, retain no Findings from that pair, record
   one `RuleFailure`, and continue with other pairs.
6. Keep successful Findings from other rules on the same asset and from the same
   rule on other assets.
7. A Rule failure exposes only trusted Rule ID, project-relative asset path, and
   the fixed message `Rule <ID> failed safely.`
8. Convert each failure to `CoverageIssueCode.RULE_ERROR`.
9. `UnscoredFinding` contains trusted descriptive metadata and validated Domain
   Evidence, but no risk, confidence, or hard-gate fields.
10. Generate `finding-sha256:<digest>` from canonical JSON of Rule ID and ordered
    authoritative Evidence locators.
11. Include source type, path, line range, field, and content SHA-256 in the
    locator; exclude plaintext excerpt.
12. Deduplicate only identical Rule ID plus locator identities. Different Rule
    IDs remain separate.
13. For duplicate locator representations, prefer a present, shorter exact
    excerpt, with lexical tie-breaking.
14. Exclude Evidence and Findings from generated `repr()` output paths that
    could accidentally log unredacted excerpts.
15. Merge rule coverage only when the number of evaluated context paths equals
    the existing scanned asset count.
16. Move every unique failed asset from scanned to skipped once, retain every
    distinct rule failure issue, and preserve existing coverage issues.
17. Keep P1-19 independent from `agentsec scan` until final Domain Findings can
    receive real scoring and confidence.
18. Catch ordinary `Exception` values at the rule boundary, but do not swallow
    `KeyboardInterrupt`, `SystemExit`, or other process-level control signals.

P1-19 changes no serialized Domain Schema, Rule Pack content, or Risk Model
meaning. Their versions remain unchanged.

## Consequences

### Positive

- One broken rule cannot hide results from other rules.
- Partial rule analysis cannot be represented as complete coverage.
- Candidate spoofing and malformed outputs fail closed at the exact rule/asset
  pair.
- Finding identity contains no plaintext source or secret value.
- Duplicate excerpt representations do not create duplicate Findings.
- Risk scoring remains a separate reviewed module rather than a rule-supplied
  value.
- Existing collector and parser coverage composes deterministically with rule
  failures.

### Negative

- `agentsec scan` still cannot emit final Findings before scoring and confidence
  are implemented.
- A rule failure marks the whole asset incomplete even when other rules succeed;
  this is conservative but may reduce the scanned count substantially.
- Including content SHA-256 means Finding IDs change after any asset-content
  change and are not suitable as long-term waiver keys.
- In-process Python exception isolation is not a sandbox against malicious or
  non-terminating third-party code.
- Successful partial Findings from an asset may coexist with skipped coverage,
  so reporters must communicate both facts clearly.
