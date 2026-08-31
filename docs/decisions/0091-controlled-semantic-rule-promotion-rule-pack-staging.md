# ADR-0091: Controlled Semantic Rule Promotion and Rule Pack Staging

- Status: Accepted
- Date: 2026-08-31
- Task: P3-10
- Scope: deterministic promotion assessment and Owner-approved, report-only Rule Pack staging

## Context

P3-06 creates review-required semantic Rule Candidates. P3-07 adds human
calibration, Finding promotion review, and deterministic implementation replay.
Without a final contract, a downstream caller could mistakenly treat a passing
replay or an LLM proposal as an active Rule Pack change.

The security boundary must distinguish four facts:

1. a model candidate was observed;
2. a human accepted a candidate for engineering implementation;
3. a deterministic implementation passed replay; and
4. a release owner approved a staging artifact.

None of those facts alone proves runtime exploitability or authorizes CI.

## Decision

Add `SemanticRulePromotionController` and the strict
`SemanticRulePromotionReport` `0.1.0` contract.

`assess()` produces either `rejected` or `eligible_for_staging` after checking
proposal status, proposal/replay binding, replay quality, Evidence and Finding
bounds, proposal-family binding, implementation digest validity, and Rule ID
novelty. `stage()` can move only an eligible report to `staged` after explicit
Owner approval. `reject()` records an explicit Owner rejection.

The Rule Pack comparison is value-free: it contains sorted Rule IDs, an
interface version, and added/removed/changed ID sets. The controller never
writes the installed Rule Pack and never loads or executes target-project code.

## Authority boundary

Every report fixes these values to false:

```text
automatic_publication=false
rule_pack_mutated=false
finding_authority=false
policy_authority=false
ci_authority=false
hard_gate_authority=false
release_authority=false
```

`staged` means “ready for a separately governed release review”, not
“published”, “enabled”, “trusted at runtime”, or “blocking”.

## Consequences

### Positive

- A Rule Candidate cannot bypass human acceptance and deterministic replay.
- Replay quality gates are explicit and machine-verifiable.
- Rule Pack impact is visible without disclosing implementation content.
- Owner approval is bound to an identifier and rationale.
- Rejected and duplicate Rule IDs remain representable as evidence.
- Future CLI/Homi callers receive a narrow, typed integration seam.

### Trade-offs

- P3-10 does not implement a Rule Pack publisher or release workflow.
- A passing fixture replay is not evidence of runtime reachability or exploitability.
- Rule ID naming and proposal-family mappings remain a reviewed finite policy.
- The report requires a separate trust plane for the eventual release process.

## Rejected alternatives

- Automatically publish a Rule after replay passes: rejected because model-derived
  candidates and fixture replay do not establish release authority.
- Mutate the installed Rule Pack during `stage()`: rejected because staging must
  be reviewable, reproducible, and reversible before release.
- Let the semantic model choose Rule IDs, families, severity, or CI behavior:
  rejected because those are trusted deterministic or governance decisions.
- Treat `staged` as a Hard Gate or CI decision: rejected; enforcement remains
  owned by deterministic Rules and reviewed Policy.
