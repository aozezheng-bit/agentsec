# ADR-0088: Semantic Candidate Calibration, Finding Promotion Review, and Rule Replay

- Status: Accepted
- Date: 2026-08-31
- Task: P3-07
- Scope: Shadow-only candidate calibration and deterministic engineering feedback

## Context

P3-06 provides semantic-to-Finding links and review-required Rule Candidates.
Without a calibration contract, a single model response could be mistaken for a
validated semantic capability. Without a promotion review, a model link could
become a new Finding. Without deterministic Rule replay, an accepted proposal
could bypass the normal Rule pipeline and fixture regression process.

## Decision

Implement three bounded, immutable report contracts:

- `SemanticCandidateCalibrationReport` `0.1.0`;
- `SemanticFindingPromotionReport` `0.1.0`;
- `RuleImplementationReplayReport` `0.1.0`.

### Calibration

Human labels identify expected candidate presence, kind, category, disposition,
and opaque Evidence IDs. The runner computes binary detection metrics and field
agreement. Every observed candidate must be labeled; missing expected candidates
are represented as False Negatives.

### Finding promotion

Only `supports` and `duplicates` links can receive an accept decision. An
accepted review is `accepted_for_finding_review`, not a `Finding`. The reviewer
and rationale are retained for auditability. `unmatched` and `contradicts` do
not qualify for acceptance.

### Rule implementation replay

A Rule Candidate must first be explicitly accepted for implementation. A trusted
AgentSec deterministic Rule is replayed using the existing `DeterministicRuleRunner`
over bounded in-memory `RuleContext` fixtures. The report includes outcome,
Finding count, Evidence binding, Rule failures, and binary metrics. Raw fixture
content is excluded from the report.

## Authority boundary

```text
finding_authority=false
rule_pack_mutated=false
policy_authority=false
ci_authority=false
creates_finding=false
```

Calibration, promotion review, and replay are evidence and engineering controls;
they cannot alter severity, confidence, policy, Hard Gates, or release state.

## Consequences

Positive:

- semantic quality is measured against explicit human labels;
- Finding review cannot silently suppress or replace deterministic Findings;
- accepted Rule Candidates must pass the same deterministic Rule pipeline and
  replay discipline as other Rules;
- failures, Evidence binding defects, and count-bound defects remain visible.

Trade-offs:

- calibration cannot estimate production quality without a representative,
  independently reviewed corpus;
- a replay pass proves the implementation against supplied fixtures, not runtime
  reachability or exploitability;
- Rule-family mapping and replay binding remain trusted code and require review
  when changed.

## Rejected alternatives

- Treat a semantic candidate as a Finding after one model response: rejected.
- Accept a Rule Candidate without human review: rejected.
- Replay by importing or executing target-project code: rejected; only trusted
  AgentSec Rule implementations and data-only contexts are allowed.
- Use replay metrics as automatic CI authorization: rejected.
