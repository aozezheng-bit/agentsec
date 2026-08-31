# P3-07 Semantic Candidate Calibration / Finding Promotion / Rule Replay

- Status: Complete
- Date: 2026-08-31
- Interfaces: Semantic Candidate Calibration `0.1.0`; Finding Promotion Review `0.1.0`; Rule Implementation Replay `0.1.0`
- Implementation: `src/agentsec/semantic/p3_07.py`
- Tests: `tests/test_semantic_p3_07.py`

## 1. Purpose

P3-07 turns the P3-06 triage outputs into a controlled engineering loop:

```text
Semantic Candidate
  → human-labeled calibration
  → deterministic Finding promotion review
  → explicitly accepted Rule Candidate
  → trusted deterministic Rule implementation
  → inert fixture replay
  → Precision/Recall/Evidence/Failure report
```

The loop is still Shadow-only. It does not create production Findings, publish a
Rule, alter a Rule Pack, activate a Hard Gate, or block CI.

## 2. Semantic Candidate Calibration

`SemanticCandidateCalibrationCase` stores a human label for a candidate key:

- expected presence;
- expected kind/category/disposition when present;
- expected opaque Evidence IDs;
- reviewer ID and bounded rationale code.

`SemanticCandidateCalibrationRunner` compares a complete observed candidate set
with the labels and reports:

- TP/FP/FN/TN presence metrics;
- Precision, Recall, and F1;
- kind/category/disposition agreement;
- Evidence binding agreement;
- reviewer count.

A candidate key with an expected label but no emitted candidate is a False
Negative. An emitted candidate labeled absent is a False Positive. An absent
candidate labeled absent is a True Negative. Calibration cases must cover every
observed candidate; unlabeled observations are rejected.

Calibration is measurement evidence only. It does not promote a Provider or a
Rule and does not change deterministic severity or Confidence.

## 3. Finding Promotion Review

`SemanticFindingPromotionReviewer` reviews a P3-06 link. Only a deterministic
`supports` or `duplicates` link can be accepted. `unmatched` and `contradicts`
links can only be rejected or left for later review.

An accepted review means:

```text
accepted_for_finding_review
```

It does **not** mean that a new `Finding` is created. The review report records
the candidate ID, existing Finding ID, relationship, reviewer, decision, and
rationale while keeping `creates_finding=false` and `modifies_finding=false`.

## 4. Rule Implementation Replay

`RuleImplementationReplayRunner` accepts only a P3-06 Rule Candidate that has
been explicitly marked `accepted_for_implementation`. It then runs a trusted
AgentSec `Rule` over bounded in-memory `RuleContext` fixtures through the normal
`DeterministicRuleRunner`.

Replay verifies:

- the Rule ID is bound to the proposal's trusted semantic family;
- expected match/no-match outcome;
- expected Finding count bounds;
- deterministic Evidence path/hash binding;
- Rule failures;
- TP/FP/FN/TN, Precision, Recall, F1, Evidence binding accuracy, and bound
  accuracy.

Replay cases carry source contexts only in memory. Reports never serialize raw
fixture content or excerpts. A failed replay remains visible and cannot be
silently interpreted as a clean result.

The semantic family `SEMANTIC_EXECUTION` is bound to a valid deterministic Rule
ID such as `SEMANTICEXECUTION-SHELL-001`; the underscore is normalized only for
Rule-ID binding and does not grant the semantic candidate Rule authority.

## 5. Authority boundary

```text
calibration_report_only=true
promotion_creates_finding=false
replay_rule_pack_mutated=false
finding_authority=false
policy_authority=false
ci_authority=false
```

The only path to a production Rule remains:

```text
human review
→ deterministic implementation
→ positive/negative fixtures
→ replay pass
→ Rule Pack review
→ provenance/version update
→ explicit release
```

## 6. Example API flow

```python
calibration = SemanticCandidateCalibrationRunner().run(
    semantic_result,
    human_labels,
)

promotion = SemanticFindingPromotionReviewer().review_report(
    integration_report,
    decisions,
    reviewer_id="reviewer-a",
)

proposal = SemanticRuleCandidateWorkflow().accept_for_implementation(
    candidate_proposal,
    reviewer_id="reviewer-a",
)

replay = RuleImplementationReplayRunner().run(
    proposal,
    trusted_rule,
    replay_cases,
)
```

No method in this flow writes to the target project or mutates the installed
Rule Pack.
