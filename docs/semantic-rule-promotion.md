# P3-10: Controlled Semantic Rule Promotion / Rule Pack Staging

- Status: Complete
- Date: 2026-08-31
- ADR: `docs/decisions/0091-controlled-semantic-rule-promotion-rule-pack-staging.md`
- Schema: `schemas/semantic-analysis/semantic-rule-promotion-report.schema.json`

## Purpose

P3-10 closes the engineering loop from a reviewed semantic Rule Candidate to a
reviewable Rule Pack staging artifact. It deliberately does **not** turn an LLM
candidate into an active Rule automatically. The flow is:

```text
accepted_for_implementation Rule Candidate
  → deterministic Rule implementation
  → Rule Implementation Replay
  → Promotion Assessment
  → Owner-approved staging artifact
  → separate explicit Rule Pack release process
```

The implementation is an API/report contract (`SemanticRulePromotionController`
and `SemanticRulePromotionReport`), not an automatic publisher. It can be used
by a future release CLI or Homi integration after those callers define their own
trusted artifact and release controls.

## Promotion states

| State | Meaning | Rule Pack / enforcement effect |
|---|---|---|
| `rejected` | One or more deterministic checks failed, or an Owner rejected the candidate | No mutation; no Finding, Policy, CI, Hard Gate, or release authority |
| `eligible_for_staging` | The accepted proposal, replay, implementation identity, and Rule ID checks passed | Still no mutation; waiting for explicit Owner approval |
| `staged` | An Owner approved the eligible report with an approval ID and rationale | Immutable staging evidence only; still not published or active |

`staged` is intentionally weaker than `published`: it does not modify the
installed Rule Pack, create or change Findings, enter Organization Policy,
activate a Hard Gate, block CI, or authorize a release.

## Deterministic promotion checks

`SemanticRulePromotionController.assess()` requires:

1. the proposal status is `accepted_for_implementation`;
2. the replay report is bound to the exact proposal ID;
3. replay has no failures, false positives, or false negatives;
4. Evidence Binding Accuracy and Finding Count Bound Accuracy are exactly `1`;
5. replay Precision, Recall, and F1 are all exactly `1`;
6. the implementation SHA-256 is a valid lowercase digest;
7. the implemented Rule ID matches the trusted proposal family prefix; and
8. the implemented Rule ID is not already present in the supplied base Rule Pack.

The output includes a value-free, sorted `RulePackDiff` containing only Rule IDs
and the base Rule Pack interface version. It never copies implementation source,
source excerpts, credentials, or target-project content.

## Owner approval

`stage()` requires all of:

- a previously `eligible_for_staging` report;
- a non-empty Owner identifier;
- a non-empty approval identifier; and
- a non-empty approval rationale.

`reject()` records the explicit review disposition while retaining the original
checks and adding the deterministic `owner_rejected` check. Both transitions
revalidate the complete report before returning it.

## Authority boundary

The following fields are fixed to false in every report:

```text
automatic_publication=false
rule_pack_mutated=false
finding_authority=false
policy_authority=false
ci_authority=false
hard_gate_authority=false
release_authority=false
```

The semantic model remains evidence only. Only a separately reviewed,
deterministic Rule implementation can be considered for staging, and a separate
explicit release process is required before any Rule Pack change can affect
production analysis.

## API example

```python
from agentsec.semantic import SemanticRulePromotionController

controller = SemanticRulePromotionController()
assessment = controller.assess(
    accepted_candidate,
    replay_report,
    implemented_rule_id="SEMANTICEXECUTION-SHELL-001",
    implementation_sha256=implementation_sha256,
    base_rule_pack_version="0.3.1",
    base_rule_ids=existing_rule_ids,
)
if assessment.status.value == "eligible_for_staging":
    staged = controller.stage(
        assessment,
        owner_id="release-owner",
        approval_id="approval-2026-08-31-001",
        approval_reason="Replay and independent review passed.",
    )
```

The report can be serialized with
`encode_semantic_rule_promotion_json()` and validated against the frozen Schema.
No CLI command in P3-10 publishes or activates the staged artifact.

## Verification

```bash
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
.venv/bin/python -m pytest tests/test_semantic_p3_10.py -q
./scripts/check.sh
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
PYTHONPATH=src .venv/bin/python scripts/verify-reproducible-build.py
```
