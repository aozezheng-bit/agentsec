# P3-10: Controlled Semantic Rule Promotion / Rule Pack Staging

- Status: Complete
- Date: 2026-08-31
- ADR: `docs/decisions/0091-controlled-semantic-rule-promotion-rule-pack-staging.md`

## Objective

Provide a deterministic, reviewable boundary between an accepted semantic Rule
Candidate and a possible future Rule Pack release. The task must prevent
automatic publication and preserve the distinction between staging evidence and
production authority.

## Deliverables

- [x] Add `SemanticRulePromotionController.assess()`.
- [x] Add strict `RulePromotionStatus`, `RulePromotionCheck`, `RulePackDiff`, and `SemanticRulePromotionReport` models.
- [x] Require accepted Rule Candidates and exact replay proposal binding.
- [x] Require zero replay failures, FP, FN, and perfect replay quality metrics.
- [x] Require Evidence/ Finding bound accuracy of `1`.
- [x] Require trusted proposal-family binding and a new deterministic Rule ID.
- [x] Add explicit Owner-approved `stage()` transition.
- [x] Add explicit Owner `reject()` transition.
- [x] Add content-addressed replay report and implementation SHA-256 fields.
- [x] Add generated JSON Schema, encoder, public API exports, and provenance ownership.
- [x] Add regression tests for success, replay failure, rejection, mismatch, duplicate Rule IDs, and missing approval rationale.
- [x] Add ADR, architecture, threat-model, Schema README, release status, and changelog updates.

## Non-goals

- No automatic Rule publication.
- No mutation of the installed or built-in Rule Pack.
- No semantic Finding creation or mutation.
- No Severity, Evidence Confidence, Policy, CI, Hard Gate, or release authority.
- No runtime verification, exploitability proof, target-project execution, or
  source-content retention in reports.
- No P3-10-specific publish CLI; a later release task must define that trust
  plane and approval workflow.

## Acceptance criteria

1. A non-accepted proposal cannot enter assessment.
2. A replay bound to another proposal cannot be accepted.
3. Any replay quality failure produces `rejected` evidence and cannot be staged.
4. A passing assessment produces `eligible_for_staging` with a value-free Rule ID diff.
5. Only an eligible report with explicit Owner ID, approval ID, and rationale can become `staged`.
6. Duplicate Rule IDs remain a rejected report rather than causing an incoherent diff.
7. Every authority boolean remains false in every state.
8. Staging and rejection revalidate the returned report.
9. The generated Schema is byte-stable and centrally owned.
10. Targeted tests, full checks, package hardening, and reproducible build checks pass.

## Verification commands

```bash
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
.venv/bin/python -m pytest tests/test_semantic_p3_10.py -q
./scripts/check.sh
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
PYTHONPATH=src .venv/bin/python scripts/verify-reproducible-build.py
```
