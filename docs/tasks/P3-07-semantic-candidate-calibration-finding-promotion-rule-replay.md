# P3-07: Semantic Candidate Calibration、Finding Promotion Review、Rule Implementation Replay

- Status: Complete
- Date: 2026-08-31
- ADR: `docs/decisions/0088-semantic-candidate-calibration-finding-promotion-rule-replay.md`

## Deliverables

- [x] Add human-labeled Semantic Candidate Calibration Case and Report.
- [x] Compute TP/FP/FN/TN, Precision, Recall, F1, field agreement, and Evidence agreement.
- [x] Require labels for every observed candidate and expose missing-candidate FN.
- [x] Add Finding Promotion Review for P3-06 links.
- [x] Allow acceptance only for deterministic `supports`/`duplicates` links.
- [x] Keep accepted promotion review report-only; never create or mutate Findings.
- [x] Require explicit review before Rule implementation replay.
- [x] Replay trusted deterministic Rules through `DeterministicRuleRunner`.
- [x] Verify Rule family binding, outcome, Finding count, Evidence binding, and failures.
- [x] Export P3-07 JSON Schemas and register provenance/ownership.
- [x] Add public API exports, tests, ADR, threat-model controls, and status updates.

## Acceptance criteria

1. Calibration exposes detection and field-agreement metrics without granting
   Provider, Finding, Rule, Policy, or CI authority.
2. A missing observed semantic candidate is counted as FN when human labels expect
   it; an unlabeled observed candidate is rejected.
3. Only positive deterministic Evidence links can be accepted for Finding review.
4. Finding promotion review never creates, modifies, scores, or gates a Finding.
5. Rule replay requires `accepted_for_implementation` and a Rule ID bound to the
   trusted proposal family.
6. Replay failures and Evidence/count defects remain visible.
7. Raw fixture text is not serialized in calibration, promotion, or replay reports.
8. All P3-07 Schemas are strict and provenance-owned.

## Verification commands

```bash
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
./scripts/check.sh
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
PYTHONPATH=src .venv/bin/python scripts/verify-reproducible-build.py
```
