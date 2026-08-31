# P3-06: Semantic Finding Integration / Rule Candidate Workflow

- Status: Complete
- Date: 2026-08-31
- ADR: `docs/decisions/0087-semantic-finding-integration-rule-candidate-workflow.md`

## Deliverables

- [x] Add `SemanticFindingIntegrator` and strict integration report.
- [x] Associate only through trusted path/hash/line/category Evidence overlap.
- [x] Emit `supports`, `duplicates`, `contradicts`, or fail-closed `unmatched`.
- [x] Keep integration read-only; never create or mutate Findings.
- [x] Add `SemanticRuleCandidateWorkflow` and content-addressed proposals.
- [x] Use a finite trusted category-to-Rule-family mapping.
- [x] Require an explicit reviewer for accept/reject transitions.
- [x] Keep proposals report-only and prohibit automatic Rule publication.
- [x] Export both JSON Schemas and register provenance/ownership.
- [x] Export stable public API types.
- [x] Add security regression tests and update threat documentation.

## Acceptance criteria

1. A matching semantic candidate never changes an existing Finding's Severity,
   Evidence Confidence, score, ID, or Evidence.
2. Model output cannot provide a Finding ID, source path, line range, asset hash,
   Rule family, Severity, Confidence, Allow/Block, Waiver, or runtime proof.
3. Missing, mismatched, or non-static Evidence yields `unmatched`.
4. Exact trusted locator equality yields `duplicates`; partial overlap yields
   `supports`; `not_supported` yields a report-only `contradicts` signal.
5. All Rule proposals begin as `review_required` and cannot be published by the
   workflow.
6. Proposals are deterministic for identical validated semantic input.
7. Schema, provenance, lint, type, targeted tests, full tests, package hardening,
   and reproducible build checks pass.

## Verification commands

```bash
./scripts/check.sh
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
PYTHONPATH=src .venv/bin/python scripts/verify-reproducible-build.py
```
