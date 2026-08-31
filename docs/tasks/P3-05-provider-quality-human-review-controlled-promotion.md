# P3-05: Provider Quality Evaluation, Human Review and Controlled Promotion

- Status: Complete
- Date: 2026-08-31
- ADR: `docs/decisions/0086-provider-quality-human-review-controlled-promotion.md`

Implemented `src/agentsec/semantic/promotion.py` with quality thresholds,
independent A/B review submissions, disagreement adjudication, and explicit
owner-controlled `eligible_shadow` → `approved_shadow` transition. Reports are
strict, value-free, report-only, and never grant production or CI authority.

Verification: P3-05 tests 3 passed; Ruff and Mypy passed; package hardening
passed; reproducible build `byte_identical=true`. Full-suite baseline before
this small additive module was 1342 passed.
