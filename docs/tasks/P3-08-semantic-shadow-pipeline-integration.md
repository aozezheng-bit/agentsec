# P3-08: Semantic Shadow Pipeline Integration

- Status: Complete
- Date: 2026-08-31
- ADR: `docs/decisions/0089-semantic-shadow-pipeline-integration.md`

> Scope assumption: the local repository did not previously define a P3-08 task
> contract. This task implements the next safe integration step: a reusable
> Shadow-only API that composes the existing invocation, Finding-link, and Rule
> Candidate workflows without opening production authority.

## Deliverables

- [x] Add `SemanticShadowPipeline` orchestration API.
- [x] Compose validated Shadow invocation, P3-06 Finding integration, and Rule Candidate proposal generation.
- [x] Add a strict content-addressed aggregate report.
- [x] Preserve `report_only`, `runtime_verified=false`, and `blocks=false`.
- [x] Reject tampered child hashes and authority flags.
- [x] Keep missing trusted Evidence fail-closed as `unmatched`.
- [x] Add P3-08 Schema, provenance ownership, public API, tests, ADR, and docs.

## Acceptance criteria

1. The pipeline accepts only `SemanticAnalysisInput` and a typed Shadow Adapter.
2. Existing deterministic Findings are never created or modified.
3. Rule Candidates remain review-required and are never published.
4. Child result hashes bind to the validated semantic analysis result.
5. The aggregate digest is deterministic and tamper-evident.
6. The report contains no raw source excerpt or enforcement decision.
7. Full lint, type, test, package-hardening, and reproducible-build checks pass.

## Verification commands

```bash
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
./scripts/check.sh
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
PYTHONPATH=src .venv/bin/python scripts/verify-reproducible-build.py
```
