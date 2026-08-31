# P3-09: Trusted Semantic Input Builder / `semantic analyze` CLI

- Status: Complete
- Date: 2026-08-31
- ADR: `docs/decisions/0090-trusted-semantic-input-builder-analyze-cli.md`

## Scope

P3-09 converts the existing Phase 3 Shadow APIs into an end-to-end developer
workflow. It does not grant semantic output production authority.

## Deliverables

- [x] Add `TrustedSemanticInputBuilder` using trusted Framework Adapter records and deterministic Manifest state.
- [x] Sanitize and bound source Evidence before the semantic Provider boundary.
- [x] Preserve Manifest Coverage, Unknown dimensions, capability IDs, and trusted SHA-256 provenance.
- [x] Add `agentsec semantic analyze PROJECT`.
- [x] Default the command to the offline, non-billable fixture Provider.
- [x] Add bounded offline response fixture support.
- [x] Add explicit live HTTPS opt-in with credential environment names and approved bindings.
- [x] Add bilingual Text and strict JSON End-to-End Shadow reports.
- [x] Add hardened ReportArtifactWriter support for the pipeline report.
- [x] Add P3-09 Schema, Provenance, API, tests, ADR, threat-model updates, and docs.

## Acceptance criteria

1. Semantic Input is built from trusted Adapter/Manifest results, not model-authored paths or lines.
2. Default CLI execution makes no network request and no billable invocation.
3. Live Provider execution requires explicit opt-in and approved Provider/Model binding.
4. The output contains invocation, Finding links, Rule Candidates, Coverage, and authority-boundary fields.
5. Raw source, credentials, and raw Provider responses are absent from the final report.
6. The command cannot create or modify Findings, publish Rules, change Policy, or block CI.
7. Output uses the hardened report artifact writer and cannot replace a supplied response fixture.
8. Full QA, package hardening, and reproducible-build checks pass.

## Verification

```bash
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
./scripts/check.sh
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
PYTHONPATH=src .venv/bin/python scripts/verify-reproducible-build.py
```
