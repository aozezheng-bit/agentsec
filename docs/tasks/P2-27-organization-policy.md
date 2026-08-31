# P2-27: Organization Policy

- Status: Complete
- Completion date: 2026-08-25
- Depends on: P2-26
- Decision: `docs/decisions/0057-organization-policy-yaml.md`

## Delivered

```text
src/agentsec/organization_policy.py
src/agentsec/reporting/organization_policy.py
policies/organization-policy.yaml
policies/organization-policy-enforce-example.yaml
schemas/policy/organization-policy.schema.json
schemas/policy/organization-assessment-report.schema.json
tests/test_organization_policy.py
```

## Acceptance

- [x] strict bounded YAML Loader;
- [x] High/Critical Scan threshold;
- [x] configurable blocking Rule IDs without disabling detection;
- [x] configurable qualified Capability Gate IDs;
- [x] report-only and enforce modes;
- [x] Coverage precedence;
- [x] explicit Policy SHA-256 provenance;
- [x] Text/JSON/SARIF Scan reporting;
- [x] Capability enforcement YAML adapter;
- [x] strict Schemas and tamper rejection;
- [x] no LLM/runtime authority;
- [x] no waiver behavior.

Final observed results on 2026-08-25:

```text
P2-27 targeted tests: 17 passed
Ruff check: passed
Ruff format check: passed — 272 files
Mypy strict: passed — 252 source files
Pytest: 1129 passed
Organization report-only scan: exit 0, 4 visible matches, blocks=false
Organization enforce SARIF scan: exit 1, block/high
Incomplete organization scan: exit 2, blocks=false
--policy + --fail-on conflict: exit 3
Capability organization YAML: CI Report 0.2.0 with Policy provenance
```
