# P2-26: `--fail-on`

- Status: Complete
- Completion date: 2026-08-25
- Depends on: P2-23 Agentic Overall/Hard Gate track and P2-25 SARIF delivery
- Requirement: support `high` and `critical`
- Decision: `docs/decisions/0056-explicit-severity-fail-on.md`

## Goal

Allow an operator to opt into deterministic local CI blocking for final
AgentSec High/Critical Findings while preserving default report-only behavior,
Coverage precedence, Evidence Confidence separation, and Capability Gate
Qualification.

## Delivered

```text
src/agentsec/fail_on.py
src/agentsec/reporting/fail_on.py
src/agentsec/policy/__init__.py
src/agentsec/reporting/__init__.py
src/agentsec/reporting/assessment.py
src/agentsec/reporting/sarif.py
src/agentsec/cli/scan.py
src/agentsec/versioning.py
schemas/assessment/assessment-fail-on-report.schema.json
scripts/export_release_schemas.py
tests/test_fail_on.py
```

## Acceptance checklist

- [x] `scan --fail-on high` accepts High and Critical;
- [x] `scan --fail-on critical` accepts Critical only;
- [x] default scan remains report-only and returns `0` for complete Findings;
- [x] threshold match with complete Coverage returns `1`;
- [x] incomplete Coverage returns `2` even when a threshold matches;
- [x] invalid threshold such as `medium` is rejected as CLI usage error;
- [x] Confidence does not suppress Severity;
- [x] matching Finding IDs are sorted, unique, and source-text-free;
- [x] Text output carries explicit threshold and decision;
- [x] JSON uses strict `agentsec-assessment-fail-on` `0.1.0` wrapper;
- [x] JSON decoder rejects a tampered decision;
- [x] frozen JSON Schema is exported;
- [x] SARIF records fail-on policy and per-Result match state;
- [x] SARIF `level` is not used as authority;
- [x] `capability assess` does not expose `--fail-on`;
- [x] no Config Schema, Domain Schema, Assessment Output, Rule Pack, Risk Model,
  CVSS Gate, or Capability contract change;
- [x] no runtime, LLM, network, command, Skill, Hook, or MCP behavior.

## Not included

```text
P2-27 organization Policy
P2-28 waivers
CVSS fail-on
Overall Score CLI fail-on
per-Rule/category thresholds
Capability Assessment severity blocking
runtime verification
```

## Verification

Final observed results on 2026-08-25:

```text
Targeted Fail-On/CLI/Text/JSON/SARIF/Docs regression: 162 passed
Ruff check: passed
Ruff format check: passed — 269 files
Mypy strict: passed — 249 source files
Pytest: 1112 passed
Default risky scan: exit 0, canonical agentsec-assessment
Risky --fail-on high: exit 1, 4 matched High Findings
Risky --fail-on critical: exit 0, ALLOW
Malformed --fail-on high: exit 2, INCOMPLETE, blocks=false
SARIF fail-on high: exit 1, decision=block, threshold=high
```
