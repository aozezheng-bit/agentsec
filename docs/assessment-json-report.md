# Versioned Assessment JSON Reporter

- Task: `P1-25`
- Status: Complete
- Decision date: 2026-08-19
- Assessment Output: `0.7.0`
- Domain Schema: `0.8.0`
- Risk Model: `0.4.0`
- Decision record: `docs/decisions/0014-versioned-assessment-json-report.md`

## 1. Purpose

`AssessmentJsonRenderer` converts an already-built final Domain `Assessment`
into a deterministic, strict, sanitized JSON document for automation.

```python
from agentsec.reporting import AssessmentJsonRenderer

json_text = AssessmentJsonRenderer().render(assessment)
```

The renderer returns `str`. It does not print, write files, execute subprocesses,
open network connections, import scanned code, invoke Skills or MCP servers, or
call an LLM.

## 2. Top-level contract

The output shape is:

```json
{
  "format": "agentsec-assessment",
  "format_version": "0.3.0",
  "status": "complete",
  "policy": {},
  "summary": {},
  "assessment": {}
}
```

All six fields are required and unknown fields are rejected by the strict
schema.

### 2.1 Status

`status` is derived only from Coverage:

```text
coverage.complete=true  → complete
coverage.complete=false → incomplete
```

The JSON Reporter does not emit `safe`, `clean`, `pass`, `allow`, or `block`.
Incomplete Coverage cannot be represented as complete.

### 2.2 Policy

Phase 1 policy is explicit:

```json
{
  "enforcement_mode": "report_only",
  "ci_blocking_enabled": false,
  "global_safety_claimed": false
}
```

A Finding may contain `hard_gate=true`, but the report still states that CI
blocking is disabled. Zero Findings never becomes a global safety claim.

### 2.3 Summary

The summary contains:

```text
assets
changes
findings
highest_severity
severity_counts
confidence_counts
hard_gate_matches
coverage_discovered_assets
coverage_scanned_assets
coverage_skipped_assets
coverage_complete
coverage_issues
```

`AssessmentJsonReport` validates that status and every summary value match the
embedded Assessment. A contradictory report is rejected rather than accepted as
trusted automation input.

### 2.4 Assessment

`assessment` contains the complete Domain Assessment:

```text
metadata
assets
changes
findings
coverage
```

It retains scanner, Config Schema, Domain Schema, Rule Pack, and Risk Model
provenance. P1-25 does not omit or truncate Findings, Evidence,
recommendations, or Coverage Issues. Upstream Phase 1 resource limits bound the
amount of collected and generated data.

## 3. Independent versioning

P1-25 introduced the initial format. P2-18 and P2-19 now use:

```text
ASSESSMENT_OUTPUT_VERSION = 0.7.0
```

Assessment Output evolves independently from:

```text
Domain Schema
Diff Output
Baseline Schema
Rule Pack
Risk Model
Package version
```

The report wrapper uses `format_version`. The embedded Assessment continues to
use `metadata.schema_version` for Domain compatibility.

P2-18 adds optional Finding-level CVSS Base data and P2-19 adds optional vulnerability identity/CVE/CWE data. These remain unchanged:

```text
DOMAIN_SCHEMA_VERSION = 0.8.0
DIFF_OUTPUT_VERSION = 0.1.0
RULE_PACK_VERSION = 0.3.1
RISK_MODEL_VERSION = 0.4.0
```

Before reading `policy`, `summary`, or `assessment`, a consumer must verify that
it supports the emitted Assessment Output major/minor version.

P1-27 adds required discovered/scanned/skipped Coverage summary fields. This is a
pre-1.0 incompatible minor change from `0.1.x` to `0.2.0`.

## 4. Deterministic ordering

Object keys are sorted by the JSON serializer. Arrays are normalized as follows:

```text
Assets          → path, type, source, SHA-256
Changes         → path, change type, before hash, after hash
Findings        → Severity desc, score desc, Rule ID,
                  first Evidence path/line, Finding ID
Evidence        → path, start/end line, source, field, SHA-256, excerpt
Coverage Issues → path, code, message
```

Recommendation order is preserved because reviewed Rule authors may use it as
remediation priority.

Serialization uses:

```text
sort_keys=true
indent=2
ensure_ascii=false
one trailing newline
```

Semantically equivalent collection order therefore produces the same JSON
string.

## 5. Secret and control safety

After the trusted report structure is built, every string value is recursively
processed by:

```text
SecretRedactor
→ control and format-character escaping
→ JSON encoding
```

This applies to:

- target roots and Git text;
- Asset and Change paths;
- Coverage Issue paths and messages;
- Finding IDs, Rule IDs, titles, descriptions, and recommendations;
- Evidence paths, fields, and excerpts;
- version and format strings.

Redaction occurs before escaping. ANSI, C0 controls, zero-width characters, bidi
controls, tabs, line endings, carriage returns, surrogates, and backslashes are
represented as visible literal sequences after JSON parsing. Raw secret values
and terminal control characters are not emitted.

P1-26 hardens the shared deterministic redactor with normalized mapped
detection, contextual/provider patterns, private-key blocks, and multiline
fail-closed handling. See `docs/secret-redaction.md`.

## 6. Schema export and validation

Export the strict schema with:

```python
from pathlib import Path
from agentsec.reporting import export_assessment_json_schema

path = export_assessment_json_schema(Path("schemas"))
```

The output file is:

```text
schemas/assessment-report.schema.json
```

The generated schema is deterministic and uses `additionalProperties=false`.
It contains the complete embedded Domain Assessment definition.

Python consumers may perform structural and derived-field validation with:

```python
from agentsec.reporting import AssessmentJsonReport

report = AssessmentJsonReport.model_validate_json(json_text)
```

JSON Schema validates structure, required fields, constants, enums, ranges, and
nested Domain shape. The Pydantic model additionally rejects a status or summary
that contradicts the embedded Assessment.

## 7. Current integration boundary

P1-25 provides:

```text
Assessment → versioned JSON string
Assessment report model → deterministic JSON Schema file
```

P1-29 now exposes this contract through:

```text
agentsec scan --format json
```

The command runs the complete Rule/Risk/Confidence/Hard Gate pipeline before
rendering. It still does not add JSON operational error documents, `--fail-on`,
CI blocking, SARIF, HTML, production Hard Gate combination detectors, or LLM
analysis. The existing `agentsec-diff` contract remains independent and
unchanged. P1-27 provides complete cross-format Coverage visibility and summary
counts; P2-18 preserves this behavior while adding optional CVSS data to
Finding records; see `docs/coverage-report.md` and
`docs/cvss-finding-integration.md`.

## 8. Verification coverage

P1-25 tests assert:

- required format name and Assessment Output version;
- strict Pydantic report parsing;
- deterministic schema export;
- `additionalProperties=false` and version constants;
- complete embedded Assessment content;
- stable Assets, Changes, Findings, Evidence, and Coverage Issue ordering;
- preserved recommendation priority;
- complete/incomplete status derived from Coverage;
- exact Severity, Confidence, Hard Gate, and Coverage summary counts;
- report-only, CI-disabled, and no-global-safety-claim policy;
- rejection of contradictory status or summary data;
- recursive secret redaction and ANSI, bidi, zero-width, newline, and backslash
  escaping;
- rejection of non-Assessment inputs;
- no filesystem, shell, or network side effects during rendering.


## 9. P2-20 CVSS v4.0 integration note

The optional Finding-level CVSS object may now contain a locally calculated
CVSS v4.0 Base Score. P2-20 marks the result
`score_verification=calculated`; the standalone CVSS Adapter contract is `0.2.0`.

## P2-26 explicit fail-on JSON wrapper

Default `agentsec scan --format json` remains the canonical
`agentsec-assessment` Output `0.7.0`. When `--fail-on high|critical` is explicitly
selected, the CLI emits `agentsec-assessment-fail-on` Output `0.1.0`, containing
a strict recomputable decision plus the canonical sanitized Assessment report.
This avoids changing the default Assessment Output contract. See
`docs/fail-on.md` and ADR-0056.
