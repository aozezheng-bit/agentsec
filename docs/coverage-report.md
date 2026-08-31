# Assessment Coverage Reporting

- Task: `P1-27`
- Status: Complete
- Decision date: 2026-08-19
- Assessment Output: `0.2.0`
- Domain Schema: `0.3.0`
- Decision record:
  `docs/decisions/0016-coverage-reporting-and-assessment-output-0.2.0.md`

## 1. Purpose

Coverage answers how much of the selected Phase 1 scope was actually evaluated.
It is separate from Findings and risk severity.

```text
Coverage Issue ≠ Finding
Incomplete Coverage ≠ Low Risk
Zero Findings + Incomplete Coverage ≠ Clean Pass
```

P1-27 makes individual Coverage gaps visible in both human and machine
Assessment reports.

## 2. Domain contract

`ScanCoverage` retains:

```text
discovered_assets
scanned_assets
skipped_assets
complete
issues
```

The Domain validator requires:

```text
scanned_assets + skipped_assets == discovered_assets
```

Complete Coverage cannot contain skipped Assets or Issues. Incomplete Coverage
must contain at least one skipped Asset or one Issue.

A `CoverageIssue` contains:

```text
code
asset_path, optional
message
```

An absent path means the Issue applies to the scan or processing stage rather
than one retained project-relative Asset.

## 3. Rich Text presentation

When Coverage is incomplete, the report now emits:

1. the existing prominent incomplete warning;
2. a `Coverage issues (N total)` section;
3. a table containing:

```text
#
Code
Asset
Reason
```

A missing Asset path is rendered as:

```text
(scan-wide)
```

Example:

```text
Coverage issues (2 total)

#  Code        Asset               Reason
1  rule_error  (scan-wide)         Rule failed safely.
2  unreadable  private/AGENTS.md   Permission denied.
```

The report continues to show total discovered, scanned, skipped, and Issue
counts in the summary.

## 4. Text output limits

`AssessmentTextLimits` adds:

```text
max_coverage_issues = 100
```

The value must be a positive non-boolean integer. If more Issues exist, the
report displays only the configured number and emits:

```text
WARNING: N Coverage Issue(s) omitted by the Text Reporter limit.
Coverage remains incomplete.
```

The summary always retains total counts. Limiting detail never changes Coverage
status or represents the report as complete.

If skipped Assets exist but `issues` is empty, the report says explicitly that
no structured Coverage Issue was retained and that upstream collection
diagnostics must be reviewed.

## 5. Deterministic ordering

Coverage Issues are sorted by:

```text
asset_path, with scan-wide first
→ issue code
→ message
```

Reordering the input tuple does not change Text or JSON output.

The reporter does not assume a one-to-one relationship between skipped Assets
and Issues. For example, one `asset_limit_exceeded` Issue may explain several
Assets that were never individually retained.

## 6. Safe paths and reasons

Issue paths and messages are untrusted data. They pass through:

```text
P1-26 SecretRedactor
→ control/format-character escaping
→ Text or JSON rendering
```

This protects credentials embedded in parser or dependency diagnostics and
prevents paths or reasons from injecting ANSI, bidi, zero-width, newline, or
Unicode separator behavior.

The report preserves Issue code because it is a fixed Domain enum rather than
repository-controlled text.

## 7. JSON presentation

Assessment JSON continues to retain the complete normalized Coverage object:

```json
{
  "coverage": {
    "complete": false,
    "discovered_assets": 2,
    "scanned_assets": 1,
    "skipped_assets": 1,
    "issues": [
      {
        "code": "unreadable",
        "asset_path": "private/AGENTS.md",
        "message": "Permission denied."
      }
    ]
  }
}
```

P1-27 adds these required JSON summary fields:

```text
coverage_discovered_assets
coverage_scanned_assets
coverage_skipped_assets
```

Existing summary fields remain:

```text
coverage_complete
coverage_issues
```

`AssessmentJsonReport` rejects any summary count that contradicts the embedded
Coverage object.

JSON does not apply `max_coverage_issues`. Machine output retains every
structured Issue because omission would make the complete Assessment
representation false.

## 8. Assessment Output 0.2.0

P1-27 changes:

```text
ASSESSMENT_OUTPUT_VERSION: 0.1.0 → 0.2.0
```

The minor increment is required because three required fields were added to the
strict JSON summary. Before 1.0, consumers supporting only `0.1.x` must reject
`0.2.0` until updated.

The following remain unchanged:

```text
CONFIG_SCHEMA_VERSION = 0.1.0
DOMAIN_SCHEMA_VERSION = 0.3.0
BASELINE_SCHEMA_VERSION = 0.1.0
DIFF_OUTPUT_VERSION = 0.1.0
RULE_PACK_VERSION = 0.2.0
RISK_MODEL_VERSION = 0.4.0
```

## 9. Risk and enforcement boundary

Coverage Issues do not automatically become Findings. P1-27 does not assign:

```text
Likelihood
Impact
Score
Severity
Evidence Confidence
Hard Gate
CI Block
```

An incomplete result remains operationally important, but its policy handling
must not be confused with deterministic security-risk scoring.

Phase 1 remains report-only. P1-27 does not add `--fail-on`, retry skipped
content, execute referenced files, or automatically repair a project.

## 10. Current integration boundary

P1-27 completes direct Assessment report-layer Coverage visibility:

```text
Assessment → Rich Text with bounded Coverage details
Assessment → JSON with complete Coverage and count summary
```

P1-29 now composes Collector, Parser, Rule, Risk, Confidence, report-only Hard
Gate, and final reporter stages in `agentsec scan`. Collector, Parser, and Rule
failures remain visible as incomplete Coverage; required downstream analysis
failure returns exit code `5` without emitting a misleading partial Assessment.

## 11. Verification coverage

P1-27 tests assert:

- stable Issue ordering independent from input order;
- visible Issue code, path or scan-wide scope, and reason;
- secret redaction and control-character escaping in paths and messages;
- total discovered/scanned/skipped/Issue counts;
- explicit incomplete warning even with zero Findings;
- visible Text omission count and persistent incomplete wording;
- explicit warning when skipped Assets have no structured Issue;
- JSON retention of the complete Issue list;
- JSON summary discovered/scanned/skipped counts;
- rejection of contradictory JSON Coverage summary counts;
- Coverage gaps do not create Findings;
- invalid `max_coverage_issues` values are rejected;
- no new filesystem, shell, network, Skill, MCP, or LLM side effects.
