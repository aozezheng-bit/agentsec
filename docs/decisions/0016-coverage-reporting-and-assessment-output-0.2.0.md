# ADR-0016: Coverage Reporting and Assessment Output 0.2.0

- Status: Accepted
- Date: 2026-08-19
- Task: P1-27

## Context

`ScanCoverage` has always retained discovered, scanned, and skipped Asset counts,
a completeness flag, and structured Coverage Issues. P1-24 displayed only the
counts and an incomplete warning in Rich Text. A reviewer could not see which
Asset or scan-wide stage failed or why. P1-25 included the complete Coverage
object in JSON, but its automation summary exposed only completeness and Issue
count rather than all three Asset counts.

This difference made Text and JSON answer different questions. It also created a
risk that a skipped Asset count with no structured Issue would be noticed in the
summary but have no explicit explanation in the detailed report.

Coverage Issues contain repository-derived paths and messages. They must pass
through the same redaction, output escaping, ordering, and resource controls as
Finding Evidence.

## Decision

Adopt these P1-27 decisions:

1. Keep `ScanCoverage` and `CoverageIssue` Domain structures unchanged.
2. Preserve the invariant
   `scanned_assets + skipped_assets == discovered_assets`.
3. Continue to derive report `COMPLETE`/`INCOMPLETE` status only from
   `ScanCoverage.complete`.
4. Never use `clean`, `safe`, `pass`, `allow`, or `block` as a Coverage result.
5. Add a Rich Text Coverage Issue section whenever Coverage is incomplete.
6. Display each visible Issue's stable code, project-relative Asset path or
   `(scan-wide)`, and human-readable reason.
7. Sort Text Coverage Issues by Asset path, Issue code, and message, matching the
   existing deterministic JSON normalization.
8. Apply the shared P1-26 `SecretRedactor` and output escaping to every Issue path
   and message before rendering.
9. Add `max_coverage_issues`, default `100`, to `AssessmentTextLimits`.
10. Reject non-positive or boolean Coverage Issue limits before rendering.
11. When the Text limit omits Issues, state the exact omitted count and repeat
    that Coverage remains incomplete.
12. When Coverage is incomplete with skipped Assets but no structured Issue,
    render an explicit warning that no structured reason was retained and direct
    the reviewer to upstream collection diagnostics.
13. Keep total discovered/scanned/skipped/Issue counts visible even when Text
    details are limited.
14. Do not infer that one Coverage Issue equals one skipped Asset. One Issue may
    represent a scan-wide failure or several omitted Assets.
15. Keep the complete, sorted, sanitized Coverage Issue list in Assessment JSON;
    do not apply the human Text limit to machine output.
16. Add `coverage_discovered_assets`, `coverage_scanned_assets`, and
    `coverage_skipped_assets` to `AssessmentReportSummary`.
17. Continue to include `coverage_complete` and `coverage_issues` in the JSON
    summary.
18. Require `AssessmentJsonReport` validation to reject any Coverage count in the
    summary that contradicts the embedded Assessment.
19. Increment `ASSESSMENT_OUTPUT_VERSION` from `0.1.0` to `0.2.0` because the
    strict machine-readable summary gains required fields. Before 1.0 this is a
    potentially incompatible minor format change.
20. Keep Domain Schema, Diff Output, Config Schema, Baseline Schema, Rule Pack,
    and Risk Model versions unchanged.
21. Keep Coverage Issues separate from Findings. A Coverage gap does not receive
    a Severity, score, Confidence grade, or Hard Gate merely because it appears
    in the report.
22. Do not add CI risk blocking, `--fail-on`, Coverage-to-Finding conversion,
    retries, automatic remediation, or execution of skipped content.
23. Keep rendering as a pure operation with no filesystem, shell, network,
    scanned import, Skill, MCP, or LLM side effects.
24. Do not wire final Assessment reporters into `agentsec scan` in this task;
    complete application orchestration remains later work.

## Consequences

### Positive

- Reviewers can identify which Asset or scan-wide stage was not evaluated and
  read a safe reason.
- Incomplete Coverage can no longer look like an unexplained clean report.
- Text and JSON expose the same total Asset counts and completeness semantics.
- Machine consumers can use summary counts without traversing the full embedded
  Assessment while still validating them against it.
- Human output remains bounded and every omitted Issue is explicit.
- Machine output preserves every structured Issue for automation and audit.
- Coverage gaps remain separate from security-risk magnitude and enforcement.

### Negative

- Assessment Output `0.1.x` consumers must explicitly add support for `0.2.0`.
- Rich reports become longer when many Coverage Issues are present.
- A missing structured Issue cannot be reconstructed by the reporter; it can
  only be made visible as missing diagnostic detail.
- Text and JSON intentionally differ in limiting behavior: Text may omit detail
  with a warning, while JSON remains complete.
- P1-27 does not establish retries, root-cause recovery, or CI policy for
  incomplete Coverage.
