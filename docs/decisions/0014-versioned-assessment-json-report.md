# ADR-0014: Versioned Safe Assessment JSON Report

- Status: Accepted
- Date: 2026-08-19
- Task: P1-25

## Context

P1-24 provides human-readable Rich text for an already-built final Assessment.
Automation also needs a strict machine-readable document that preserves the
complete Assessment, exposes compatibility metadata, and cannot silently imply
that a Hard Gate match blocked CI.

Serializing `Assessment.model_dump_json()` directly is insufficient. It would
not identify the report delivery format independently from Domain Schema,
would omit explicit report-only policy, would not provide an automation summary,
and could emit secret-like or output-significant strings from repository-derived
paths, Coverage Issues, Findings, Evidence, and recommendations.

The existing `agentsec-diff` JSON contract is independently versioned and has
different fields and meaning. Reusing its `format_version` would conflate file
Diff delivery with full security Assessment delivery.

## Decision

Adopt these P1-25 decisions:

1. Introduce independent `ASSESSMENT_OUTPUT_VERSION`, initially `0.1.0`, in
   `agentsec.versioning` and include it in `VersionSet`.
2. Keep Package, Config Schema, Domain Schema, Baseline Schema, Diff Output,
   Rule Pack, and Risk Model versions unchanged.
3. Define the top-level format as `agentsec-assessment` with
   `format_version=0.1.0`.
4. Wrap the complete Domain Assessment in a strict `AssessmentJsonReport`
   document rather than changing the existing Domain Assessment model.
5. Include top-level `status`, `policy`, `summary`, and `assessment` fields.
6. Define status only as `complete` or `incomplete`, derived from
   `Assessment.coverage.complete`. Do not emit a clean, safe, pass, allow, or
   block state.
7. Define immutable Phase 1 policy fields:
   `enforcement_mode=report_only`, `ci_blocking_enabled=false`, and
   `global_safety_claimed=false`.
8. Include summary counts for Assets, Changes, Findings, Severity, Evidence
   Confidence, Hard Gate matches, Coverage completeness, and Coverage Issues.
9. Require Pydantic validation to reject a status or summary that contradicts
   the embedded Assessment.
10. Preserve the complete Assessment rather than truncating or omitting
    Findings, Evidence, recommendations, Assets, Changes, or Coverage Issues.
    Upstream collector, parser, matcher, and rule limits remain responsible for
    bounding the Assessment.
11. Normalize array order before serialization:
    - Assets by stable asset identity;
    - Changes by stable change identity;
    - Findings by Severity descending, score descending, Rule ID, first
      authoritative Evidence location, and Finding ID;
    - Evidence by authoritative locator and stable optional fields;
    - Coverage Issues by path, code, and message.
12. Preserve recommendation order because reviewed Rule authors may use it as
    remediation priority.
13. Recursively apply the existing `SecretRedactor` and output escaping to every
    string value after the trusted report structure has been created.
14. Redact before escaping. Emit ANSI, control, zero-width, bidi, newline,
    tab, carriage-return, and backslash characters as visible string data.
15. Serialize with sorted object keys, two-space indentation, UTF-8 Unicode, and
    exactly one trailing newline.
16. Provide `export_assessment_json_schema()` to emit deterministic
    `assessment-report.schema.json` from the strict report model.
17. Use `additionalProperties=false` throughout the generated Pydantic schema.
18. Keep JSON Schema responsible for structural validation and Pydantic model
    validation responsible for status/summary cross-field consistency.
19. Make `AssessmentJsonRenderer.render(assessment) -> str` a pure in-memory
    transformation with no filesystem, shell, network, scanned import, Skill,
    MCP, or LLM side effects.
20. Reject non-Assessment inputs before processing attacker-controlled object
    behavior.
21. Do not wire this renderer into `agentsec scan` in P1-25. Full application
    orchestration and CLI format selection remain later integration work.
22. Do not add JSON operational error documents, `--fail-on`, CI blocking,
    SARIF, HTML, active production Hard Gates, or LLM analysis.
23. Reuse the existing redactor at this boundary; broader secret detection and
    adversarial redaction hardening remain P1-26.

## Consequences

### Positive

- Automation can reject unsupported Assessment output versions before reading
  security-significant fields.
- The complete sanitized Domain Assessment remains available for downstream
  tools and later replay.
- Report-only, CI-disabled, and no-global-safety-claim semantics are explicit
  rather than inferred from `Finding.hard_gate`.
- Stable array order and sorted object keys produce reproducible output.
- Summary values cannot silently contradict the embedded Assessment when using
  the public Pydantic model.
- The independent schema can evolve without changing Diff Output or risk-score
  meaning.
- JSON rendering has the same redaction-before-escaping boundary as existing
  Diff and Text delivery.

### Negative

- Machine output contains both a summary and the complete Assessment, increasing
  document size.
- JSON Schema alone cannot express every derived cross-field equality; consumers
  wanting those checks must use the public model or recompute the summary.
- Sanitized strings intentionally differ from the in-memory raw Assessment.
- The renderer does not truncate output; upstream resource limits must remain
  correctly configured.
- `agentsec scan` does not yet expose the report through a `--format json`
  option.
- P1-25 does not provide operational error JSON or organization policy results.
