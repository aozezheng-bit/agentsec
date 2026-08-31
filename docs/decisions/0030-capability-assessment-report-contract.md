# ADR-0030: Capability Assessment Report Contract 0.1.0

- Status: Accepted
- Date: 2026-08-20
- Task: P2I-03
- Agent Manifest Schema: `0.3.0` (unchanged)
- Capability Diff Schema: `0.1.0` (unchanged)
- Capability Assessment Output: `0.1.0` (new)

## Context

P2I-01 produces a final validated Agent Manifest and safe nine-stage trace.
P2I-02 evaluates that Manifest with independently versioned deterministic
Capability Rules. Developers and management now need stable human-readable and
machine-readable output without conflating three different artifacts:

```text
Agent Manifest
Capability Assessment
Capability Diff
```

The existing Agent Manifest and Capability Diff already have canonical strict
JSON codecs. Creating alternative report-specific JSON shapes for them would
introduce schema drift and make downstream automation choose between two sources
of truth. Capability Findings, Rule failures, policy, management summary, and
Stage Trace have no existing public JSON wrapper and therefore require a new,
independently versioned contract.

Reports cross a security boundary: source paths and normalized identifiers are
untrusted, incomplete Coverage must remain visible, and report consumers must
not infer runtime reachability, authorization, CI enforcement, or global Agent
safety.

## Decision

1. Keep the canonical artifacts independent:

   ```text
   AgentManifest                 schema 0.3.0
   CapabilityDiffResult          schema 0.1.0
   CapabilityAssessmentJsonReport output 0.1.0
   ```

2. `ManifestJsonRenderer` delegates to
   `encode_agent_manifest_json(manifest)`. It does not invent a second Manifest
   JSON representation.
3. `CapabilityDiffJsonRenderer` delegates to
   `encode_capability_diff_json(diff)`. It does not add raw before/after values
   to the value-minimizing Diff artifact.
4. Introduce:

   ```text
   CAPABILITY_ASSESSMENT_OUTPUT_VERSION = 0.1.0
   format = agentsec-capability-assessment
   format_version = 0.1.0
   ```

5. The Capability Assessment JSON wrapper contains:

   ```text
   format
   format_version
   status
   versions
   policy
   summary
   manifest
   findings
   stage_trace
   rule_failures
   ```

6. Embed the canonical strict `AgentManifest` model in the assessment wrapper.
   Do not expose raw `FrameworkInspectionResult`, Parser objects, source excerpts,
   Commands, endpoint values, URL query/fragment values, Header values,
   environment values, credentials, or memory content.
7. Include both reviewed English and Simplified Chinese Finding text in JSON.
   Language selection is a Text presentation concern and never changes Finding
   identity, correlation, score, Severity, Confidence, or evidence.
8. Derive `status` as complete only when both are true:

   ```text
   Manifest Coverage is complete
   Capability Rule execution has no isolated failures
   ```

   Summary fields are derived from embedded content and validated against it.
9. Fix policy metadata to:

   ```text
   enforcement_mode = report_only
   ci_blocking_enabled = false
   global_safety_claimed = false
   runtime_capability_verified = false
   ```

10. Preserve Severity and Evidence Confidence as independent fields. Summary
    counts never average Findings, and High/Critical Findings cannot be diluted
    by lower results.
11. Include the complete ordered nine-stage trace and sorted unique Rule failure
    IDs. Dependency exception messages are never serialized.
12. Text reports are bilingual, deterministic, ANSI-free, bounded, and pass
    every dynamic string through the shared `SecretRedactor` and
    `sanitize_untrusted_text` boundary. Every limit emits an explicit omitted
    count.
13. Capability Assessment Text presents a one-screen management summary first,
    followed by developer evidence, correlation, related IDs, and remediation.
14. Canonical JSON is complete within existing Parser and inspection resource
    limits. Human Text display limits do not truncate JSON artifacts.
15. Compatibility validation reads `format` and `format_version` before the
    full payload, uses the existing pre-1.0 compatibility policy, rejects extra
    fields, and exposes only bounded trusted field paths in errors.
16. P2I-03 does not add CLI commands, LLM analysis, runtime verification, Hard
    Gates, or CI blocking. P2I-04 owns CLI and artifact file I/O.
17. The new Capability Assessment Output version is independent from the Phase 1
    `ASSESSMENT_OUTPUT_VERSION = 0.2.0`; the two reports represent different
    analysis products and must not share a format identifier.

## Consequences

### Positive

- Manifest and Capability Diff retain one canonical machine representation.
- Capability Findings gain a strict, deterministic, schema-exportable wrapper.
- Management can see highest Severity, Confidence distribution, Coverage, Rule
  execution, and inventory counts before developer detail.
- Developers can trace every Finding to portable path, field, line range, and
  content hash without source excerpts or credential values.
- Incomplete Coverage or Rule execution cannot be represented as complete.
- English and Chinese presentation are supported without changing detector
  semantics.
- Report-only and no-runtime-proof boundaries are machine-visible and visible in
  Text.

### Negative

- The assessment wrapper embeds a full Manifest, so it is larger than a summary-
  only report.
- Capability Assessment Output is another interface that must be versioned and
  maintained independently.
- Text display limits may omit details; consumers requiring complete data must
  use JSON.
- Static declarations and correlations still cannot prove runtime reachability,
  successful exploitation, or global safety.
- CLI commands and durable artifact writing remain unavailable until P2I-04.
