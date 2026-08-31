# ADR-0013: Safe Assessment Text Report and Version Metadata

- Status: Accepted
- Date: 2026-08-19
- Task: P1-24

## Context

P1-23 can assemble the final Domain `Finding`, but AgentSec still needs a
human-readable report that lets a reviewer understand the scan summary and the
direct Evidence behind each Finding. The renderer processes repository-derived
paths, titles, descriptions, excerpts, and recommendations, so terminal output
is a security boundary rather than presentation-only code.

The existing `AssessmentMetadata` retained scanner, Domain Schema, and Rule Pack
versions, but did not retain the Config Schema or Risk Model version used by the
assessment. Looking up the current process constants while rendering would let
a historical Assessment be mislabeled after configuration or scoring behavior
changes.

P1-24 must remain report-only. It must not introduce JSON output, `--fail-on`,
a CI decision, active Hard Gate detectors, or execution of scanned content.

## Decision

Adopt these P1-24 decisions:

1. Add required `config_schema_version` and `risk_model_version` fields to
   `AssessmentMetadata`.
2. Increment `DOMAIN_SCHEMA_VERSION` from `0.2.0` to `0.3.0` because the public
   serialized Assessment Metadata schema gains required fields.
3. Keep Package, Config Schema, Baseline Schema, Diff Output, Rule Pack, and Risk
   Model versions unchanged; P1-24 changes delivery and provenance retention,
   not their semantics.
4. Populate both new fields when `CollectionAssessmentEngine` creates an
   Assessment. A reporter reads the Assessment's retained versions and never
   substitutes process-global versions.
5. Introduce `AssessmentTextRenderer.render(assessment) -> str` as the P1-24
   delivery seam.
6. Use Rich `Panel`, `Table`, `Group`, and `Text` renderables, but render through
   a fixed-width `Console` configured with no color system, no terminal forcing,
   no markup, and no syntax highlighting.
7. Return deterministic, ANSI-free text. Do not write files, invoke shell
   commands, open network connections, import scanned code, or call Skills,
   MCP servers, or an LLM.
8. Treat every repository-derived string as untrusted. Apply the existing
   `SecretRedactor` before escaping terminal controls, newlines, backslashes,
   zero-width characters, bidi controls, and other output-significant Unicode.
9. Show target, completeness, report-only policy, asset/change/Finding counts,
   highest Severity, per-Severity counts, per-Confidence counts, Hard Gate match
   count, Coverage counts, full version vector, timestamps, and available Git
   provenance.
10. Sort Finding details by Severity descending, score descending, Rule ID,
    first Evidence location, and Finding ID.
11. Show Finding ID, Rule ID, category, score, Severity, likelihood, impact,
    Confidence, report-only Hard Gate state, description, direct Evidence, and
    recommendations.
12. State explicitly that a matched Hard Gate does not block CI in Phase 1.
13. State explicitly that incomplete Coverage makes Findings partial and cannot
    be interpreted as a clean pass.
14. State explicitly that zero Findings in the supported scope does not prove
    that the Agent is globally safe.
15. Bound rendered Findings, Evidence items, recommendations, per-value text,
    and console width through immutable `AssessmentTextLimits`. Every omitted or
    truncated state remains visible.
16. Keep detailed Coverage Issue enumeration outside this task; P1-24 reports
    Coverage counts and a prominent incomplete warning. Later Coverage reporting
    may add issue details without changing the safety boundary.
17. Do not wire the renderer into `agentsec scan` in this task. The direct Python
    seam can be tested independently while application orchestration and output
    format selection remain later integration work.
18. Do not implement the general Assessment JSON Reporter; that remains P1-25.

## Consequences

### Positive

- Reviewers can read a bounded summary and inspect direct Evidence for every
  rendered Finding.
- High and Critical Findings remain prominent and cannot be hidden by input
  order or averaging.
- Severity, Confidence, and Hard Gate state remain visibly separate.
- Terminal-control injection and Rich-markup injection are disabled at the
  renderer boundary.
- Historical Assessment reports retain the actual Config Schema and Risk Model
  versions used to create them.
- Output limits make truncation explicit rather than silently dropping evidence.
- The pure renderer is testable without filesystem, shell, network, or CLI side
  effects.

### Negative

- Domain Schema `0.2.x` consumers must explicitly add support for `0.3.0` before
  reading new Assessments.
- Rich output uses Unicode box-drawing characters and may wrap according to the
  configured deterministic width.
- P1-24 does not provide color, interactive folding, JSON, SARIF, or HTML.
- The initial report summarizes Coverage Issues but does not enumerate their
  individual details.
- `agentsec scan` does not yet deliver final Findings through this renderer.
- The renderer reuses the existing secret redactor; broader secret detection and
  adversarial redaction hardening remain P1-26.
