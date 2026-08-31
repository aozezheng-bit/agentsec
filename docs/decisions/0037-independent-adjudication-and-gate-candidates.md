# ADR-0037: Independent Adjudication and Gate Candidate Report

- Status: Accepted for source development
- Date: 2026-08-21
- Task: `P2-CAL-04`

## Context

P2-CAL-02 produces deterministic Fact Bundle TP/FP/FN/TN metrics and P2-CAL-03
measures Evidence Confidence agreement. Those reports cannot by themselves
distinguish a Rule implementation defect from policy-accepted risk, unsupported
scope, or runtime uncertainty. They also must not turn a small synthetic seed
corpus into a production Hard Gate decision.

## Decision

1. Add an independent `AdjudicationReviewSet` contract rather than changing the
   P2-CAL-01 Case Schema or overwriting P2-CAL-03 reviewer labels.
2. Require a complete label for every Case/Rule expectation from every declared
   reviewer. Root containment, bounded UTF-8, no symlink, and no fixture
   execution remain mandatory.
3. Keep reviewer observations separate from deterministic classifications. A
   report may show a reviewer disagreement, but it must not silently use a
   majority vote as an authorization decision.
4. Derive consensus only when classification, category, and disposition all
   agree. Otherwise emit `unresolved` with `more_data`.
5. Calculate Rule tuning recommendations with deterministic thresholds:
   insufficient samples → `more_data`; reviewed detection FP or in-scope FN →
   `tune`; scope/Unknown/Confidence limitations → `shadow`; otherwise `keep`.
   No recommendation mutates or publishes a Rule.
6. Evaluate only three report-only Gate Candidates from the approved plan. A
   candidate requires at least 20 positive and 20 negative/near-miss reviewed
   Cases, precision ≥95%, recall ≥90%, Kappa ≥0.80, complete Coverage, no
   relevant Unknown, and no D-confidence evidence. Critical candidates require
   B-confidence evidence.
7. Count Gate Candidate samples only from Cases containing every component Rule
   expectation. Confirmed Negative/Near-miss counts exclude incomplete Coverage
   and relevant Unknown dimensions; Unknown boundary Cases remain visible but do
   not satisfy the sample threshold.
8. Treat `more_data_required` as the expected result while labels remain seeded.
   Never convert this report into `hard_gate=true`, CI blocking, or `--fail-on`
   behavior.

## Consequences

### Positive

- Detection FP/FN, policy actionability, and runtime uncertainty remain separate.
- Gate candidates have auditable, reproducible reasons for acceptance, rejection,
  or insufficient data.
- The report creates a safe seam for real independent adjudication without
  granting an LLM or scanned Agent content authority.

### Limitations

- The checked-in 122 labels are seeded and therefore cannot satisfy independent
  production evidence requirements.
- Fact Bundle replay still does not measure parser or Framework Adapter recall.
- The candidate definitions are report metadata; P2-15A Gate implementation is
  intentionally not part of this task.

## Rejected alternatives

- **Use deterministic TP/FP/FN as final policy truth:** rejected because policy
  accepted risk and unsupported/runtime uncertainty need separate categories.
- **Let a majority reviewer vote activate a Gate:** rejected because unresolved
  disagreement must fail closed and remain report-only.
- **Automatically tune or retire Rules:** rejected because Rule changes require
  tests, review, and independent Rule Pack versioning.
- **Promote a candidate from seed metrics:** rejected because one positive and one
  negative/near-miss sample per Rule is insufficient for production qualification.

## P2-CAL-04A repair note

Adjudication Report Output `0.2.0` changes Gate Candidate sample-count semantics
to candidate-scoped eligible samples. It excludes relevant Unknown and incomplete
Cases from confirmed-negative counts while preserving them in the Case report.
The Review Set Schema and Capability Risk Model remain unchanged.


## P2-CAL-04A Agent 2 provenance note

ADR-0038 supersedes the earlier implementation detail that represented a final
adjudication by replacing Reviewer rows. Independent Reviewer A/B labels now
remain unchanged, final resolutions use a separate contract, and human
Confidence evidence must be supplied explicitly in human evidence mode.
