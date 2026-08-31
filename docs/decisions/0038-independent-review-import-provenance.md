# ADR-0038: Independent Review Import Provenance and Human Evidence Mode

- Status: Accepted for source development
- Date: 2026-08-21
- Task: `P2-CAL-04A-AGENT-02-FIX-02`

## Context

The P2-CAL-04A Reviewer Pack creates blinded source views and collects two
independent human reviews. The first import design exposed three integrity gaps:

1. Pack validation verified known files but did not reject undeclared files, so
   a post-build answer file could be added to a Reviewer directory.
2. A completed adjudication was copied into both Reviewer rows, destroying the
   original disagreement and falsely increasing Reviewer agreement metrics.
3. Reviewer Confidence and Correlation were validated but discarded during the
   formal import, causing P2-CAL-04 to continue using seeded Confidence labels.

These are evidence-provenance and report-contract decisions. They must be fixed
without enabling a Hard Gate, CI blocking, automatic Rule publication, runtime
execution, or LLM authorization.

## Decision

1. Treat a Reviewer Pack as an exact, closed file set. `pack-manifest.json`
   records every distributed file except itself with its relative path, SHA-256,
   byte size, role, Reviewer scope, and required mode. Validation rejects extra,
   missing, changed, symbolic-linked, or incorrectly permissioned files and
   directories.
2. Preserve Reviewer A and Reviewer B labels exactly as independent observations.
   The formal `AdjudicationReviewSet` contains those original reviewed labels;
   an adjudicator never replaces or impersonates either reviewer.
3. Add an independent `AdjudicationResolutionSet` contract. It records only
   completed human resolutions for disputed decisive Case/Rule rows and is
   optional because not every row requires adjudication. A Reviewer row that
   remains `uncertain` is not forced into TP/FP/FN/TN; it fails closed until
   Reviewer follow-up supplies a decisive independent label.
4. P2-CAL-04 computes original Reviewer agreement from `AdjudicationReviewSet`.
   When original labels disagree, a matching `AdjudicationResolution` may provide
   the final classification/category/disposition while agreement remains false.
   The report separately records `adjudication_required` and
   `adjudication_completed`.
5. Import Reviewer Confidence and Correlation into the existing
   `ConfidenceReviewSet` contract for every current matching Case/Rule
   expectation. The import does not overwrite the reviewers with an adjudicated
   value; human Kappa must be calculated from the two original submissions.
6. Add an explicit P2-CAL-04 evidence mode:

   ```text
   seed   = current checked-in seed review behavior
   human  = requires non-seeded AdjudicationReviewSet plus an explicit human
            ConfidenceCalibrationReport; no fallback to seed Confidence labels
   ```

7. In human mode, Gate Candidate Confidence grades and Kappa are derived from the
   supplied human Confidence report. `seed-labels-not-independent` is emitted
   only in seed mode.
8. All outputs remain report-only. Resolved adjudication is evidence, not an
   authorization action, and original Reviewer disagreement remains visible.

## Consequences

### Positive

- Reviewer agreement and adjudicated resolution are no longer conflated.
- Real Reviewer Confidence/Kappa can replace seed labels without a silent
  fallback.
- A Reviewer Pack is cryptographically and structurally closed after build.
- Existing P2-CAL-04 `AdjudicationReviewSet` and P2-CAL-03
  `ConfidenceReviewSet` remain reusable.

### Costs and limitations

- A new versioned `AdjudicationResolutionSet` Schema and Loader are required.
- The Reviewer import operation produces up to three artifacts instead of one.
- The existing Confidence report still stratifies by the Case expectation's
  reviewed correlation dimension; Reviewer-selected correlations remain in the
  imported labels and are preserved for future correlation-agreement work.
- Fact Bundle replay still does not calibrate production parser, Framework
  Adapter, runtime identity, OAuth, or actual tool reachability.

## Rejected alternatives

- **Copy the adjudicator result into Reviewer A/B rows:** rejected because it
  fabricates Reviewer agreement and destroys original evidence.
- **Keep Confidence only in the Reviewer submission:** rejected because the
  Gate Candidate Runner would continue consuming seeded Confidence labels.
- **Allow extra Pack files if bound files remain valid:** rejected because a
  distributed answer file can compromise blind review without changing a bound
  Case.
- **Automatically use human mode when files happen to be present:** rejected;
  evidence mode must be explicit and fail closed.
