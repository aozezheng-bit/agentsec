# ADR-0036: Evidence Confidence Calibration and Cohen's Kappa

- Status: Accepted for source development
- Date: 2026-08-21
- Task: `P2-CAL-03`

## Context

AgentSec must distinguish the strength of an evidence path from Finding
Severity. The P2-CAL-01 Case Schema records expected Correlation and Evidence
Confidence, and P2-CAL-02 can replay deterministic Fact Bundles. That is not
enough to measure whether reviewer labels agree or whether a deterministic
adapter emits the expected grade.

A simple percentage agreement can be misleading when grade distributions are
imbalanced. The calibration contract therefore needs a categorical agreement
statistic, bounded reviewer labels, deterministic output, and a report-only
policy that cannot become an authorization path.

## Decision

1. Add an independent `ConfidenceReviewSet` contract rather than changing the
   P2-CAL-01 Case Schema. Human/reviewer labels are observations and must not be
   conflated with immutable Case ground truth.
2. Use categorical Cohen's Kappa over `A/B/C/D` grades:

   ```text
   Po = observed agreement
   Pe = agreement expected from marginal distributions
   Kappa = (Po - Pe) / (1 - Pe)
   ```

   Degenerate populations are handled explicitly: perfect constant agreement
   is `1`, inconsistent constant marginals are `0`, and an empty population is
   `null`.
3. Compute reviewer agreement over every unordered reviewer pair for every
   evaluated Case. Also compute an independent Expected-vs-Emitted population
   using the Case expectation and deterministic evaluator output.
4. Include grade matrices, per-Rule/Correlation metrics, sample insufficiency,
   version metadata, limitations, and report-only policy in the output.
5. Keep the checked-in labels explicitly `seeded`. Kappa `1.0` on those labels is
   a deterministic fixture result, not production reviewer evidence.
6. Keep A-level runtime evidence out of the current static evaluator. D-level or
   incomplete evidence remains ineligible for Hard Gate promotion.
7. Keep all loaders bounded and value-minimizing. Reviewer files are contained
   by the Corpus root, reject symlinks, and never execute fixtures.

## Consequences

### Positive

- Reviewer disagreement can be represented without changing ground truth.
- Kappa avoids reporting raw agreement as chance-corrected agreement.
- Text and JSON reports are reproducible and easy to compare in CI/reporting
  pipelines while remaining report-only.
- The contract creates a seam for independently adjudicated labels in
  P2-CAL-04.

### Negative / limitations

- Kappa is sensitive to prevalence and is not a Severity, risk score, or gate
  threshold by itself.
- Two reviewers and 32 seed Findings are insufficient for production claims.
- The current deterministic evaluator remains a Fact Bundle adapter; parser,
  Framework Adapter, and runtime Evidence Confidence are not calibrated.
- A reviewer disagreement does not automatically mean the Rule is wrong; it
  requires Case adjudication and evidence-path review.

## Rejected alternatives

- **Use raw accuracy only:** rejected because it ignores chance agreement and is
  not sufficient for the intended categorical calibration signal.
- **Overwrite Case expected confidence with reviewer labels:** rejected because
  it destroys the distinction between deterministic ground truth and reviewer
  observation.
- **Use Confidence as a score multiplier or gate predicate:** rejected because
  Severity and Evidence Confidence are independent security concepts.
- **Let an LLM adjudicate or publish labels automatically:** rejected because
  LLM output is evidence only and cannot authorize a Rule or a Gate.
