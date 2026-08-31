# P2-CAL-04 Independent Adjudication and Gate Candidate Report

- Task: `P2-CAL-04`
- Status: Complete for source development
- Date: 2026-08-21
- Adjudication Review Set Schema: `0.1.0`
- Adjudication Report Output: `0.3.0`
- Adjudication Resolution Set Schema: `0.1.0`
- Current enforcement: report-only

## 1. Purpose

P2-CAL-04 joins deterministic Corpus/Rule replay with either Seed or explicit
Human evidence:

```text
P2-CAL-01 Calibration Corpus
P2-CAL-02 deterministic FP/FN replay report
P2-CAL-03 Evidence Confidence agreement report
P2-CAL-04 independent AdjudicationReviewSet
optional AdjudicationResolutionSet
```

It adds a separate adjudication contract for distinguishing:

```text
detection false positive
policy-accepted risk
in-scope false negative
out-of-scope uncertainty
runtime uncertainty
unresolved reviewer disagreement
```

It then produces deterministic Rule tuning recommendations and a report-only
Gate Candidate assessment. It does not edit the Capability Rule Pack, change a
Risk Model, activate a Hard Gate, or block CI.

## 2. Adjudication contract

The new format is:

```text
agentsec-capability-calibration-adjudication-set
```

Each reviewer label contains only bounded identifiers and classifications:

```text
adjudication_id
case_id
rule_id
reviewer_id
classification: true_positive / false_positive / false_negative / true_negative
category
 disposition: keep / tune / shadow / retire / more_data
status: seeded / reviewed / adjudicated
rationale_code
```

The Loader requires every Case/Rule expectation to have one label from every
reviewer. It validates corpus and labels version, Case/Rule references,
completeness, sorting, duplicate keys, root containment, UTF-8, file size, and
symlink safety. It does not read raw fixture values or execute fixture content.

The report derives a consensus only when all reviewer classifications,
categories, and dispositions agree. A disagreement becomes `unresolved` and
receives the conservative `more_data` disposition. There is no silent majority
vote that can authorize a Gate.


## 2.1 Independent Reviewer and Resolution provenance

ADR-0038 separates the two original Reviewer labels from final adjudication.
`AdjudicationReviewSet` always retains Reviewer A/B observations. A completed
`AdjudicationResolutionSet` supplies a final classification/category/disposition
for a disputed row without changing the original agreement flags. Reports expose
`adjudication_required` and `adjudication_completed` separately.

The Runner supports explicit evidence modes:

```text
seed  = checked-in seeded Adjudication and Confidence labels
human = non-seeded AdjudicationReviewSet plus an explicit human Confidence report
```

Human mode fails closed when Human Confidence is missing and never silently
loads the checked-in Seed Confidence file.

## 3. Rule tuning and FP/FN calibration

For every current Capability Rule, the report includes:

```text
TP / FP / FN / TN
Precision / Recall / F1
positive and negative sample counts
reviewed detection false positives
policy-accepted risks
in-scope false negatives
out-of-scope and runtime uncertainty
unresolved adjudications
reviewer agreement and category agreement
Confidence Kappa
recommended disposition
reason codes
```

Recommendation policy is deterministic:

```text
MORE_DATA: positive or negative sample threshold is not met
TUNE: reviewed detection FP or in-scope FN exists
SHADOW: scope, Coverage, Unknown, or reviewer-confidence limitation remains
KEEP: sufficient and no blocking calibration limitation
```

`RETIRE` is a possible reviewed disposition in the contract, but the runner
never retires a Rule automatically. Rule changes require tests, review, and a
separate Capability Rule Pack version decision.

## 4. Gate Candidate assessment

The report evaluates three design candidates from the Hard Gate plan:

```text
HG-CAPCHAIN-001       High: execute + secret access + external network
HG-PRODAUTO-001       High: production authority without effective approval
HG-EXTERNALPROD-001   Critical candidate: privileged external identity + production authority
```

Each candidate reports:

```text
positive and negative sample counts
conservative precision and recall across component Rules
Confidence grades and reviewer Kappa
Coverage completeness
relevant Unknown state
reviewer consensus
status: accepted / rejected / more_data_required
reason codes
```

Candidate sample counts use only Gate-scoped Cases that contain all component
Rule expectations. Positive counts require all component outcomes to match;
Negative/Near-miss counts exclude incomplete Coverage and any Case with relevant
Unknown dimensions. Unknown boundary Cases remain visible but do not satisfy the
confirmed-negative sample threshold.

The promotion thresholds are intentionally conservative:

```text
at least 20 reviewed positive Cases
at least 20 reviewed negative or near-miss Cases
precision >= 0.95
in-scope recall >= 0.90
reviewer Kappa >= 0.80
complete relevant Coverage
no relevant Unknown
no D-confidence evidence
Critical candidates require B-confidence evidence
```

The P2-CAL-04A expanded draft Corpus now has at least 20 semantically distinct
eligible Positive and Negative/Near-miss scenarios per candidate. It still uses
machine-generated `seeded` labels rather than independent human review.
Therefore all three candidates continue to return:

```text
status=more_data_required
```

This is the intended fail-closed calibration result, not a Gate rejection due
to a Rule defect.

## 5. Usage

English report:

```bash
.venv/bin/python scripts/run-calibration-adjudication.py \
  --corpus calibration \
  --adjudications calibration/adjudication-reviews.json \
  --format text \
  --language en
```

Chinese report:

```bash
.venv/bin/python scripts/run-calibration-adjudication.py \
  --corpus calibration \
  --adjudications calibration/adjudication-reviews.json \
  --format text \
  --language zh
```

JSON report:

```bash
.venv/bin/python scripts/run-calibration-adjudication.py \
  --corpus calibration \
  --adjudications calibration/adjudication-reviews.json \
  --format json \
  --output /tmp/agentsec-calibration-adjudication.json
```

Explicit output files are created with mode `0600` and are not overwritten.

## 6. Seed result and boundary

The checked-in Seed adjudication set contains:

```text
216 Cases
431 Expectations
862 reviewer labels
2 Seed reviewers
431 seeded consensus results
0 unresolved Seed results
3 Gate Candidates
3 more_data_required candidates
```

The labels are generated Seed labels, not independent production adjudication.
The report proves the data contract, deterministic aggregation, and fail-closed
candidate logic. It does not prove Rule precision/recall for production
parsers, Framework Adapters, runtime permissions, OAuth scopes, reachability, or
vulnerability exploitability.

The policy remains:

```text
enforcement_mode=report_only
ci_blocking_enabled=false
hard_gate_eligibility_decided=false
automatic_rule_publication=false
```

P2-15A must not enable `hard_gate=true` based on this seed report. The next
separate work is to replace Seed labels with independently reviewed and
adjudicated Cases, expand sample volume, and rerun the report.


## 8. Human evidence execution

After the independent Reviewer Pack importer creates the three formal artifacts,
run:

```bash
.venv/bin/python scripts/run-calibration-adjudication.py \
  --corpus /safe/calibration \
  --adjudications /safe/calibration/human-adjudication-reviews.json \
  --confidence-reviews /safe/calibration/human-confidence-reviews.json \
  --resolutions /safe/calibration/human-adjudication-resolutions.json \
  --evidence-mode human \
  --format json
```

The report remains `report_only`. Human evidence mode removes the
`seed-labels-not-independent` reason only after explicit non-seeded review and
Confidence inputs pass validation; it does not activate a Hard Gate.
