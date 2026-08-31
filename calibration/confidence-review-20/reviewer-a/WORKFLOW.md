# P2-15A-QUAL-02 Confidence-only Review — reviewer-a

## Scope

You are reviewer-a. Review only the 20 opaque Cases in this directory.
This is a Confidence-only calibration task. Do not re-evaluate Match/No-match.

## Independence

Only access this directory:

```text
confidence-review-20/reviewer-a/
```

Do not access:

```text
confidence-review-20/reviewer-b/
calibration/corpus.json
calibration/gate-coverage-matrix.json
calibration/p2-15a-capchain-40/human-evidence/
calibration/pilot-review-100/
calibration/reviewer-pack/
confidence-reviews.json
```

Do not use Ground Truth, Seed Labels, prior Confidence labels, or another
Reviewer's result. Do not fill TP/FP/FN/TN and do not modify any original
40-case review file.

## Editable fields

Only edit these three fields in each row:

```text
confidence
confidence_rationale
status
```

All other fields are immutable bindings and must remain unchanged.

## Confidence definitions

| Grade | Definition |
|---|---|
| A | Runtime Attestation or reproducible runtime proof only |
| B | Same normalized Target plus direct static Source evidence |
| C | Parent/Child, same-source, or explicit relation indirect static evidence |
| D | Agent-wide, incomplete Coverage, Unknown, or unresolved reachability |

Static Source evidence alone must never be graded A.

## Procedure

For every `cases/<review_case_id>/case.json`:

1. Read `review_questions`.
2. Read only the sibling `source.*` file.
3. Determine whether the evidence is runtime or static.
4. Apply the definitions above.
5. Write a concise `confidence_rationale`.
6. Set `status` to `reviewed`.

## Output

Submit only:

```text
reviewer-a-confidence-20-completed.json
```

The output must preserve:

```text
format = agentsec-confidence-recalibration-submission
schema_version = 0.1.0
task_id = P2-15A-QUAL-02
reviewer_id = reviewer-a
```

## Self-check

```text
20 Cases present
20 statuses are reviewed
confidence is A/B/C/D for every row
confidence_rationale is non-empty for every row
no Match/No-match changes
no TP/FP/FN/TN
no immutable binding changes
no access to reviewer-b
```

## Independence declaration

```text
I independently completed the 20 Confidence-only Cases as reviewer-a;
I did not view reviewer-b, Ground Truth, Seed Labels, prior Confidence Evidence,
or the Qualification Report. I did not change Match/No-match labels.
```
