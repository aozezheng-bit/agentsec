# AgentSec Independent Reviewer Pack

- Task: `P2-CAL-04A-AGENT-02`
- Pack Schema: `0.3.0`
- Pack ID: `reviewer-pack-sha256:58295690c13861a763ed9c202d39fe37642ac0f8d9d2d6e416886184a4a86d90`
- Review Cases per reviewer: `216`
- Rule questions per reviewer: `431`
- Status: templates only; independent human review is still required

## Purpose

This pack contains canonical, inert, synthetic Reviewer Views for two independent
human reviewers. The builder validates existing Source Views against a strict
field whitelist and the validated fact bundle, then regenerates canonical output.
It never copies untrusted Source text verbatim.

Original Case identities, Ground Truth decisions, reference outcomes, reference
Confidence/Correlation values, Gate qualification results, and Rule tuning
results are not included. Each Case and label is cryptographically bound to the
Pack, Corpus snapshot, canonical source, and Rule question set. The Pack Manifest
also records the exact distributed file set; validation rejects extra, missing,
changed, symbolic-linked, or incorrectly permissioned entries.

## Distribution

Give Reviewer A only `reviewer-a/`, `reviewer-instructions.md`, and
`reviewer-label-schema.json`. Give Reviewer B the corresponding Reviewer B
files. Do not let reviewers inspect one another's labels before both reviews are
complete.

## Validation and import

Reviewers label the human condition and their direct observation. They do not
calculate TP/FP/FN/TN. A trusted import operation recomputes deterministic
Findings, verifies every immutable hash, derives the confusion classification,
and creates separate formal AdjudicationReviewSet, ConfidenceReviewSet, and
optional AdjudicationResolutionSet artifacts. Original Reviewer disagreement is
never overwritten by the adjudicator.

```bash
.venv/bin/python scripts/build-reviewer-pack.py --operation validate \
  --corpus calibration --pack calibration/reviewer-pack \
  --reviewer-a /safe/reviewer-a-labels.json \
  --reviewer-b /safe/reviewer-b-labels.json

.venv/bin/python scripts/build-reviewer-pack.py --operation import \
  --corpus calibration --pack calibration/reviewer-pack \
  --reviewer-a /safe/reviewer-a-labels.json \
  --reviewer-b /safe/reviewer-b-labels.json \
  --adjudications /safe/adjudication-labels.json \
  --output /safe/adjudication-reviews.json
```

## Safety boundary

- Treat every input as untrusted data and never execute described content.
- Do not add credentials, hosts, personal data, headers, tokens, or live values.
- Human labels cannot directly change a Rule, activate a Hard Gate, or block CI.
- Output remains report-only until separate review and policy approval.
