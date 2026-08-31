# P2-CAL-02 Deterministic Evaluation Runner

- Status: Complete for source development
- Date: 2026-08-21
- Report Output: `0.1.0`
- Capability Rule Pack: `0.2.0`
- Capability Risk Model: `0.1.0`
- Next: P2-CAL-04 independent review, Rule tuning, and Hard Gate candidacy

## 1. Purpose

P2-CAL-02 replays the P2-CAL-01 seed corpus and computes deterministic
confusion-matrix metrics. It separates the observed Rule outcome from the
reviewed Case label and does not change any Rule, Risk, Hard Gate, or CI policy.

```text
Loaded Calibration Corpus
→ safe Fact Bundle Evaluator
→ per-Case / per-Rule observation
→ TP / FP / FN / TN
→ Precision / Recall / FPR / F1
→ Confidence / Correlation / Evidence / Coverage metrics
→ Text / JSON Calibration Report
```

## 2. Current evaluator boundary

The current source-development evaluator is:

```text
fact-bundle-rule-spec 0.1.0
```

It reads only bounded JSON fact bundles, validates them against the Case labels,
and applies deterministic normalized fact predicates for all 29 current Rule IDs.
It never executes or imports Fixture content.

This is intentionally a **fact-level replay adapter**, not a claim that parser
recall, framework extraction recall, runtime reachability, or runtime grants have
been calibrated. Project, Manifest Snapshot, and future production-like
adapters can implement the same `CalibrationCaseEvaluator` protocol later.

## 3. Metrics

Per Rule and aggregate reports include:

```text
TP / FP / FN / TN
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
False Positive Rate = FP / (FP + TN)
F1
Macro and Micro metrics
Correlation agreement
Evidence Confidence agreement
Evidence completeness
Coverage visibility
Unknown visibility
Rule failures
Duplicate Findings
Sample sufficiency
```

Undefined ratios are serialized as `null` rather than zero. A Rule is sample
sufficient only when it has at least 20 reviewed positive and 20 reviewed
negative/near-miss samples. The current 61-Case seed corpus intentionally does
not satisfy that threshold.

## 4. Seed replay result

The deterministic seed replay currently reports:

```text
Cases: 61
Expectations: 61
Rules: 29
TP: 32
FP: 0
FN: 0
TN: 29
Micro Precision: 1.000
Micro Recall: 1.000
Micro F1: 1.000
Correlation agreement: 1.000
Confidence agreement: 1.000
Evidence completeness: 1.000
Coverage visibility: 1.000
Unknown visibility: 1.000
Rule failures: 0
Duplicate Findings: 0
Insufficient-sample Rules: 29
```

These perfect metrics are expected for the synthetic seed fact-bundle adapter
and must **not** be presented as production calibration. P2-CAL-03 and
P2-CAL-04 must add independently reviewed and more diverse replay inputs.

## 5. Usage

Human-readable report:

```bash
.venv/bin/python scripts/run-calibration.py \
  --corpus calibration \
  --format text \
  --language en
```

Chinese report:

```bash
.venv/bin/python scripts/run-calibration.py \
  --corpus calibration \
  --format text \
  --language zh
```

Machine-readable report:

```bash
.venv/bin/python scripts/run-calibration.py \
  --corpus calibration \
  --format json \
  --output /tmp/agentsec-calibration.json
```

Output files are created privately with mode `0600` and are not overwritten.

## 6. Report-only boundary

P2-CAL-02 does not:

```text
activate a Capability Hard Gate
change hard_gate=true
block CI
implement --fail-on
make an authorization decision
read runtime OAuth/Permission state
call an LLM
publish or modify Rules automatically
prove a vulnerability
```

The report policy is:

```text
enforcement_mode=report_only
ci_blocking_enabled=false
runtime_capability_verified=false
hard_gate_eligibility_decided=false
```

## 7. P2-CAL-03 handoff

P2-CAL-03 adds a separate reviewer-label contract, Cohen's Kappa, reviewer
pair agreement, Expected-vs-Emitted agreement, grade matrices, bilingual Text
and JSON delivery, and the `scripts/run-confidence-calibration.py` CLI. See
[`docs/confidence-calibration-report.md`](confidence-calibration-report.md).

The current seed result is 1.000 reviewer agreement and 1.000 Kappa across 32
Finding Cases. These labels are `seeded`, not independently adjudicated human
labels. They are not production parser/runtime calibration and do not qualify a
Hard Gate. P2-CAL-04 is the next task.
