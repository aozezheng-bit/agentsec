# P3-AG-08: Attack Path Evidence Calibration

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-AG-05～07
- Mode: report-only; human-review evidence only

## Objective

Calibrate the four deterministic Attack Path Evidence relations against
independent labels without changing the associator or granting enforcement
authority.

```text
frozen association report
  + independent case labels
  → exact/partial/unmatched relation metrics
  → review evidence and follow-up tuning candidates
```

## Contract

`AttackPathCalibrationCase` binds each label to:

- an exact path/target lookup key;
- the SHA-256 of the frozen association report;
- one of the reviewed case families;
- a reviewer identity and rationale code.

`AttackPathEvidenceCalibrationRunner` compares the expected relation with the
observed relation and reports:

- exact relation accuracy;
- correct/incorrect counts;
- per-relation one-vs-rest Precision, Recall, and F1;
- unreviewed association count;
- reviewer count.

Missing report rows are represented as `observed_relation=missing` and are
incorrect rather than silently treated as `unmatched`.

## Seed pilot

The checked-in seed pilot is a three-case story corpus:

```text
partial Finding association     → partially_supports
exact Semantic association       → duplicates
unrelated Semantic association  → unmatched
```

Files:

```text
calibration/attack-path/seed-association-report.json
calibration/attack-path/seed-cases.json
calibration/attack-path/seed-calibration-report.json
```

The seed pilot is intentionally not a production qualification set. It uses a
single seed reviewer and must be replaced or expanded with independent human
labels before any quality claim.

## Running

```bash
PYTHONPATH=src .venv/bin/python scripts/run-attack-path-calibration.py
PYTHONPATH=src .venv/bin/python scripts/run-attack-path-calibration.py \
  --format json \
  --output /tmp/attack-path-calibration-report.json
```

## Security boundary

```text
report_only=true
blocks=false
finding_authority=false
semantic_authority=false
policy_authority=false
ci_authority=false
hard_gate_authority=false
release_authority=false
runtime_verified=false
```

Calibration does not tune, publish, or mutate Rules. It does not modify the
association report, Findings, Severity, Confidence, Policy, CI, Hard Gates, or
runtime state. It does not prove path reachability or exploitability.

## Acceptance criteria

- [x] Strict case and report contracts with deterministic ordering.
- [x] Frozen association-report digest binding.
- [x] Exact, partial, unmatched, and missing-row evaluation.
- [x] Accuracy and per-relation Precision/Recall/F1 metrics.
- [x] Unreviewed-association visibility.
- [x] Seed pilot data and runnable calibration script.
- [x] Canonical JSON, frozen Schema, and report-only authority checks.
- [x] Tests for mismatch, duplicate labels, forged authority, and replay.

## Follow-up

The next quality step is to replace seed labels with independent human review
and expand exact-match, partial-match, hash-mismatch, path-mismatch,
line-mismatch, runtime-only, and no-source cases. That work is required before
using these metrics as a release or Gate qualification claim.
