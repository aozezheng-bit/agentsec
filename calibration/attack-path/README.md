# Attack Path Evidence Calibration Seed

This directory contains a **seed wiring pilot** for P3-AG-08, not production
quality qualification evidence.

```text
seed-association-report.json
  + seed-cases.json
  → seed-calibration-report.json
```

The three cases cover:

- Finding `partially_supports`;
- Semantic Candidate `duplicates`;
- unrelated Semantic Candidate `unmatched`.

All labels are bound to the SHA-256 digest of the frozen association report.
The seed uses one seed reviewer and must be replaced or expanded with
independent human labels before reporting production Precision/Recall or using
it for Gate qualification.

Run:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-attack-path-calibration.py
```

The runner is deterministic, report-only, and does not modify the association
report, Findings, Rules, Policy, CI, Hard Gates, or runtime state.
