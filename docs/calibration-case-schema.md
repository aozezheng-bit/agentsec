# P2-CAL-01 Calibration Case Schema and Labeled Corpus

- Status: Complete for source development
- Date: 2026-08-21
- Schema: `0.1.0`
- ADR: `docs/decisions/0035-calibration-case-schema-and-seed-corpus.md`

## 1. Contract

P2-CAL-01 introduces two independent JSON contracts:

```text
agentsec-capability-calibration-case
agentsec-capability-calibration-corpus
```

The Case contract stores normalized labels and value-free evidence locations. It
never stores raw source text or runtime secrets.

## 2. Case structure

```text
format
schema_version
case_id
case_kind
language
framework_id
purpose
fixture
source_formats
ground_truth
review
tags
```

`case_kind` supports:

```text
positive
negative
near_miss
incomplete
unknown
conflict
```

`ground_truth` contains:

```text
Coverage state
Unknown dimensions
normalized facts
Rule expectations
runtime_verified=false
```

A Rule expectation contains expected outcome, correlation, Evidence Confidence,
Finding count bounds, supporting fact IDs, and a stable rationale code.

## 3. Seed corpus

The corpus is located at:

```text
calibration/corpus.json
calibration/cases/
calibration/fixtures/
```

Current seed size:

```text
61 Cases
29 positive
29 near-miss
3 boundary Cases
29 Rule IDs covered with match and no-match labels
```

Validate it with:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
from agentsec.calibration import load_calibration_corpus

corpus = load_calibration_corpus(Path("calibration"))
print(corpus.summary)
PY
```

## 4. Security constraints

The Loader:

- treats all fixture files as untrusted data;
- never executes, imports, or follows fixture instructions;
- rejects symlinks and root traversal;
- bounds index and Case reads;
- rejects invalid UTF-8;
- verifies all evidence paths remain inside the fixture;
- requires the current Capability Rule Pack version;
- requires match and no-match labels for every current Rule ID.

The seed corpus is not a runtime proof, not an authorization source, and not a
statistical calibration result.

## 5. Next tasks

```text
P2-CAL-02: deterministic replay Runner and confusion-matrix metrics
P2-CAL-03: Evidence Confidence agreement and grade calibration
P2-CAL-04: reviewer adjudication, Rule tuning, and Gate candidate report
```

Only after those tasks pass their acceptance criteria may a Case support P2-15A
Report-only Capability Hard Gate selection.
