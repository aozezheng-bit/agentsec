# AgentSec P2-CAL Calibration Corpus

- Tasks: `P2-CAL-01` through `P2-CAL-04A`
- Schema: `0.1.0`
- Capability Rule Pack: `0.2.0`
- Status: Expanded draft corpus complete; independent human review remains pending
- Cases: `216` (`61` original Seed Cases + `155` P2-CAL-04A draft Cases)

## Purpose

This corpus is the first Ground Truth contract for calibrating:

```text
false positives
false negatives
Evidence Confidence
Coverage and Unknown handling
Hard Gate candidate eligibility
```

The Cases are labels for deterministic evaluation. They are not runtime
attestations and do not authorize or block any deployment.

## Layout

```text
calibration/
├── corpus.json
├── cases/<case-id>/case.json
├── fixtures/<case-id>/facts.json
├── fixtures/<case-id>/source.*
├── gate-coverage-matrix.json
├── confidence-reviews.json
├── adjudication-reviews.json
└── reviewer-pack/
```

`facts.json` files contain only normalized, value-free fact labels. They do not
contain source excerpts, commands, URLs, headers, environment values, secrets,
credentials, personal data, or executable content.

## Corpus composition

```text
61 original P2-CAL-01 Seed Cases
155 P2-CAL-04A machine-generated draft Gate scenarios
216 total Cases
431 Rule Expectations
246 expected matches
185 expected no-matches
```

The P2-CAL-04A expansion contains 25 semantically distinct Positive scenarios
per Gate and at least 21 semantically distinct, complete, relevant-Unknown-free
Negative/Near-miss scenarios per Gate. It also retains separate Unknown boundary
Cases that do not count toward the confirmed-negative threshold.

All 29 current Capability Rule IDs have at least one expected `match` and one
expected `no_match` label. Cases cover English, Chinese, and bilingual review
labels. Expected Correlation and Evidence Confidence are explicit in each Rule
expectation.

## Loading and validation

```python
from pathlib import Path
from agentsec.calibration import load_calibration_corpus

corpus = load_calibration_corpus(Path("calibration"))
print(corpus.summary.total_cases)
print(corpus.summary.matching_cases_by_rule)
```

The Loader is data-only. It enforces bounded UTF-8 JSON, root containment, no
symlinks, fixture existence, evidence-path safety, current Rule Pack version,
and full current Rule ID coverage. It never executes fixture content.

## Boundary

This is a **Seed and machine-generated draft corpus**, not a final calibration
result. P2-CAL-02 through P2-CAL-04 provide deterministic replay, Confidence,
and adjudication contracts. The expanded scenarios still require independent
human Reviewer labels and adjudication before they can support P2-15A.

## Deterministic replay

Run the P2-CAL-02 seed replay:

```bash
.venv/bin/python scripts/run-calibration.py --corpus calibration --format text
.venv/bin/python scripts/run-calibration.py --corpus calibration --format json
```

The current fact-bundle adapter produces a perfect seed replay by construction.
This is a contract and implementation smoke test, not a production calibration
claim. Every Rule remains sample-insufficient until the corpus contains at least
20 reviewed positive and 20 reviewed negative/near-miss Cases.

## Evidence Confidence review labels

P2-CAL-03 uses `confidence-reviews.json`, currently containing 492 explicitly
seeded labels for 246 matching Finding expectations and two Seed reviewers. It is checked
against the Corpus before evaluation and never executes fixture content.

Run the Confidence report:

```bash
.venv/bin/python scripts/run-confidence-calibration.py \
  --corpus calibration \
  --reviews calibration/confidence-reviews.json \
  --format text --language zh
```

The report includes reviewer agreement, Cohen's Kappa, Expected-vs-Emitted
agreement, A/B/C/D grade matrices, per-Rule/Correlation metrics, and explicit
sample limitations. Seed Kappa `1.000` is not independent review evidence and
must not be used to enable a Hard Gate or CI blocking. See
[`docs/confidence-calibration-report.md`](../docs/confidence-calibration-report.md)
and ADR-0036.

## P2-CAL-04 adjudication and Gate Candidates

P2-CAL-04 uses `adjudication-reviews.json`, currently containing 862 explicitly
seeded labels for 431 Case/Rule expectations and two Seed reviewers. The adjudication Runner keeps
detection FP/FN, policy-accepted risk, in-scope FN, out-of-scope uncertainty,
runtime uncertainty, and unresolved reviewer disagreement separate.

Run the report:

```bash
.venv/bin/python scripts/run-calibration-adjudication.py \
  --corpus calibration \
  --adjudications calibration/adjudication-reviews.json \
  --format text --language zh
```

The current three Gate Candidates are all `more_data_required`. The expanded
Corpus now satisfies the draft scenario volume and semantic-uniqueness targets,
but the labels are still machine-generated `seeded` placeholders rather than
independent production adjudications. No Rule is changed, no
Gate is activated, and CI remains unblocked. See
[`docs/calibration-adjudication-report.md`](../docs/calibration-adjudication-report.md)
and ADR-0037.


## Independent Reviewer Pack and human import

The checked-in `reviewer-pack/` uses Pack Schema `0.3.0` and contains 216 opaque
Cases plus 431 Rule questions per Reviewer. Its Manifest binds the exact file
set, modes, SHA-256 values, roles, and Reviewer scopes. Extra, missing, changed,
or symbolic-linked files are rejected.

A completed import writes separate artifacts so adjudication cannot overwrite
Reviewer A/B or fabricate agreement:

```bash
.venv/bin/python scripts/build-reviewer-pack.py \
  --operation import \
  --corpus calibration \
  --pack calibration/reviewer-pack \
  --reviewer-a /safe/reviewer-a-labels.json \
  --reviewer-b /safe/reviewer-b-labels.json \
  --adjudications /safe/adjudication-labels.json \
  --output /safe/human-adjudication-reviews.json \
  --confidence-output /safe/human-confidence-reviews.json \
  --resolution-output /safe/human-adjudication-resolutions.json
```

Use `--evidence-mode human` only with the explicit Human Confidence artifact.
No human-mode execution falls back to Seed Confidence labels. See ADR-0038.

## Gate Calibration Coverage Check

The report-only Coverage Check CLI verifies that each approved Gate Candidate
holds at least 20 unique Positive and 20 unique eligible Negative/Near-miss
scenarios, recomputed from validated Corpus Ground Truth:

```bash
.venv/bin/python scripts/check-gate-calibration-coverage.py \
  --corpus calibration \
  --matrix calibration/gate-coverage-matrix.json \
  --format json
```

Exit codes: `0` ready, `2` insufficient samples, `4` invalid or tampered input,
`5` unexpected failure. The CLI implements no `--fail-on` and cannot block CI.
Current result: `overall_status=ready` on draft volume only — `HG-CAPCHAIN-001`
25/21, `HG-PRODAUTO-001` 25/21, `HG-EXTERNALPROD-001` 25/26, with 4 Unknown
boundary Cases per Gate. Volume readiness is not review readiness: every label
remains `seeded`, and `hard_gate=true` stays disabled until independent human
review and adjudication complete.

## Capability Shadow Gate Demo

P2-15A-PILOT-03 combines the validated `HG-CAPCHAIN-001` coverage statistics
with five live deterministic Match/No-match scenarios:

```bash
./scripts/run-shadow-gate-demo.sh --language zh --format text
```

Machine-readable output:

```bash
./scripts/run-shadow-gate-demo.sh \
  --format json \
  --output /tmp/agentsec-shadow-gate-demo.json
```

Current seeded Matrix distribution is 25 expected Match, 25 expected No-match,
21 eligible Negative/Near-miss, and 4 Unknown boundaries. These are expected
calibration labels, not independent Human Evidence. The Demo keeps
`mode=shadow`, `qualification=pilot_only`, `blocks=false`,
`hard_gate_enabled=false`, and `ci_blocking_enabled=false`.

## Demo-first Pilot Review: 100 Questions

When the full 431-question review is too large for the first demonstration, use
the deterministic pilot selection under:

```text
calibration/pilot-review-100/
```

The pilot contains exactly 100 opaque Rule questions:

```text
CAP-CHAIN-001 Demo Track: 44 questions
  20 Positive, 20 eligible Negative/Near-miss, 4 relevant Unknown boundaries
other 28 Rule IDs: 2 questions each (one match and one no_match)
```

`CAP-CHAIN-001` is selected as the Demo Track because the existing Chinese
Capability Drift Demo uses the same execute + Secret access + external network
chain as its central story. The other 28 Rules provide one-match/one-no-match
smoke coverage across the Rule Pack, languages, formats, and boundary types.

The pilot is a **human-review usability and semantic-calibration exercise**, not
a replacement for the complete Reviewer Pack. It does not qualify a Hard Gate,
does not remove the requirement for two independent Reviewers, and does not
produce a P2-CAL-04 human-evidence report. The current formal
`build-reviewer-pack.py validate/import` path still requires all 431 questions;
pilot labels must be merged through an explicitly approved subset-import flow
before they can become formal evidence.

Reviewer-facing selection and draft templates are available in:

```text
calibration/pilot-review-100/selection.json
calibration/pilot-review-100/selection.csv
calibration/pilot-review-100/reviewer-a-labels.template.json
calibration/pilot-review-100/reviewer-b-labels.template.json
```

See the directory README for the exact workflow and boundaries. The Pilot
progress CLI is `scripts/pilot-review.py`; it validates bindings, reports only
human-label progress, can compare two completed Pilot submissions, can create a
human-only disagreement worksheet, and can create a non-clobbering 431-row
merge snapshot. It never reads Ground Truth or emits formal P2-CAL-04 evidence.

## Human review guide

The complete recruitment, blind review, Ground Truth isolation, Label
lifecycle (`pending → reviewed → adjudicated`), disagreement handling, FP/FN
vocabulary, Case reuse rules, and post-review CLI workflow are documented in
[`docs/calibration-adjudication-reviewer-pack.md`](../docs/calibration-adjudication-reviewer-pack.md).
P2-CAL-04A only prepares Cases and the Reviewer Pack; it produces no Hard Gate
qualification conclusion.
