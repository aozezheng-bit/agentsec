# P2-CAL-03 Evidence Confidence Agreement and Kappa Calibration

- Task: `P2-CAL-03`
- Status: Complete for source development
- Date: 2026-08-21
- Reviewer Set Schema: `0.1.0`
- Calibration Report Output: `0.1.0`
- Capability Rule Pack: `0.2.0`
- Capability Risk Model: `0.1.0`
- Enforcement: report-only

## 1. Purpose

P2-CAL-03 adds a bounded, deterministic contract for comparing Evidence
Confidence labels. It answers two separate questions:

1. **Reviewer agreement:** do two or more reviewers assign the same categorical
   `A/B/C/D` Evidence Confidence grade to the same deterministic Finding?
2. **Expected versus emitted agreement:** does the deterministic evaluator emit
   the grade declared by the Calibration Case expectation?

Evidence Confidence remains independent from Severity. It is not a score
multiplier, does not downgrade High/Critical Findings, and cannot authorize or
block a deployment.

## 2. Contracts

The implementation adds two independent JSON contracts:

```text
agentsec-capability-confidence-review-set
agentsec-capability-confidence-calibration-report
```

A reviewer label contains only bounded identifiers and categorical labels:

```text
review_id
case_id
rule_id
reviewer_id
confidence: A / B / C / D
correlation
status: seeded / reviewed / adjudicated
rationale_code
```

The review loader requires every matching Calibration Case/Rule expectation to
have one label from every declared reviewer. It validates corpus identity,
matching Rule references, correlation compatibility, deterministic ordering,
duplicate keys, root containment, UTF-8, file size, and symlink safety. It never
opens or executes fixture code and never includes raw fixture values in an error
or report.

The generated report includes:

```text
reviewer pair agreement
Cohen's Kappa
expected-versus-emitted agreement and Kappa
grade confusion matrices
per Rule / Correlation metrics
per Case evaluation records
sample insufficiency count
version and report-only policy metadata
```

## 3. Agreement calculation

For a pair of categorical label sequences:

```text
Po = observed agreement
Pe = expected agreement from the two marginal distributions
Kappa = (Po - Pe) / (1 - Pe)
```

The implementation handles the degenerate population explicitly:

```text
Pe = 1 and Po = 1 → Kappa = 1
Pe = 1 and Po != 1 → Kappa = 0
empty population → Kappa = null
```

Reviewer agreement uses all unordered reviewer pairs for each evaluated Case.
The current seed set has two reviewers, 32 evaluated Findings, and therefore 32
reviewer comparisons. The matrix uses expected grades as rows and observed
grades as columns. For `Expected vs Emitted`, the same matrix shape is used with
the Case expectation as the row label and deterministic output as the column
label.

A known calculation fixture is covered by tests:

```text
Reviewer A: A A B B
Reviewer B: A B B C
Accuracy: 0.500
Cohen's Kappa: 0.200
```

This prevents treating raw accuracy as Kappa.

## 4. Seed result

The checked-in `calibration/confidence-reviews.json` contains two **seeded**
reviewers and 492 labels for 246 matching Findings in the expanded draft
Corpus. The current deterministic result is:

```text
Reviewer agreement: 1.000
Reviewer Kappa: 1.000
Expected vs emitted agreement: 1.000
Expected vs emitted Kappa: 1.000
Reviewer agreement and Expected-vs-Emitted agreement: 1.000
The exact grade distribution is emitted by the current report.
Machine-generated draft labels remain ineligible as independent evidence.
```

These values are an implementation smoke test. They are not evidence that
independent human reviewers agree in production. A seeded label set must not be
used as Hard Gate qualification evidence.

## 5. Usage

English Text report:

```bash
.venv/bin/python scripts/run-confidence-calibration.py \
  --corpus calibration \
  --reviews calibration/confidence-reviews.json \
  --format text \
  --language en
```

Chinese Text report:

```bash
.venv/bin/python scripts/run-confidence-calibration.py \
  --corpus calibration \
  --reviews calibration/confidence-reviews.json \
  --format text \
  --language zh
```

Private JSON report:

```bash
.venv/bin/python scripts/run-confidence-calibration.py \
  --corpus calibration \
  --reviews calibration/confidence-reviews.json \
  --format json \
  --output /tmp/agentsec-confidence-calibration.json
```

The CLI requires the review file to be contained by the Corpus root, writes
explicit output files with mode `0600`, and refuses to overwrite an existing
file. Standard output contains only the selected report; it does not print
review labels or fixture contents.

## 6. Interpretation boundary

P2-CAL-03 does **not**:

```text
claim that the seed labels are independently adjudicated
calibrate parser or Framework Adapter recall
prove runtime OAuth, Tool, Permission, or sandbox state
produce A-level runtime evidence from static source rules
activate a Capability Hard Gate
enable CI blocking or --fail-on
call an LLM or publish Rules automatically
execute an Agent, MCP server, Hook, Skill, or Fixture
prove a runtime vulnerability
```

The report policy remains:

```text
enforcement_mode=report_only
ci_blocking_enabled=false
hard_gate_eligibility_decided=false
```

P2-CAL-04 provides the adjudication and candidate-report contract. The
checked-in labels remain seeded; independent label collection, diverse cases,
and Corpus expansion are still required before any P2-15A candidate is
considered.
