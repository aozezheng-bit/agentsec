# ADR-0035: P2-CAL-01 Calibration Case Schema and Seed Corpus

- Status: Accepted for source development
- Date: 2026-08-21
- Task: P2-CAL-01
- Calibration Case Schema: `0.1.0`
- Capability Rule Pack under test: `0.2.0`
- Capability Risk Model: `0.1.0` (unchanged)
- Enforcement: report-only, unchanged

## Context

P2-14 expanded the deterministic Capability Rule Pack to 29 Rules. Before
introducing Capability Hard Gates, AgentSec needs a reproducible way to label
positive, negative, near-miss, incomplete, Unknown, and conflicting scenarios.
The labels must distinguish:

```text
detection false positive
policy/actionability false positive
in-scope false negative
out-of-scope or runtime uncertainty
```

The calibration corpus must be safe to store and replay. It must not contain
real credentials, internal endpoints, personal data, executable helpers, raw
secret values, or runtime authorization claims.

## Decision

### 1. Add an independent Calibration Case contract

Add `agentsec.calibration` with strict immutable models for:

```text
CalibrationCase
CalibrationFixture
CalibrationGroundTruth
CalibrationFact
CalibrationRuleExpectation
CalibrationEvidenceReference
CalibrationReview
CalibrationCorpusIndex
```

The serialized formats are:

```text
agentsec-capability-calibration-case
agentsec-capability-calibration-corpus
```

Both use Schema `0.1.0` and Draft 2020-12 JSON Schema exports.

### 2. Store expected normalized facts, not raw source values

A Case records bounded fact labels such as:

```text
permission / execute / present
control / human-approval / absent
relationship / persists-memory / present
coverage / relevant-dimension / unknown
```

Evidence is value-free and contains only:

```text
fixture-relative asset path
safe field path
optional line range
```

The schema does not accept source excerpts, Commands, URLs, headers,
environment-variable values, credentials, memory content, or runtime grants.

### 3. Keep Rule outcome and reviewer disposition separate

Each Rule expectation independently records:

```text
match / no_match
expected correlation
expected Evidence Confidence
Finding count bounds
supporting fact IDs
```

The reviewer record independently records:

```text
seeded / reviewed / adjudicated
Actionable / Accepted Risk / Not Applicable / Unsupported / Ambiguous
reviewer reference aliases
rationale code
```

A Rule match therefore does not automatically mean a CI block or an approved
policy decision.

### 4. Use portable fixture references and fail closed

The corpus index contains sorted relative Case paths. The Loader verifies:

```text
UTF-8 bounded JSON
root containment
no symlink Case or fixture paths
existing fixture files/directories
safe evidence asset paths
current Capability Rule Pack version
all current Rule IDs have match and no-match labels
```

The Loader never executes or imports fixture content. A future calibration Runner
may interpret a fixture through an explicit safe adapter, but the Case Loader
itself remains data-only.

### 5. Add a reviewed seed corpus for all 29 Rules

The source tree contains 61 seed Cases:

```text
29 positive Rule Cases
29 near-miss Rule Cases
1 incomplete Coverage boundary Case
1 Unknown relationship boundary Case
1 conflicting approval-control boundary Case
```

The corpus covers English, Chinese, and bilingual labels, and records expected
B/C/D Evidence Confidence without producing A-level runtime evidence.

These are **seed labels**, not final calibrated metrics. P2-CAL-02 through
P2-CAL-04 must replay, review, adjudicate, and expand the corpus before any
Hard Gate candidate is accepted.

### 6. Keep versions independent

P2-CAL-01 changes neither:

```text
Capability Rule Pack `0.2.0`
Capability Risk Model `0.1.0`
Agent Manifest Schema `0.3.0`
Capability Assessment Output `0.1.0`
Capability Change Impact Output `0.1.0`
```

Only the independent Calibration Case Schema `0.1.0` is introduced.

## Consequences

### Positive

- Calibration inputs and labels are deterministic and reviewable.
- FP/FN analysis can distinguish Rule defects from policy acceptance and runtime
  uncertainty.
- Evidence Confidence expectations are explicit per Case and Rule.
- Hard Gate candidates can be rejected before implementation when evidence is
  weak or Coverage is incomplete.
- The corpus is portable and contains no executable or secret-bearing payload.

### Negative

- The seed corpus is not large enough to claim production Precision or Recall.
- Fact bundles are normalized calibration inputs, not proof that a runtime
  system grants the represented capability.
- Reviewer aliases and dispositions require later human adjudication.
- P2-CAL-02 still needs a deterministic evaluation Runner and confusion-matrix
  report.
