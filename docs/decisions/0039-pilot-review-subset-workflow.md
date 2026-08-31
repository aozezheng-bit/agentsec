# ADR-0039: Demo-first Pilot Review Subset Workflow

- Status: Accepted for Pilot Review tooling
- Date: 2026-08-24
- Scope: P2-CAL-04A Pilot Review only

## Context

The expanded Reviewer Pack contains 431 Rule questions per Reviewer. A full
independent review is required for formal P2-CAL-04 evidence, but it is too
large for the first Chinese Capability Drift Demo and rule-usability check.
The project needs an incremental workflow while preserving Ground Truth
Isolation and preventing partial labels from being mistaken for Hard Gate
qualification.

## Decision

Keep the formal 431-question Reviewer Pack unchanged and add a separate
Demo-first 100-question Pilot Selection. The Pilot workflow provides:

```text
selection.json / selection.csv
Reviewer A/B Pilot label templates
validate: binding and row-shape checks
report: human-label progress only
compare: two-Reviewer field-agreement report without raw label values
adjudication-template: disagreement-only human worksheet
merge: non-clobbering 431-row progress snapshot
```

Pilot tooling may read the closed Reviewer Pack's opaque Case materials and
immutable binding rows, but it does not read Corpus Ground Truth. It does not
produce `AdjudicationReviewSet`, `ConfidenceReviewSet`,
`AdjudicationResolutionSet`, TP/FP/FN/TN, Precision/Recall, Hard Gate status, or
CI decisions. The full formal importer continues to require all 431 questions.

Pilot Comparison does not calculate Kappa, Precision, Recall, or TP/FP/FN/TN.
The Adjudication Template contains no final decision and must be completed by a
human Adjudicator if the Pilot is later used for workflow testing.

Pilot labels remain `reviewed` only when a real human has explicitly completed
the row. Pending rows remain pending. The merge operation always writes a new
0600 file and never overwrites a full template or existing output.

## Selection policy

The checked-in Pilot contains:

```text
44 CAP-CHAIN-001 Demo Track questions:
  20 Positive, 20 eligible Negative/Near-miss, 4 Unknown boundaries
2 questions for each of the other 28 Rule IDs
100 questions total
```

The selection is opaque to the Reviewer: expected outcomes, Case kinds,
Unknown dimensions, Gate status, and Ground Truth are not serialized in the
reviewer-facing selection.

## Alternatives rejected

1. **Allow the formal importer to accept arbitrary partial input.** Rejected:
   it would blur Pilot progress with formal human evidence and weaken the
   complete-set contract used by P2-CAL-04.
2. **Copy Pilot labels into the formal 431-row artifact.** Rejected:
   pending rows and incomplete Confidence/Adjudication evidence would be easy
   to misinterpret as production calibration.
3. **Wait for all 431 rows before testing the Demo workflow.** Rejected:
   it delays rule-language and evidence-usability feedback unnecessarily.

## Consequences

Positive:

- a human can start with a bounded workload;
- the Demo rule receives meaningful Positive, Negative/Near-miss, and Unknown
  coverage;
- progress can be validated, summarized, and merged without destructive writes;
- the formal Reviewer Pack and P2-CAL-04 contracts remain stable.

Limitations:

- Pilot results are not sufficient for P2-15A;
- the current formal importer still requires the full 431-question set;
- a future explicitly approved subset-import contract would need its own schema,
  evidence-mode semantics, and ADR update.
