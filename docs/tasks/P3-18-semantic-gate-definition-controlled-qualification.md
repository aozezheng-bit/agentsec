# P3-18：Semantic Gate Definition / Controlled Qualification

- Status: Complete
- Date: 2026-09-01
- Depends on: P3-05, P3-07, P3-10, P3-17
- Mode: report-only; no semantic or LLM authorization

## Objective

Define a versioned Semantic Gate candidate and a deterministic qualification
runner. The runner turns P3-05 Provider quality/promotion evidence, P3-07
calibration and Finding-promotion evidence, P3-10 Rule staging evidence, and
human Evidence Confidence into a transparent qualification result.

Qualification means only that the evidence satisfies the declared quality and
review thresholds. It does not mean that the Gate can block CI, publish a Rule,
approve a waiver, change severity, grant runtime authority, or authorize a
release.

All model/provider output remains **candidate evidence only**.

## Work split and deliverables

### P3-18-01：Semantic Gate Contract

Implemented in:

```text
src/agentsec/semantic/gate_definition.py
```

The contract defines:

- Gate ID, signal, description, and digest-bound Candidate identity;
- minimum total, Positive, and Eligible Negative/Near-miss sample counts;
- Precision, Recall, F1, Evidence Binding, and complete-Coverage thresholds;
- maximum unevaluated cases and minimum human reviewer count;
- Evidence Confidence grades A/B/C/D;
- explicit authority boundary.

Confidence grade A requires a Runtime Attestation marker. Static-only evidence
cannot silently claim A. Grade D cannot satisfy a complete adjudication claim.

### P3-18-02：Semantic Gate Candidate Schema

`SemanticGateCandidate` is exported as:

```text
schemas/semantic-analysis/semantic-gate-candidate.schema.json
```

The Candidate is digest-bound to its reviewed Gate definition fields. Its
immutable authority contract is:

```text
report_only=true
blocks=false
can_block_ci=false
can_publish_rule=false
can_approve_waiver=false
can_grant_runtime_authority=false
```

### P3-18-03：Qualification Runner

`SemanticGateQualificationRunner` evaluates deterministic evidence and emits:

```text
qualified
conditionally_qualified
not_qualified
```

The runner checks sample coverage, quality metrics, unevaluated cases, human
Evidence Confidence, and optional upstream evidence contracts. Missing required
evidence is `pending` and produces `conditionally_qualified`; failed quality or
integrity evidence produces `not_qualified`.

### P3-18-04：Qualification Report

`SemanticGateQualificationReport` is exported as:

```text
schemas/semantic-analysis/semantic-gate-qualification-report.schema.json
```

The report contains Gate/Candidate identity, Provider/Model identity, metrics,
per-check pass/pending/fail status, failed and pending check summaries, reasons,
Evidence Confidence, and the fixed authority boundary. It is value-minimized
and does not contain corpus text or raw model output.

### P3-18-05：P3-05 / P3-07 / P3-10 integration

The runner accepts and validates:

- P3-05 `ProviderPromotionReport`; an input required by the Candidate must be
  `approved_shadow`, Provider/Model-bound, quality-passed, human-review-passed,
  and still report-only;
- P3-07 candidate-calibration and Finding-promotion reports; required inputs
  must meet the declared quality/reviewer and authority constraints;
- P3-10 Rule-promotion/staging reports; required inputs must be eligible/staged
  without automatic publication, Rule Pack mutation, Finding, Policy, CI,
  Hard-Gate, or release authority.

These integrations only qualify evidence. They never mutate Findings, Rules,
Policies, CI state, or runtime state.

## CLI

Create a Candidate definition:

```bash
PYTHONPATH=src .venv/bin/python scripts/create-semantic-gate-candidate.py \
  --gate-id SG-INSTRUCTION-INTEGRITY-001 \
  --title "Instruction integrity" \
  --description "Detect semantic instruction integrity risks." \
  --signal instruction_integrity \
  --output calibration/semantic-gates/sg-instruction-integrity-001.json
```

Run qualification:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-semantic-gate-qualification.py \
  --candidate calibration/semantic-gates/sg-instruction-integrity-001.json \
  --quality-report <quality-report.json> \
  --provider-promotion <provider-promotion.json> \
  --evidence-confidence <confidence.json> \
  --positive-cases 20 \
  --eligible-negative-cases 20 \
  --format json \
  --output semantic-gate-qualification.json
```

A missing required Provider Promotion or Evidence Confidence input is visible as
`conditionally_qualified`; it is not silently treated as a pass.

## Authority boundary

The output is a qualification evidence artifact only:

- no CI blocking;
- no Hard Gate activation;
- no Rule publication;
- no Waiver approval;
- no severity or score override;
- no runtime proof;
- no release authorization.

A real Provider endpoint, credentials, cost approval, data residency, and data
retention decision are still organizational prerequisites for a Real Provider
Pilot. Fixture-derived metrics are wiring evidence and must not be presented as
an external quality claim.
