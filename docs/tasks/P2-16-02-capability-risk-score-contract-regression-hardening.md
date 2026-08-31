# P2-16-02 Capability Risk Score Contract Regression Hardening

- Task ID: `P2-16-02`
- Status: Complete
- Completion date: 2026-08-24
- Parent audit: `docs/tasks/P2-16-01-capability-risk-model-gap-audit.md`
- Capability Risk Model: `0.1.0` unchanged
- Enforcement: `report_only`

## 1. Objective

Add a named cross-layer regression contract for the P2-16 risk path without
introducing a second risk engine or changing any existing scoring semantics.

The regression contract is:

```text
CapabilityRuleCandidate
→ correlation-derived Likelihood
→ metadata High-Water-Mark Impact
→ NIST Matrix cell
→ NIST semi-quantitative value
→ AgentSec Base Score
→ Severity
→ Text/JSON report
→ Capability Risk Model version
```

## 2. Delivered change

Added:

```text
tests/test_p2_16_risk_score_contract.py
```

The tests use the real `CapabilityAssessmentEngine`, real Manifest analysis path,
real deterministic Capability Rule runner, and real Text/JSON reporters. They do
not use Corpus Ground Truth, Pilot labels, or Seed labels.

## 3. Contract coverage

The regression suite verifies:

```text
all materialized Capability Findings recompute their High-Water-Mark Impact
Risk level equals NIST Likelihood × Impact matrix output
NIST semi-quantitative value is distinct from AgentSec Base Score
AgentSec Base Score is derived from the matrix level
Severity is derived from the bounded Base Score
Capability Risk Model version is retained on Findings and reports
Text and JSON expose the same score semantics
Confidence remains separate from Score and Severity
Agent-wide D-confidence uses Low static Likelihood
Incomplete-Coverage D-confidence remains visible
hard_gate=false remains enforced
report_only policy remains enforced
```

The tests specifically preserve the P2-16 safety boundary:

```text
Confidence is not a score multiplier
High/Critical impact is not averaged away
D-confidence does not authorize or block
Incomplete/Unknown is not treated as safe
No runtime capability is claimed
```

## 4. Version and ADR decision

No Risk Model semantic changed. Therefore:

```text
RISK_MODEL_VERSION: 0.4.0 unchanged
CAPABILITY_RISK_MODEL_VERSION: 0.1.0 unchanged
CAPABILITY_RULE_PACK_VERSION: 0.2.0 unchanged
```

No new ADR is required for this regression-only task. A future change to the
NIST matrix, Impact aggregation, Base Score mapping, Severity thresholds,
Correlation-to-Likelihood mapping, or Confidence interaction must create a new
ADR and complete a Risk Model version-impact review before implementation.

## 5. Verification

Targeted regression:

```bash
.venv/bin/pytest -q tests/test_p2_16_risk_score_contract.py
```

Result:

```text
3 passed
```

Full repository gate:

```bash
scripts/check.sh
```

Result:

```text
Ruff: passed
Ruff format: passed
Mypy: passed
Full Pytest: 929 passed
```

## 6. Scope boundary

This task does not:

```text
add CVSS Base vector ingestion
add Agentic Factors
add Threat/Mitigation multipliers
add Drift Score
add Governance Score
add Overall Score aggregation
activate Hard Gates
implement --fail-on
enable CI blocking
read or use Pilot Review labels as formal risk evidence
```

P2-17 can now start as a separate task. It must not be combined with P2-16-02
because CVSS Base input is a new scoring adapter contract.
