# ADR-0048: Capability Shadow Gate

- Status: Accepted for source development; Shadow-only
- Date: 2026-08-24
- Task: `P2-15A-PILOT-02`
- Depends on: ADR-0029, ADR-0030, ADR-0037, ADR-0038, ADR-0039
- Gate version: `CAPABILITY_SHADOW_GATE_VERSION = 0.1.0`
- Capability Assessment Output: `0.2.0`
- Capability Risk Model: unchanged at `0.1.0`
- Enforcement: disabled

## Context

AgentSec needs to validate the technical path for a future report-only Capability
Hard Gate while formal independent human review is still pending. A normal
Finding is not sufficient to prove that a candidate Gate can preserve target
correlation, Coverage, Unknown handling, bilingual reporting, and the
non-enforcement boundary.

The first candidate is `HG-CAPCHAIN-001`, based on the deterministic
`CAP-CHAIN-001` Finding:

```text
execute + secret-access + external network
```

The candidate must not become a production authorization or CI decision merely
because the technical evaluator exists.

## Decision

1. Add a deterministic `CapabilityShadowGateEngine` seam after the Capability
   Rule runner and before Text/JSON report rendering.
2. Implement only `HG-CAPCHAIN-001` in this task.
3. Permit Shadow matches only for `same_target` or `parent_child` correlation.
4. Require complete Manifest Coverage and zero relevant Unknowns.
5. Keep the Gate floor High. No Critical Shadow Gate is introduced.
6. Attach a typed `CapabilityShadowGateAssessment` to the existing Finding while
   preserving the Finding's score, Severity, Evidence Confidence, ID, and
   generic `hard_gate=false`.
7. Fix the serialized Shadow fields to:

   ```text
   mode=shadow
   qualification=pilot_only
   blocks=false
   ```

8. Version the Shadow metadata independently with
   `CAPABILITY_SHADOW_GATE_VERSION=0.1.0`. The Capability Risk Model remains
   `0.1.0` because Shadow metadata does not change risk calculation semantics.
9. Keep CLI exit behavior report-only. Shadow matches never return risk exit code
   `1`, never enable `--fail-on`, and never block CI.
10. Reject stale Gate versions, non-eligible correlations, empty related IDs,
    matched assessments with incomplete Coverage or relevant Unknowns, and
    mismatched Finding/Gate IDs at model-validation boundaries.

## Alternatives rejected

### Activate `hard_gate=true` now

Rejected. P2-CAL-04A Seed Labels and Joint Expert Evidence are not formal
independent human evidence. Technical code existence is not Gate qualification.

### Use Agent-wide or D-confidence correlations

Rejected. The static model does not establish a shared reachable target for
Agent-wide declarations. D-confidence evidence cannot match this High-floor
candidate.

### Let a Shadow match change score or CLI exit behavior

Rejected. That would silently convert a report-only diagnostic into policy
enforcement and would violate the current CI boundary.

### Call an LLM or inspect runtime state in the Gate engine

Rejected. The Gate must remain deterministic, offline, and evidence-backed. LLM
analysis and runtime verification are separate future capabilities.

## Consequences

### Positive

- The complete capability-to-Gate reporting path can be tested offline.
- Target correlation, Coverage, Unknown, version, and non-enforcement invariants
  are checked at both domain and report boundaries.
- Developers and reviewers can see a Gate match without mistaking it for a
  production authorization decision.

### Negative

- A Shadow match is not evidence of runtime reachability or exploitability.
- The current evaluator covers only one candidate Gate.
- Formal P2-15A qualification still requires independent human review and
  calibration acceptance.
- The Capability Assessment output contract must retain Shadow fields until a
  separately reviewed migration removes them.

## Verification

```text
tests/test_capability_shadow_gate.py
  - positive same-target match
  - Agent-wide, Unknown, and incomplete-Coverage rejection
  - stale version, invalid correlation, empty related IDs rejection
  - Finding/Gate binding and non-blocking contract
  - English/Chinese Text and JSON serialization

tests/test_capability_assessment_reporting.py
  - external Shadow contract drift rejection

scripts/check.sh
  - Ruff
  - Ruff format
  - strict Mypy
  - full Pytest
```
