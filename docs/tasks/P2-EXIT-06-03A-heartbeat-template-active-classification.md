# P2-EXIT-06-03A: Heartbeat Template / Active Task Classification Calibration

- Status: Complete
- Date: 2026-08-26
- Depends on: P2-EXIT-06-02, P2-EXIT-06-03
- ADR: `docs/decisions/0079-heartbeat-template-active-classification.md`
- Enforcement: deterministic report-only classification; no runtime action

## Objective

Correct the Homi Heartbeat false positive discovered by the real baseline and
make the concrete PR-03 activation visible as semantic drift.

## Delivered

```text
src/agentsec/frameworks/homi.py
src/agentsec/frameworks/homi_policy.py
src/agentsec/frameworks/homi_profile.py
src/agentsec/frameworks/homi_simulation.py
src/agentsec/frameworks/homi_pilot.py
src/agentsec/frameworks/__init__.py
tests/test_homi_adapter.py
tests/test_homi_profile.py
tests/test_homi_simulation.py
tests/test_homi_pilot.py
tests/test_homi_cli.py
tests/test_external_homi_baseline_evidence.py
tests/test_external_homi_pr_drift_evidence.py
```

## Classification contract

| Heartbeat content | File state | Capability | Tasks | Simulation |
|---|---|---|---:|---|
| Blank or comment-only | `empty` | `absent` | false | `blocked_static_boundary` |
| Fenced/docs template, no real task | `example_only` | `example_only` | false | `blocked_example_only` |
| Concrete task outside scaffolding | `present` | `present` | true | evaluated against external capability |
| Missing/skipped | `missing/skipped` | `unknown` | false | `unknown_coverage` |

Template recognition requires at least two reviewed markers and no actionable
outside line. Appending a real task always changes the result to `present`.

## Version changes

```text
HOMI_ADAPTER_VERSION                 0.2.0
HOMI_PROFILE_MODEL_VERSION           0.2.0
HOMI_PILOT_FORMAT_VERSION            0.2.0
HOMI_SAFE_SIMULATION_MODEL_VERSION   0.2.0
HOMI_COMBINATION_RULE_PACK_VERSION   0.1.0 (unchanged)
```

Homi Pilot `0.2.0` now records:

```json
{
  "adapter_version": "0.2.0",
  "profile_model_version": "0.2.0"
}
```

## Baseline result after calibration

```text
HEARTBEAT.md file state            example_only
heartbeat_schedule                 example_only
tasks_present                      false
api_calls_enabled_by_file          false
HOMI-COMB-002                      not emitted
HOMI-SIM-001                       blocked_example_only
Combination Finding count          3
```

Remaining baseline Findings:

```text
HOMI-COMB-001 proactive + external capability
HOMI-COMB-003 user profile + persistent memory
HOMI-COMB-004 persona/identity self-modification
```

## PR-03 result after calibration

```text
heartbeat_schedule   example_only → present
HOMI-COMB-002        added
HOMI-SIM-001         blocked_example_only → declared_path
review_outcome       contract_pass
```

The aggregate now reports:

```text
scenario contracts             10/10 pass
calibration-required scenarios 0
```

## Evidence preservation and regeneration

Pre-calibration evidence is preserved at:

```text
pilots/external-homi-demo/review-history/pre-heartbeat-calibration-20260826/
```

Canonical evidence was regenerated at:

```text
pilots/external-homi-demo/results/baseline-01/
pilots/external-homi-demo/evidence/
pilots/external-homi-demo/pr-change-evidence/
```

The original source ZIP is unchanged.

## Security assertions

```text
scanned content executed       false
scheduler invoked              false
network/email/calendar called  false
runtime tools invoked          false
target modified                false
CI blocked                     false
runtime verified               false
```

## Acceptance requirements

```text
comment-only remains absent
fenced documentation becomes example_only
real task appended becomes present
policy distinguishes template disabled / activation path
combination Rule does not fire for template
simulation blocks template as example-only
real PR activation produces Finding Drift
API/CLI regenerated evidence is deterministic
old evidence remains preserved
Ruff / format / strict Mypy / full Pytest / reproducible build pass
```

## Completion verification record

Executed on 2026-08-26:

| Verification | Result |
|---|---|
| Homi + evidence focused regression | 71 passed |
| Full Pytest | 1289 passed |
| Ruff | Pass |
| Ruff format | Pass; 320 files |
| Strict Mypy | Pass; 291 source files |
| Package hardening | Pass |
| Fixed-epoch reproducible build | Pass; Wheel/sdist byte-identical |
| Baseline API/CLI replay | Byte-for-byte identical |
| PR-07 API/CLI replay | Byte-for-byte identical |
| Regenerated scenario contracts | 10/10 pass |
| Calibration-required scenarios | 0 |
| Runtime execution / side effects / CI blocks | 0 / 0 / 0 |

Exact sdist hashes are not embedded because this task record and regenerated
evidence are included in the source distribution. Artifact signatures and SLSA
provenance remain `not_claimed`.
