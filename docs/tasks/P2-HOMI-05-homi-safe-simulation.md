# P2-HOMI-05: Homi Safe Simulation

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-HOMI-01, P2-HOMI-02, P2-HOMI-03, P2-HOMI-04
- ADR: `docs/decisions/0072-homi-safe-simulation.md`

## Objective

Provide a bounded, deterministic, in-memory dry-run of important Homi capability
paths. The simulator is a decision trace over the static Profile; it is not a
Homi runtime, a sandbox, an exploit test, or a proof of actual reachability.

## Delivered

```text
src/agentsec/frameworks/homi_simulation.py
src/agentsec/frameworks/__init__.py
tests/test_homi_simulation.py
docs/decisions/0072-homi-safe-simulation.md
```

Public entry point:

```python
from agentsec.frameworks import (
    DeterministicHomiSafeSimulationEngine,
    HomiSafeSimulationRequest,
)

result = DeterministicHomiSafeSimulationEngine().simulate(
    profile,
    HomiSafeSimulationRequest(),
)
```

## Scenario catalog

The fixed catalog is intentionally small and bounded:

| Scenario | Trigger | Simulated action | Meaning |
|---|---|---|---|
| `HOMI-SIM-001` | Heartbeat tick | external network read | Whether a Heartbeat declaration would describe an external-read path. |
| `HOMI-SIM-002` | proactive persona | external tool use | Whether proactive behavior would describe an active external capability path. |
| `HOMI-SIM-003` | user-profile update | memory persist | Whether user-profile persistence would enter long-term memory. |
| `HOMI-SIM-004` | control-file update | control-file write | Whether persona and identity self-modification describe a write path. |
| `HOMI-SIM-005` | Skill discovery | tool discovery | Whether Skill discovery would reach an active local tool binding. |

Callers may select a subset through `HomiSafeSimulationRequest`; arbitrary
commands, URLs, payloads, callbacks, and tool handlers are not accepted.

## Outcomes

Each step has one bounded outcome:

```text
declared_path         static Profile describes the path; no action was run
not_declared           required static capability is not present
blocked_example_only   only template/example tool notes were found
blocked_static_boundary empty Heartbeat or another static boundary disables path
unknown_coverage       missing, skipped, or Unknown evidence prevents conclusion
```

The result also preserves the IDs of P2-HOMI-04 static combination Findings and
any isolated combination-rule failures. Static Finding data and simulation steps
remain separate objects; the simulator does not reinterpret a simulation result
as a vulnerability proof.

## Safety contract

The simulator guarantees:

```text
mode = dry_run
executed = false
side_effects = false
runtime_verified = false
```

It does not:

- execute Markdown, code blocks, scripts, skills, hooks, or commands;
- call Shell, SSH, MCP, OAuth, Camera, TTS, network, or scheduler APIs;
- write files or persistent memory;
- fetch Avatar URLs;
- use user values, credentials, IP addresses, or Secret contents;
- treat `TOOLS.md` as a Runtime Tool Registry;
- authorize an action, generate a Hard Gate, or block CI;
- claim that a scheduler or tool actually ran.

## Evidence contract

Each simulated step includes only value-minimized Profile signal evidence:

- signal ID;
- bounded state;
- evidence confidence;
- evidence method;
- source locator metadata;
- rationale and limitations.

No source excerpt or raw file value is copied into the simulation result.
Example-only tool notes are carried as evidence for a suppression outcome but are
never upgraded to active access.

## Completeness and determinism

- Scenario IDs, steps, evidence, and outcome counts are ordered deterministically.
- The scenario catalog is fixed and limited to eight or fewer scenarios per
  request; the current catalog contains five.
- Profile incompleteness remains visible through `profile_complete=false` and
  `result.complete=false`.
- Safe steps can still be produced for a partial Profile, but Unknown outcomes
  are retained rather than converted to `not_declared`.
- JSON output uses the versioned format
  `agentsec-homi-safe-simulation` / `0.1.0`.

## Verification

```text
.venv/bin/pytest -q tests/test_homi_adapter.py tests/test_homi_profile.py tests/test_homi_combination.py tests/test_homi_simulation.py
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/mypy
```

P2-HOMI-05 acceptance tests cover declared paths, example suppression, empty
Heartbeat blocking, incomplete coverage, bounded scenario selection, deterministic
catalog output, no execution, no side effects, runtime-unverified output, and
Secret non-disclosure.

## Deferred work

```text
P2-HOMI-06 Homi Real-project Report-only Pilot — Complete 2026-08-25
P2-HOMI-07 Homi CLI Packaging
```

## P2-EXIT-06-03A calibration amendment

`HOMI_SAFE_SIMULATION_MODEL_VERSION=0.2.0` maps a documentation-only Heartbeat to
`blocked_example_only`. A concrete task can transition that scenario to
`declared_path`; no scheduler or external action is executed.
