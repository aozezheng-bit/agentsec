# P2-HOMI-06: Homi Real-project Report-only Pilot

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-HOMI-01～05
- ADR: `docs/decisions/0073-homi-real-project-report-only-pilot.md`
- Evidence posture: external report-only; runtime and human acceptance pending

## Objective

Provide a controlled entry point for scanning one real Homi workspace supplied by
the project owner. The Pilot connects the safe Homi layers into one flow:

```text
explicit external target root
    → Homi Adapter
    → File Policy / Precedence Resolution
    → Capability Profile
    → Cross-file Combination Rules
    → Safe Simulation
    → value-minimized JSON/Text report
```

This task delivers the Pilot contract and runner. It does not claim that an
external customer repository, runtime tool registry, scheduler, or human review
has already been supplied.

## Delivered

```text
src/agentsec/frameworks/homi_pilot.py
src/agentsec/frameworks/__init__.py
tests/test_homi_pilot.py
pilots/homi-real-project-template/README.md
docs/decisions/0073-homi-real-project-report-only-pilot.md
```

Public API:

```python
from pathlib import Path

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotRequest,
)

request = HomiPilotRequest(
    pilot_id="homi-real-project-pilot",
    project_name="External Homi Project",
    owner="security-team",
    target_root=Path("/absolute/path/to/external-homi-workspace"),
    output_root=Path("/absolute/path/to/controlled-output"),
    reviewer_ids=("reviewer-a",),
)
report = DeterministicHomiReportOnlyPilot().run_and_write(request)
```

`run_and_write()` creates only these controlled artifacts:

```text
homi-pilot-report.json
homi-pilot-report.md
```

It refuses to overwrite existing artifacts.

## Report contract

The report format is:

```text
format             agentsec-homi-report-only-pilot
format_version     0.2.0
adapter_version    0.2.0
profile_model_version 0.2.0
evidence_mode      external_report_only
report_only        true
runtime_verified   false
ci_blocked         false
acceptance_ready   false
```

The JSON report contains:

- six standard Homi file states, digests, sizes, line counts, and coverage issues;
- capability signal summaries with state, confidence, method, and relative source
  paths;
- persona, identity, user-privacy, tool-binding, and Heartbeat summaries;
- Homi file-policy resolution status and bounded observations;
- P2-HOMI-04 combination Findings and isolated rule failures;
- P2-HOMI-05 simulation steps and outcome counts;
- explicit limitations and reviewer IDs supplied by the caller.

It does not contain:

```text
absolute target paths
raw file excerpts
USER.md values
passwords / tokens / IP addresses / URLs
Avatar bytes
runtime tool output
```

## External target safety

The runner requires:

- an existing target directory;
- the target root itself must not be a symbolic link;
- a separate output root outside the target tree;
- an existing output parent directory;
- all Homi source to remain untrusted input.

The runner never executes target project code, hooks, skills, commands, MCP
servers, schedulers, or tools. It does not write to the target root.

## Honest coverage posture

`status=complete` means that the six-file static Homi inspection and policy
resolution completed without coverage issues. It does **not** mean:

- runtime access was verified;
- a scheduler was observed running;
- a tool or OAuth scope was confirmed;
- a vulnerability was exploited;
- a human reviewer accepted the result;
- CI or production enforcement is authorized.

Missing or skipped files produce `status=partial`, preserve Unknown states, and
keep `acceptance_ready=false`.

## Report-only enforcement posture

This Pilot cannot:

- block CI;
- approve or deny deployment;
- create a Hard Gate;
- authorize runtime tools;
- modify Homi files;
- publish findings externally;
- invoke LLM analysis.

P2-HOMI-04 findings and P2-HOMI-05 simulation paths are review evidence only.

## Verification

```text
.venv/bin/pytest -q tests/test_homi_adapter.py tests/test_homi_profile.py tests/test_homi_combination.py tests/test_homi_simulation.py tests/test_homi_pilot.py
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/mypy
```

P2-HOMI-06 acceptance tests cover complete and partial external workspaces,
explicit target/output separation, symlink rejection, no-clobber artifacts,
value minimization, bilingual Text output, reviewer-ID provenance, and the
report-only/non-runtime/non-CI posture.

## Remaining external evidence

A user-supplied Homi workspace export was collected as the first external
baseline on 2026-08-26. The inert source ZIP and value-minimized reports are in
`pilots/external-homi-demo/`; see P2-EXIT-06-02.

The baseline is not a customer-production or runtime acceptance claim. It has
no independent human labels, runtime attestation, remote CI evidence, or PR
drift set. Repeated PR/change snapshots and independent review remain pending.

## Next task

```text
P2-HOMI-07 Homi CLI Packaging — Complete 2026-08-25
```

## P2-EXIT-06-03A calibration amendment

Homi Pilot format `0.2.0` records `adapter_version` and
`profile_model_version`. Canonical external evidence was regenerated after the
Heartbeat template/active-task classifier fix; pre-calibration evidence remains
in `pilots/external-homi-demo/review-history/`.


## Final P2-EXIT-06 acceptance amendment

The original baseline and PR/change evidence were later expanded to the final
20-State external Pilot. A real independent Reviewer completed all Cases;
P2-EXIT-06-05A calibrated four bounded false negatives, and the final Replay
reached 20/20 with FP=0, FN=0, and `acceptance_ready=true`.

Canonical accepted evidence:

```text
pilots/external-homi-demo/final-pilot/final-results/
```
