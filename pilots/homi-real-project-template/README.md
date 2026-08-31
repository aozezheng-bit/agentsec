# Homi Real-project Report-only Pilot Template

This directory is a usage template for P2-HOMI-06. It does not contain a target
Homi workspace and does not claim external evidence has been collected.

## Run from Python

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
print(report.status.value)
```

The output directory must be separate from and outside the target workspace.
The Pilot writes only:

```text
homi-pilot-report.json
homi-pilot-report.md
```

## Review checklist

1. Confirm the target root is the intended Homi workspace.
2. Confirm the output directory is controlled and not inside the target.
3. Review missing/skipped standard files and Unknown states.
4. Review P2-HOMI-04 combination Findings.
5. Review P2-HOMI-05 simulation outcomes.
6. Confirm that `report_only=true`, `runtime_verified=false`, and
   `ci_blocked=false` remain unchanged.
7. Do not interpret `declared_path` as proof that a runtime action occurred.

P2-HOMI-06 is implementation-complete but remains external-evidence-pending
until a real workspace and an independent review are supplied.
