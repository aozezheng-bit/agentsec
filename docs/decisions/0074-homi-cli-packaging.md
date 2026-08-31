# ADR-0074: Homi CLI Packaging

- Status: Accepted for P2-HOMI-07
- Date: 2026-08-25
- Depends on: ADR-0073 Homi Real-project Report-only Pilot
- Scope: CLI delivery; not runtime execution or enforcement

## Context

P2-HOMI-06 provides a Python API for running a real-project Homi report-only
Pilot. Developers and reviewers need a stable command surface that can emit a
single report, paired artifacts, or Safe Simulation output without importing or
running Homi itself.

The existing AgentSec CLI already has explicit output and exit-code conventions.
The Homi commands must follow those conventions while preserving the external
workspace and output-root separation contract.

## Decision

Register a dedicated lazy `homi` command group:

```text
agentsec homi scan <workspace>
agentsec homi report <workspace>
agentsec homi simulate <workspace>
```

`scan` emits a complete Homi Pilot report in Text/JSON. `report` writes paired
JSON/Markdown artifacts. `simulate` emits only the Safe Simulation result.

The CLI accepts only typed, bounded scenario IDs and explicit file/directory
paths. It does not accept command strings, URLs, tool clients, callbacks, or
execution modes.

## Exit behavior

```text
complete static scan       exit 0
partial static coverage    exit 2
invalid configuration      exit 3
artifact output failure    exit 4
required analysis failure  exit 5
```

Combination Findings and simulation paths remain report-only; a risk Finding
cannot make the Homi CLI block CI.

## Output safety

- Target root must be a real directory and must not be a symlink.
- Output path/directory must resolve outside the target root.
- Output parents may be created only after the separation check.
- Existing artifacts require `--force` for replacement.
- Writes use a temporary file and atomic replacement; the target workspace is
  never a write destination.
- Report values are value-minimized and exclude source content and secrets.

## Import boundary

Homi Combination, Safe Simulation, and Pilot exports remain lazily loaded from
`agentsec.frameworks`. This avoids introducing a risk/manifests import cycle in
existing Calibration, Manifest, and CLI startup paths.

## Consequences

Positive:

- the Homi pipeline is usable without a custom Python wrapper;
- JSON output is suitable for CI artifacts while default behavior remains
  report-only;
- Text/Chinese output supports developer and management demonstrations;
- partial Coverage is visible through exit 2 without turning Findings into
  enforcement.

Trade-offs:

- CLI packaging does not add real runtime verification;
- repeated snapshots and capability drift comparison remain future work;
- output files are local artifacts and are not automatically published.

## Rejected alternatives

- **Run Homi from the CLI:** violates the no-execution boundary.
- **Write reports into the workspace:** contaminates the next scan and may alter
  evidence.
- **Return non-zero for every Finding:** would turn report-only analysis into an
  implicit gate and contradict calibration/qualification policy.
- **Allow arbitrary scenario payloads:** could turn a dry-run interface into an
  execution or data-exfiltration surface.

## Follow-up

P2-EXIT-07 will harden packaging metadata, API exports, lockfiles, SBOM, and
reproducible distribution. Any future enforcement must use an independently
qualified policy path and a new decision record.
