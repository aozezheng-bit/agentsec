# P2-HOMI-07: Homi CLI Packaging

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-HOMI-01～06
- ADR: `docs/decisions/0074-homi-cli-packaging.md`
- Enforcement posture: report-only; no runtime actions and no CI blocking

## Objective

Expose the Homi Adapter, Profile, Combination Rules, Safe Simulation, and
Real-project Pilot through the AgentSec CLI without changing their safety
boundaries.

## Delivered

```text
src/agentsec/cli/homi.py
src/agentsec/cli/app.py
src/agentsec/frameworks/homi_simulation.py
tests/test_homi_cli.py
```

The CLI is registered as a lazy, separate `homi` command group so existing
Manifest/Calibration imports do not acquire a new circular dependency.

## Commands

### Full report-only scan

```bash
agentsec homi scan /absolute/path/to/homi-workspace \
  --format json \
  --output /absolute/path/to/reports/homi-scan.json \
  --project-name "External Homi Project" \
  --owner security-team \
  --reviewer-id reviewer-a
```

Outputs one full Homi Pilot report. Without `--output`, the report is written to
stdout.

Supported options:

```text
--format text|json
--language en|zh
--pilot-id ID
--project-name NAME
--owner NAME
--reviewer-id ID[,ID...]
--output PATH
--force
--scenario HOMI-SIM-001,...,HOMI-SIM-005
```

### Paired JSON/Markdown reports

```bash
agentsec homi report /absolute/path/to/homi-workspace \
  --output-dir /absolute/path/to/controlled-output \
  --language zh
```

Creates:

```text
homi-pilot-report.json
homi-pilot-report.md
```

The output directory must be outside the scanned workspace. Existing artifacts
are not replaced unless `--force` is supplied.

### Safe Simulation only

```bash
agentsec homi simulate /absolute/path/to/homi-workspace \
  --scenario HOMI-SIM-001,HOMI-SIM-005 \
  --format json
```

This emits only the P2-HOMI-05 simulation output. It never executes a
Heartbeat, Skill, tool, network request, file write, or memory write.

## Exit codes

```text
0   static Homi scan completed with complete Coverage
2   static Homi scan completed but Coverage/Profile is partial
3   invalid target/output/scenario/configuration input
4   output artifact failure or no-clobber conflict
5   required Homi analysis failure
```

A detected report-only Finding does not return a risk-blocking exit code. Homi
CLI does not implement `--fail-on`, Hard Gates, CI enforcement, runtime proof, or
production authorization.

## Output invariants

Every full report and simulation output preserves:

```text
report_only=true
runtime_verified=false
ci_blocked=false
executed=false
side_effects=false
acceptance_ready=false
```

The CLI rejects:

- a target root that is a symbolic link;
- an output path or output directory inside the scanned workspace;
- a symbolic-link output path/directory;
- unknown simulation scenario IDs;
- replacing an existing report without `--force`.

The CLI creates missing output parents only after verifying that the resolved
output path is outside the target workspace.

## Security boundaries

- The scanned workspace is untrusted input.
- No source code, Markdown, command, hook, Skill, MCP server, scheduler, SSH,
  OAuth, Camera, TTS, or network action is executed.
- No raw User value, Secret, password, token, IP, URL, or Avatar bytes are copied
  into reports.
- `declared_path` and a complete static scan are not runtime attestations.
- `--force` only replaces an explicitly selected regular output artifact; it does
  not modify the scanned workspace.

## Verification

```text
.venv/bin/pytest -q tests/test_homi_adapter.py tests/test_homi_profile.py tests/test_homi_combination.py tests/test_homi_simulation.py tests/test_homi_pilot.py tests/test_homi_cli.py
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/mypy
```

P2-HOMI-07 tests cover JSON/Text output, paired artifacts, Chinese output,
scenario selection, partial Coverage exit 2, invalid scenario exit 3,
no-clobber/force behavior, output-root separation, and report-only flags.

## Next stage

```text
P2-EXIT-07 Package API / Supply-chain Hardening
P2-EXIT-08 Phase 3 Entry Review / 0.4.0 Candidate
```

## P2-EXIT-06-03A calibration amendment

CLI commands are unchanged. Full reports now use Homi Pilot format `0.2.0` and
include Adapter/Profile model provenance. A documentation-only Heartbeat is
reported as `example_only` and does not activate `HOMI-COMB-002`.
