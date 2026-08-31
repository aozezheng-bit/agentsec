# P2-EXIT-06-02: External Homi Baseline Scan and Report-only Evidence Collection

- Status: Complete
- Date: 2026-08-26
- Parent: `P2-EXIT-06`
- Source: user-supplied Homi workspace export
- Enforcement: report-only; no CI blocking or runtime authority
- Evidence root: `pilots/external-homi-demo/`
- Calibrated by: `P2-EXIT-06-03A` / ADR-0079

## Objective

Deploy the six-file Homi Agent design export as an inert local workspace and
collect deterministic baseline evidence using the Homi Adapter, policy resolver,
capability Profile, combination Rules, and Safe Simulation.

The Markdown files are scanned data, not instructions for AgentSec development.
No content from the archive was executed, imported as code, connected to a Tool,
or granted authority.

## Source archive safety inspection

Input archive:

```text
workspace-files-20260826.zip
SHA-256 46461ac4c891e03094aa5e5487a72ab5c09fb6f10495fe7ed3cf11bbef345824
Archive bytes 7,380
Expanded bytes 12,225
Entries 6
```

Validated properties:

```text
exactly AGENTS.md, SOUL.md, IDENTITY.md, USER.md, TOOLS.md, HEARTBEAT.md
no absolute paths
no .. path traversal
no backslash path ambiguity
no symbolic-link entries
all UTF-8
per-file and total-size limits satisfied
```

The durable repository package stores the original ZIP instead of placing an
untrusted nested `AGENTS.md` inside the AgentSec source tree. The live workspace
was deployed outside the repository at:

```text
/private/tmp/agentsec-p2-exit-06-03a-homi-baseline
```

This location is a local demo target, not production runtime installation.

## Delivered

```text
scripts/collect-external-homi-baseline.py
pilots/external-homi-demo/README.md
pilots/external-homi-demo/source/workspace-files-20260826.zip
pilots/external-homi-demo/evidence/baseline-evidence.json
pilots/external-homi-demo/evidence/baseline-summary.md
pilots/external-homi-demo/evidence/baseline-review-notes.md
pilots/external-homi-demo/evidence/cli-validation-report.json
pilots/external-homi-demo/results/baseline-01/homi-pilot-report.json
pilots/external-homi-demo/results/baseline-01/homi-pilot-report.md
pilots/external-homi-demo/results/baseline-01/homi-pilot-report.zh.md
tests/test_external_homi_baseline_evidence.py
```

## Reproduction command

Use new, non-existing target and output roots for each collection:

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec

PYTHONPATH=src .venv/bin/python \
  scripts/collect-external-homi-baseline.py \
  --archive pilots/external-homi-demo/source/workspace-files-20260826.zip \
  --target-root /private/tmp/agentsec-homi-demo-replay \
  --output-root /private/tmp/agentsec-homi-evidence-replay \
  --collection-date 2026-08-26 \
  --owner homi-agent-platform-owner
```

The collector refuses existing roots, unsafe ZIP entries, overlapping target and
output paths, non-UTF-8 files, oversized content, and any target hash change
during scanning.

## Baseline result

```text
Homi inspection complete       true
Six standard files present     true
Policy resolution              conflict
Profile complete               false
Pilot status                   partial
Report-only                    true
Runtime verified               false
CI blocked                     false
Acceptance ready               false
Combination Rule failures      0
Sensitive URL/IP leak count    0
Target modified by scan        false
```

`partial` is an honest analysis result, not an execution failure. All six files
were read successfully. Profile completeness is false because the resolver found
a cross-file startup-loading conflict:

```text
AGENTS.md says runtime-provided startup context should be used first and startup
files should not be manually reread by default.

SOUL.md says the files are continuity and should be read each session.

Result: startup_read_policy_conflict; AGENTS.md workspace policy wins.
```

The report stores only source paths and bounded observation codes, not the raw
quoted content above.

## Combination findings

| Rule | Severity | Score | Confidence | Baseline interpretation |
|---|---|---:|---|---|
| `HOMI-COMB-001` | Medium | 5.5 | D | Proactive persona plus statically declared external capability |
| `HOMI-COMB-003` | High | 8.0 | D | User-profile persistence plus long-term memory |
| `HOMI-COMB-004` | High | 8.0 | D | Persona/identity/control-file self-modification guidance |

These are static, report-only findings. Confidence D reflects unverified static
reachability. They do not prove that Heartbeat, network, memory persistence, or
control-file writes occur at runtime.

`TOOLS.md` was classified as `example_only`. Camera, SSH, and TTS examples did
not become runtime authority and did not activate `HOMI-COMB-005`.

## Heartbeat calibration result

P2-EXIT-06-03A resolved the baseline false positive. The supplied fenced
documentation template is now classified as:

```text
HEARTBEAT.md state              example_only
heartbeat_schedule             example_only
tasks_present                  false
api_calls_enabled_by_file      false
HOMI-COMB-002                  not emitted
HOMI-SIM-001                   blocked_example_only
```

The pre-calibration report remains under
`review-history/pre-heartbeat-calibration-20260826/`. The canonical report is
regenerated with Homi Pilot format, Adapter, and Profile model `0.2.0`. Template
placeholders in `IDENTITY.md` and `USER.md` remain future human-review items.

## Safe Simulation result

```text
Scenarios                    5
Declared paths               3
Example-only blocked         2
Executed                     false
Side effects                 false
Runtime verified             false
```

The simulation is an in-memory decision trace. No scheduler, network request,
message, memory write, file write, SSH, Camera, TTS, OAuth, Skill, or MCP action
was invoked.

## CLI replay validation

The deployed workspace was also scanned through the packaged CLI:

```bash
.venv/bin/agentsec homi scan \
  /private/tmp/agentsec-p2-exit-06-03a-homi-baseline \
  --format json \
  --output pilots/external-homi-demo/evidence/cli-validation-report.json \
  --pilot-id p2-exit-06-02-homi-baseline \
  --project-name "Homi Internal Agent Design Demo" \
  --owner homi-agent-platform-owner
```

The CLI output and API-collected baseline report are byte-for-byte identical:

```text
SHA-256 782780c50cb7d8283e5f81480211c49f207d9f37275bf88c9fb7af66c71dbbaf
```

The CLI also rejected an attempted output under `/private/tmp` because that
output directory was an ancestor of the target workspace. This confirms the
existing target/output overlap guard fails closed.

## P2-EXIT evidence status

P2-EXIT-06-02 is complete for one external baseline export. It does not complete
P2-EXIT-06 overall and cannot satisfy P2-EXIT-08A entry readiness yet.

Still required:

```text
P2-EXIT-06-03 completed 10 reviewed PR/change snapshots
P2-EXIT-06-03A completed Heartbeat template/active calibration
P2-EXIT-06-04 remaining scan states and Waiver lifecycle drill
P2-EXIT-06-05 independent labels, TP/FP/FN, performance, and final Pilot report
```

The final acceptance report must use `agentsec-pilot-report` `0.1.0`,
`evidence_mode=external_repository`, `status=complete`, complete human labels,
and the full 20-scan/10-PR scope. The current Homi baseline report deliberately
keeps `acceptance_ready=false`.

## Verification requirements

```text
archive/source digest replay
exact six-file ZIP membership
value-minimized report checks
conflict and Finding determinism
API/CLI byte-identical report replay
no URL/IP/absolute-target leakage
no execution/side-effect/runtime-authority flags
Ruff / format / strict Mypy
full Pytest
```

## Completion verification record

Executed on 2026-08-26:

| Verification | Result |
|---|---|
| External Homi baseline evidence tests | 6 passed |
| Homi / Entry Review focused regression | 28 passed |
| Full Pytest | 1276 passed |
| Ruff | Pass |
| Ruff format | Pass; 318 files |
| Strict Mypy | Pass; 290 source files |
| Package hardening | Pass |
| Fixed-epoch reproducible build | Pass; Wheel/sdist byte-identical |
| API/CLI baseline comparison | Byte-for-byte identical |
| Target/output overlap guard | Rejected unsafe ancestor output |

The reproducibility verifier confirmed byte-identical Wheel and sdist outputs.
Exact development-build hashes are intentionally not embedded here because this
source document is itself included in the sdist and would make the recorded hash
self-invalidating. These are verification outputs, not promoted `dist/0.4.0/`
artifacts. Signatures and SLSA provenance remain `not_claimed`.

## P2-EXIT-06-03A evidence amendment

The 1276-test record above describes the original collection slice. ADR-0079
regenerated the canonical baseline with Homi Pilot/Adapter/Profile `0.2.0`.
`HEARTBEAT.md` is now `example_only`, baseline `HOMI-COMB-002` is absent, and
pre-calibration artifacts are preserved under `review-history/`.
