# P2-EXIT-06: External Real-project Report-only Pilot

- Status: `Complete; independently reviewed external Pilot accepted`
- Date: 2026-08-25
- Depends on: P2-EXIT-02 Trusted CI Control Plane
- ADR: `docs/decisions/0067-external-pilot-evidence-contract.md`
- Evidence mode: `external_repository`
- Authority: report-only; this Pilot cannot authorize CI blocking

## Delivered in this slice

```text
src/agentsec/pilot.py
  - explicit external target root and protected trust root
  - separate root containment and non-symlink checks
  - Policy SHA-256 pin passthrough to the trusted CI wrapper
  - 20-scan / 10-pull-request / three-drill scope contract
  - scan-kind and drill metadata
  - independent human-label contract and safe loader
  - evidence-pending state until scope and labels are complete
  - value-minimized scope and human-evidence provenance in reports

scripts/run-pilot.py
  - --target-root
  - --trust-root
  - --expect-policy-sha256
  - --human-labels
  - --allow-evidence-pending

schemas/pilot/
  - pilot-plan.schema.json regenerated
  - pilot-report.schema.json regenerated
  - pilot-human-labels.schema.json added

pilots/external-repository-template/
  - pilot.yaml
  - human-labels.example.json
  - README.md

docs/pilots/external-repository-template/acceptance.md
```

## Security contract

1. The Pilot plan, human labels, and output directory are controlled by the
   AgentSec side; the scanned project is never allowed to define trust inputs.
2. External `project_root` values resolve only below the explicit
   `--target-root`.
3. External `policy_path` values resolve only below the separate explicit
   `--trust-root`.
4. The target and trust roots must be existing, non-symlink, different
   directories.
5. A protected Policy digest can be supplied with `--expect-policy-sha256` and
   is verified by the existing trusted CI wrapper before a decision is used.
6. The runner executes only the AgentSec-controlled `scripts/run-agentsec-ci.sh`;
   it does not execute target scripts, hooks, skills, commands, or MCP servers.
7. Missing independent labels or incomplete scope produces
   `status=evidence_pending`, never a false claim of external acceptance.
8. Findings, severity, Waivers, authorization, and CI blocking remain
   deterministic and outside the human-label loader.

## Scope contract

An external plan must declare and provide:

- at least 20 scan states;
- at least 10 states with `scan_kind: pull_request`;
- one `risky_change` drill;
- one `incomplete_coverage` drill;
- one `waiver_lifecycle` drill;
- a separate independent Reviewer label file covering every case.

The human label file contains only expected exit, Coverage, and deterministic
Rule IDs. It does not store source excerpts, secrets, URLs, or runtime exploit
claims.

## Run modes

### Report-only collection before labels

```bash
PYTHONPATH=src .venv/bin/python scripts/run-pilot.py \
  --plan pilots/external-repository-template/pilot.yaml \
  --target-root /absolute/path/to/external-agent-repo \
  --trust-root /absolute/path/to/protected-policy-root \
  --expect-policy-sha256 SHA256_OF_PROTECTED_POLICY \
  --output-dir /absolute/path/to/external-pilot-results \
  --allow-evidence-pending
```

### Reviewed acceptance run

```bash
PYTHONPATH=src .venv/bin/python scripts/run-pilot.py \
  --plan pilots/external-repository-template/pilot.yaml \
  --target-root /absolute/path/to/external-agent-repo \
  --trust-root /absolute/path/to/protected-policy-root \
  --expect-policy-sha256 SHA256_OF_PROTECTED_POLICY \
  --human-labels pilots/external-repository-template/human-labels.json \
  --output-dir pilots/external-repository-template/results
```

The second command is eligible for acceptance only when its report is
`status=complete` and `metrics.acceptance_ready=true`.

## Remaining evidence work

P2-EXIT-06-02 completed one report-only baseline on 2026-08-26 using the
user-supplied Homi workspace export. The durable evidence is under
`pilots/external-homi-demo/`; see
`docs/tasks/P2-EXIT-06-02-external-homi-baseline-evidence.md`.

P2-EXIT-06-03 completed ten deterministic PR/change snapshots on 2026-08-26.
Every expected drift contract passed; the evidence is under
`pilots/external-homi-demo/pr-change-evidence/`. P2-EXIT-06-03A then corrected
the Heartbeat template classification and regenerated the evidence: PR-03 now
adds `HOMI-COMB-002`, and no scenario remains calibration-required.

P2-EXIT-06-04 completed the full 20-State machine scope on 2026-08-26. The
canonical report records 10 Baseline states, 10 PR states, all required Drills,
20/20 passing engineering contracts, complete performance data, and a passed
active/expired Waiver lifecycle exercise.

P2-EXIT-06-05 completed the blinded Reviewer Pack, review-submission Schema,
strict Human Label import, final acceptance replay, and P2-EXIT-08A handoff
automation. An automation-only smoke fixture verified that matching complete
labels reach `ready_for_candidate`; the fixture was deleted and is not human
evidence.

## Final accepted result

The independent submission was imported and validated on 2026-08-26. The first
reviewed Replay exposed four false negatives in `baseline-01`; Human Labels were
preserved and Rule Pack `0.3.1` calibrated those bounded declarations under
P2-EXIT-06-05A.

```text
Cases                 20/20 passed
TP                    25
FP                    0
FN                    0
Precision             1.0
Recall                1.0
Scope complete        true
Human labels complete true
Acceptance ready      true
```

Canonical final evidence:

```text
pilots/external-homi-demo/final-pilot/final-results/
```

