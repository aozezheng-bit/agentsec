# P2-EXIT-06-03: Reviewed Homi PR/Change Snapshots and Capability Drift Evidence

- Status: Complete for engineering scenario-contract review
- Date: 2026-08-26
- Parent: `P2-EXIT-06`
- Depends on: `P2-EXIT-06-02`
- ADR: `docs/decisions/0078-external-homi-pr-drift-evidence.md`
- Calibrated by: `P2-EXIT-06-03A` / ADR-0079
- Independent human review: Pending; deferred to P2-EXIT-06-05
- Enforcement: report-only; no CI blocking, release, waiver, or runtime authority
- Evidence root: `pilots/external-homi-demo/pr-change-evidence/`

## Objective

Create ten inert PR/change snapshots derived from the user-supplied Homi
baseline, scan each snapshot with the deterministic Homi pipeline, compare it to
the pinned baseline report, and produce capability, policy, Finding, and Safe
Simulation drift evidence.

“Reviewed” in P2-EXIT-06-03 means every scenario has a controlled engineering
expectation contract and the generated drift must equal that contract exactly.
It does not mean independent human TP/FP/FN adjudication. That distinction is
preserved in every artifact.

## Delivered

```text
scripts/collect-external-homi-pr-drift.py
pilots/external-homi-demo/pr-change-plan.json
pilots/external-homi-demo/pr-change-evidence/README.md
pilots/external-homi-demo/pr-change-evidence/snapshots/*.zip              (10)
pilots/external-homi-demo/pr-change-evidence/results/*/homi-pilot-report.json (10)
pilots/external-homi-demo/pr-change-evidence/results/*/homi-pilot-report.md   (10)
pilots/external-homi-demo/pr-change-evidence/results/*/homi-pilot-report.zh.md (10)
pilots/external-homi-demo/pr-change-evidence/drift/*.json                 (10)
pilots/external-homi-demo/pr-change-evidence/drift/*.md                   (10)
pilots/external-homi-demo/pr-change-evidence/evidence/pr-change-evidence.json
pilots/external-homi-demo/pr-change-evidence/evidence/pr-change-summary.md
pilots/external-homi-demo/pr-change-evidence/evidence/pr-07-cli-validation-report.json
tests/test_external_homi_pr_drift_evidence.py
```

The durable snapshots are ZIP files. Actual `AGENTS.md` files are deployed only
under `/private/tmp`, outside the AgentSec source instruction hierarchy:

```text
/private/tmp/agentsec-p2-exit-06-03-homi-pr-demo
```

## Evidence formats

Per-PR drift:

```text
format          agentsec-homi-capability-drift-evidence
format_version  0.1.0
```

Aggregate:

```text
format          agentsec-external-homi-pr-change-evidence
format_version  0.1.0
acceptance_ready false
```

Each drift artifact contains:

```text
baseline/report/snapshot SHA-256 provenance
file additions/modifications/removals
capability state transitions
persona signal transitions
policy observation additions/removals
Finding additions/removals/evidence changes
Safe Simulation outcome transitions
expected scenario contract
actual deterministic result
contract_pass
report-only/runtime/CI authority flags
```

## Scenario matrix

| Scenario | Direction | Main expected result | Engineering review |
|---|---|---|---|
| `pr-01-heartbeat-template-disabled` | Hardening | Heartbeat example-only→absent; simulation boundary changes | Pass |
| `pr-02-startup-policy-alignment` | Governance hardening | Conflict→resolved; Profile becomes complete | Pass |
| `pr-03-real-heartbeat-activation` | Risk increase | Heartbeat example-only→present; add `HOMI-COMB-002` | Pass |
| `pr-04-remove-external-actions` | Hardening | Network/message→unknown; remove `HOMI-COMB-001` | Pass |
| `pr-05-remove-external-approval-boundary` | Governance risk | Persona external approval present→unknown | Pass |
| `pr-06-activate-ssh-binding` | Risk increase | SSH/TTS become conditional; add `HOMI-COMB-005` | Pass |
| `pr-07-activate-mcp-oauth-secret` | Risk increase | MCP/OAuth/Secret become conditional; add `HOMI-COMB-005` | Pass |
| `pr-08-disable-persistent-memory` | Hardening | Persistent memory and user persistence→unknown; remove `HOMI-COMB-003` | Pass |
| `pr-09-disable-self-modification` | Hardening | Persona/identity self-modification→unknown; remove `HOMI-COMB-004` | Pass |
| `pr-10-tools-coverage-missing` | Coverage degradation | `TOOLS.md` missing; example Tool signals→unknown | Pass |

Aggregate metrics:

```text
PR snapshots                         10
Scenario contract passes             10
Calibration-required scenarios        0
Risky-change drill snapshots           2
Incomplete-Coverage drill snapshots    1
Waiver-lifecycle drill snapshots        0
Runtime executions                     0
Side effects                           0
CI blocks                              0
```

## Heartbeat calibration closure

P2-EXIT-06-03A corrected the baseline template classification and regenerated
all evidence. PR-03 now produces the intended semantic drift:

```text
before heartbeat_schedule   example_only
after  heartbeat_schedule   present
HOMI-COMB-002               added
HOMI-SIM-001                blocked_example_only → declared_path
review_outcome              contract_pass
```

The aggregate now has zero calibration-required scenarios. Pre-calibration
artifacts are preserved under
`review-history/pre-heartbeat-calibration-20260826/`.

## Risk-increasing evidence

### PR-06 SSH binding

```text
ssh_access          example_only → conditional
tts_output          example_only → conditional
HOMI-COMB-005       added
HOMI-SIM-005        blocked_example_only → declared_path
```

### PR-07 MCP/OAuth/Secret binding

```text
mcp_access          unknown → conditional
oauth_access        unknown → conditional
secret_access       unknown → conditional
HOMI-COMB-005       added
HOMI-COMB-001       evidence changed
HOMI-SIM-005        blocked_example_only → declared_path
```

No endpoint, host, scope, alias, token, credential, URL, IP, or absolute target
path is copied into the report.

## Hardening evidence

The drift engine also demonstrates that security improvements are visible:

```text
PR-01 changes Heartbeat example-only to structurally absent
PR-04 removes proactive/external Finding HOMI-COMB-001
PR-08 removes user-profile/long-term-memory Finding HOMI-COMB-003
PR-09 removes persona/identity self-modification Finding HOMI-COMB-004
PR-02 changes static resolution from conflict to resolved
```

This prevents a demo from showing only risk additions; it demonstrates both risk
increase and risk reduction.

## Coverage degradation evidence

`pr-10-tools-coverage-missing` removes `TOOLS.md` and aligns the startup policy so
that the final status is genuinely Coverage-driven:

```text
resolution_status   conflict → partial
TOOLS.md             example_only → missing
camera_access        example_only → unknown
ssh_access           example_only → unknown
tts_output           example_only → unknown
HOMI-SIM-005         blocked_example_only → unknown_coverage
```

Unknown is retained rather than reported as safe.

## CLI replay

PR-07 was also scanned through the packaged CLI. API and CLI JSON reports are
byte-for-byte identical:

```text
SHA-256 86476f3519756b56ad4d1cbff2a0927ce77efb001306f5b6a31e46bacf4b982a
```

CLI evidence:

```text
pilots/external-homi-demo/pr-change-evidence/evidence/pr-07-cli-validation-report.json
```

## Reproduction

Use new, non-existing target and output roots:

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec

PYTHONPATH=src .venv/bin/python \
  scripts/collect-external-homi-pr-drift.py \
  --baseline-archive pilots/external-homi-demo/source/workspace-files-20260826.zip \
  --baseline-report pilots/external-homi-demo/results/baseline-01/homi-pilot-report.json \
  --plan pilots/external-homi-demo/pr-change-plan.json \
  --target-root /private/tmp/agentsec-homi-pr-replay \
  --output-root /private/tmp/agentsec-homi-pr-evidence-replay \
  --collection-date 2026-08-26 \
  --owner homi-agent-platform-owner
```

The collector fails closed for existing/overlapping roots, malformed plans,
unsafe baseline ZIPs, scenario contract mismatch, target mutation, authority
flag drift, absolute path leakage, or sensitive binding-value leakage.

## P2-EXIT status

P2-EXIT-06-03 is complete for deterministic engineering-reviewed PR/change
evidence. Together with P2-EXIT-06-02, the project now has:

```text
1 original Homi baseline
10 PR/change snapshots
10 PR Homi reports
10 capability drift reports
2 risky-change snapshots
1 incomplete-Coverage snapshot
```

This still does not satisfy final external acceptance. Remaining work:

```text
at least 9 additional reviewed scan states to reach 20 total
Waiver lifecycle drill
independent human labels
TP/FP/FN adjudication
performance acceptance
final agentsec-pilot-report with status=complete
```

The current evidence cannot make P2-EXIT-08A ready for candidate promotion.

## Completion verification record

Executed on 2026-08-26:

| Verification | Result |
|---|---|
| PR drift evidence tests | 7 passed |
| PR drift + Phase 3 fail-closed focused tests | 19 passed |
| Full Pytest | 1284 passed |
| Ruff | Pass |
| Ruff format | Pass; 320 files |
| Strict Mypy | Pass; 291 source files |
| Package hardening | Pass |
| Fixed-epoch reproducible build | Pass; Wheel/sdist byte-identical |
| PR-07 API/CLI replay | Byte-for-byte identical |
| Scenario contracts | 10/10 pass |
| Target mutation / runtime execution / side effects | 0 |

Exact development sdist hashes are not embedded because this task record and the
frozen evidence are included in the source distribution. Signatures and SLSA
provenance remain explicitly `not_claimed`.

## P2-EXIT-06-03A evidence amendment

The 1284-test record above describes the pre-calibration PR evidence. ADR-0079
regenerated all ten canonical snapshots/reports/drifts. PR-03 now produces
`example_only→present`, adds `HOMI-COMB-002`, and changes `HOMI-SIM-001` to
`declared_path`; all 10 contracts pass with zero calibration-required scenarios.


## Final external Pilot resolution

The remaining scope listed above was completed by P2-EXIT-06-04, P2-EXIT-06-05,
and P2-EXIT-06-05A. The accepted final report has 20/20 passing Cases, complete
independent Human Evidence, FP=0, FN=0, and `ready_for_candidate` Entry status.
