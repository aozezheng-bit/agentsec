# P2-EXIT-06-04: Remaining Scan States and Drill Closure

- Status: Complete
- Date: 2026-08-26
- Parent: P2-EXIT-06
- Depends on: P2-EXIT-06-02, P2-EXIT-06-03, P2-EXIT-06-03A
- ADR: `docs/decisions/0080-final-external-homi-pilot-and-blinded-review.md`

## Delivered

```text
src/agentsec/external_pilot.py
scripts/collect-external-homi-final-pilot.py
pilots/external-homi-demo/final-pilot/
tests/test_external_homi_final_pilot.py
schemas/pilot/external-pilot-review-submission.schema.json
```

The collector builds deterministic six-file Homi state ZIPs, deploys them to an
explicit external target root, copies one protected Policy to a separate trust
root, verifies its SHA-256 pin, runs the existing AgentSec CI wrapper, checks
that the target remains unchanged, and emits value-minimized evidence.

## Final machine scope

```text
States                         20
Baseline states                10
Pull-request states            10
Engineering contracts          20/20 pass
Risky-change drill             pass
Incomplete-Coverage drill      pass
Waiver lifecycle drill         pass
Scope complete                 true
Independent human labels       false
Acceptance ready               false
```

Canonical evidence:

```text
pilots/external-homi-demo/final-pilot/results/pilot-report.json
pilots/external-homi-demo/final-pilot/results/pilot-report.md
pilots/external-homi-demo/final-pilot/evidence/collection-evidence.json
pilots/external-homi-demo/final-pilot/evidence/waiver-drill-evidence.json
```

## Waiver drill result

```text
active execution Waiver applied                 true
waived MD-EXEC-001 Finding remained visible     true
expired secret Waiver reported                  true
expired MD-SECRET-001 restored blocking         true
```

The report remains `status=evidence_pending` because engineering expectations
are not independent human labels. This is intentional and cannot be bypassed by
the collector.

## Safety

```text
scanned content executed    false
target code executed        false
Hooks/Skills/MCP invoked    false
network accessed            false
target modified             false
Policy selected by target   false
```

## Completion verification record

Executed on 2026-08-26:

| Verification | Result |
|---|---|
| Canonical external collection | 20/20 engineering contracts passed |
| Baseline / PR states | 10 / 10 |
| Required Drills | 3/3 passed |
| Focused Pilot/Homi/Entry tests | 45 passed |
| Full repository check | 1298 passed |
| Ruff | Pass |
| Ruff format | Pass; 987 files |
| Strict configured Mypy (`src`, `tests`) | Pass; 293 source files |
| Package hardening | Pass |
| Fixed-epoch reproducible build | Pass; Wheel/sdist byte-identical |

P2-EXIT-06-04 completion-time development build hashes:

```text
agentsec-0.4.0.dev0-py3-none-any.whl
9a30c3e0f0b156cdce80debd12a5fc2e0f0a4f58a8240e8f04f52f80b8bb9d6a

agentsec-0.4.0.dev0.tar.gz
e28be45c983d3d622a993f7abbaf802c734e0b2f6e7aa20a89e85e555f484495
```

Artifact signature and SLSA provenance remain `not_claimed`.
