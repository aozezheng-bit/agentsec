# AgentSec Pilot Report: Internal Release Agent Integration Pilot

- Pilot ID: `internal-release-agent-pilot`
- Status: **COMPLETE**
- Evidence mode: `internal_integration`
- Cases: 8/8 passed
- Decision accuracy: 100.00%
- Detection accuracy: 100.00%
- Precision: 100.00%
- Recall: 100.00%
- FP/FN: 0/0
- Performance p50/p95/max: 605/654/654 ms

| Case | Exit E/O | Coverage E/O | Rules E/O | Duration | Result |
|---|---:|---|---:|---:|---|
| active-waiver | 0/0 | complete/complete | 9/9 | 654 ms | PASS |
| expired-waiver | 1/1 | complete/complete | 9/9 | 628 ms | PASS |
| incomplete | 2/2 | incomplete/incomplete | 0/0 | 605 ms | PASS |
| near-miss | 0/0 | complete/complete | 0/0 | 590 ms | PASS |
| prompt-injection | 0/0 | complete/complete | 2/2 | 588 ms | PASS |
| remediated | 0/0 | complete/complete | 0/0 | 582 ms | PASS |
| risky-block | 1/1 | complete/complete | 9/9 | 567 ms | PASS |
| safe-baseline | 0/0 | complete/complete | 0/0 | 634 ms | PASS |

## Limitations

- This checked-in run is an internal integration pilot, not remote production repository evidence.
- False-positive and false-negative metrics use reviewed scenario-level unique Rule IDs, not runtime exploit labels.
- Performance is local wall-clock integration latency and varies by host and filesystem cache.
- Static findings do not prove runtime Tool, OAuth, identity, permission, or exploit reachability.
