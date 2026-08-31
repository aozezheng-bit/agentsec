# AgentSec Pilot Report: External Homi Agent Final Report-only Pilot

- Pilot ID: `external-homi-final-pilot`
- Status: **COMPLETE**
- Evidence mode: `external_repository`
- Cases: 20/20 passed
- Decision accuracy: 100.00%
- Detection accuracy: 100.00%
- Precision: 100.00%
- Recall: 100.00%
- FP/FN: 0/0
- Performance p50/p95/max: 668/692/699 ms
- Baseline/PR scans: 10/10
- Scope: READY; human labels: READY

| Case | Exit E/O | Coverage E/O | Rules E/O | Duration | Result |
|---|---:|---|---:|---:|---|
| baseline-01 | 0/0 | complete/complete | 5/5 | 681 ms | PASS |
| baseline-02 | 0/0 | complete/complete | 0/0 | 673 ms | PASS |
| baseline-03 | 0/0 | complete/complete | 0/0 | 684 ms | PASS |
| baseline-04 | 0/0 | complete/complete | 0/0 | 673 ms | PASS |
| baseline-05 | 0/0 | complete/complete | 0/0 | 660 ms | PASS |
| baseline-06 | 0/0 | complete/complete | 0/0 | 629 ms | PASS |
| baseline-07 | 0/0 | complete/complete | 2/2 | 668 ms | PASS |
| baseline-08 | 0/0 | complete/complete | 1/1 | 686 ms | PASS |
| baseline-09 | 0/0 | complete/complete | 0/0 | 692 ms | PASS |
| baseline-10 | 0/0 | complete/complete | 0/0 | 668 ms | PASS |
| pr-01 | 1/1 | complete/complete | 8/8 | 658 ms | PASS |
| pr-02 | 0/0 | complete/complete | 1/1 | 655 ms | PASS |
| pr-03 | 0/0 | complete/complete | 1/1 | 630 ms | PASS |
| pr-04 | 1/1 | complete/complete | 1/1 | 655 ms | PASS |
| pr-05 | 1/1 | complete/complete | 2/2 | 692 ms | PASS |
| pr-06 | 2/2 | incomplete/incomplete | 0/0 | 679 ms | PASS |
| pr-07 | 0/0 | complete/complete | 2/2 | 699 ms | PASS |
| pr-08 | 0/0 | complete/complete | 1/1 | 647 ms | PASS |
| pr-09 | 0/0 | complete/complete | 1/1 | 663 ms | PASS |
| pr-10 | 0/0 | complete/complete | 0/0 | 637 ms | PASS |

## Limitations

- External evidence is report-only; no CI blocking or authorization decision is enabled by this Pilot.
- The target repository is treated as untrusted input; AgentSec does not execute project code, hooks, skills, commands, or MCP servers.
- False-positive and false-negative metrics use reviewed scenario-level unique Rule IDs, not runtime exploit labels.
- Performance is local wall-clock integration latency and varies by host and filesystem cache.
- Static findings do not prove runtime Tool, OAuth, identity, permission, or exploit reachability.
