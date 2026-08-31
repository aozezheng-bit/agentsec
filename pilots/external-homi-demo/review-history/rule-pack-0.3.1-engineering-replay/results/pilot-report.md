# AgentSec Pilot Report: External Homi Agent Final Report-only Pilot

- Pilot ID: `external-homi-final-pilot`
- Status: **EVIDENCE_PENDING**
- Evidence mode: `external_repository`
- Cases: 20/20 passed
- Decision accuracy: 100.00%
- Detection accuracy: 100.00%
- Precision: 100.00%
- Recall: 100.00%
- FP/FN: 0/0
- Performance p50/p95/max: 678/703/739 ms
- Baseline/PR scans: 10/10
- Scope: READY; human labels: PENDING

| Case | Exit E/O | Coverage E/O | Rules E/O | Duration | Result |
|---|---:|---|---:|---:|---|
| baseline-01 | 0/0 | complete/complete | 5/5 | 739 ms | PASS |
| baseline-02 | 0/0 | complete/complete | 0/0 | 703 ms | PASS |
| baseline-03 | 0/0 | complete/complete | 0/0 | 695 ms | PASS |
| baseline-04 | 0/0 | complete/complete | 0/0 | 687 ms | PASS |
| baseline-05 | 0/0 | complete/complete | 0/0 | 678 ms | PASS |
| baseline-06 | 0/0 | complete/complete | 0/0 | 645 ms | PASS |
| baseline-07 | 0/0 | complete/complete | 2/2 | 639 ms | PASS |
| baseline-08 | 0/0 | complete/complete | 1/1 | 648 ms | PASS |
| baseline-09 | 0/0 | complete/complete | 0/0 | 681 ms | PASS |
| baseline-10 | 0/0 | complete/complete | 0/0 | 690 ms | PASS |
| pr-01 | 1/1 | complete/complete | 8/8 | 684 ms | PASS |
| pr-02 | 0/0 | complete/complete | 1/1 | 646 ms | PASS |
| pr-03 | 0/0 | complete/complete | 1/1 | 659 ms | PASS |
| pr-04 | 1/1 | complete/complete | 1/1 | 627 ms | PASS |
| pr-05 | 1/1 | complete/complete | 2/2 | 635 ms | PASS |
| pr-06 | 2/2 | incomplete/incomplete | 0/0 | 658 ms | PASS |
| pr-07 | 0/0 | complete/complete | 2/2 | 698 ms | PASS |
| pr-08 | 0/0 | complete/complete | 1/1 | 690 ms | PASS |
| pr-09 | 0/0 | complete/complete | 1/1 | 642 ms | PASS |
| pr-10 | 0/0 | complete/complete | 0/0 | 657 ms | PASS |

## Limitations

- External evidence is report-only; no CI blocking or authorization decision is enabled by this Pilot.
- The target repository is treated as untrusted input; AgentSec does not execute project code, hooks, skills, commands, or MCP servers.
- Independent human TP/FP/FN labels are incomplete; acceptance remains evidence-pending.
- False-positive and false-negative metrics use reviewed scenario-level unique Rule IDs, not runtime exploit labels.
- Performance is local wall-clock integration latency and varies by host and filesystem cache.
- Static findings do not prove runtime Tool, OAuth, identity, permission, or exploit reachability.
