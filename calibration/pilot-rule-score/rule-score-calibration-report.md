# AgentSec Rule and Score Calibration Report

- Status: **COMPLETE**
- Pilot: `internal-release-agent-pilot` (`internal_integration`)
- Rules covered/uncovered: 9/6
- Pilot FP/FN: 0/0
- Scoring replay: 7 cases, PASS
- Rule Pack action: `retain_current`
- Risk Model action: `retain_current`
- Internal MVP ready: `true`

| Rule | Positive cases | TP/FP/FN | Score | Severity | Recommendation |
|---|---:|---:|---:|---|---|
| MD-APPROVAL-001 | 3 | 3/0/0 | 5.5 | medium | retain_current |
| MD-DEPLOY-001 | 3 | 3/0/0 | 8.0 | high | retain_current |
| MD-DESTRUCT-001 | 0 | 0/0/0 | 8.0 | high | more_data |
| MD-EXEC-001 | 3 | 3/0/0 | 8.0 | high | retain_current |
| MD-EXEC-002 | 0 | 0/0/0 | 8.0 | high | more_data |
| MD-INSTR-001 | 4 | 4/0/0 | 5.5 | medium | retain_current |
| MD-INSTR-002 | 4 | 4/0/0 | 5.5 | medium | retain_current |
| MD-MEMORY-001 | 0 | 0/0/0 | 2.0 | low | more_data |
| MD-NET-001 | 3 | 3/0/0 | 5.5 | medium | retain_current |
| MD-OBFUSC-001 | 0 | 0/0/0 | 2.0 | low | more_data |
| MD-PRIV-001 | 3 | 3/0/0 | 8.0 | high | retain_current |
| MD-PRIV-002 | 0 | 0/0/0 | 8.0 | high | more_data |
| MD-SECRET-001 | 3 | 3/0/0 | 8.0 | high | retain_current |
| MD-SELF-001 | 0 | 0/0/0 | 8.0 | high | more_data |
| MD-TOOL-001 | 3 | 3/0/0 | 2.0 | low | retain_current |

## Limitations

- Pilot evidence is internal and curated rather than a production distribution sample.
- Six Rules have no positive Pilot scenario and remain marked more_data.
- Scoring replay proves deterministic stability, not empirical loss calibration.
- Static evidence does not prove runtime exploitability or reachable permissions.
