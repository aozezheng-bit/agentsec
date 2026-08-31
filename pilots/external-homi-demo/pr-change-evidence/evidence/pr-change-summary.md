# P2-EXIT-06-03 Homi PR/Change Drift Evidence

- Collection date: 2026-08-26
- PR snapshots: 10
- Contract passes: 10
- Calibration-required scenarios: 0
- Independent human review: False
- Acceptance ready: False

| Scenario | Direction | Status | Added | Removed | Changed | Review |
|---|---|---|---|---|---|---|
| pr-01-heartbeat-template-disabled | hardening | partial | - | - | - | contract_pass |
| pr-02-startup-policy-alignment | governance_hardening | complete | - | - | - | contract_pass |
| pr-03-real-heartbeat-activation | risk_increase | partial | HOMI-COMB-002 | - | - | contract_pass |
| pr-04-remove-external-actions | hardening | partial | - | HOMI-COMB-001 | - | contract_pass |
| pr-05-remove-external-approval-boundary | governance_risk | partial | - | - | - | contract_pass |
| pr-06-activate-ssh-binding | risk_increase | partial | HOMI-COMB-005 | - | HOMI-COMB-001 | contract_pass |
| pr-07-activate-mcp-oauth-secret | risk_increase | partial | HOMI-COMB-005 | - | HOMI-COMB-001 | contract_pass |
| pr-08-disable-persistent-memory | hardening | partial | - | HOMI-COMB-003 | - | contract_pass |
| pr-09-disable-self-modification | hardening | partial | - | HOMI-COMB-004 | - | contract_pass |
| pr-10-tools-coverage-missing | coverage_degradation | partial | - | - | - | contract_pass |

## Limitations

- Engineering scenario-contract review is complete, but independent human labels are pending.
- The baseline plus ten PR snapshots do not yet constitute the full 20-scan acceptance set.
- Waiver lifecycle evidence is deferred to P2-EXIT-06-04.
- Static drift does not prove runtime Tool, OAuth, scheduler, permission, or exploit reachability.
- All evidence remains report-only and cannot authorize CI blocking or Phase 3 entry.
