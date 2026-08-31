# P2-EXIT-06-02 External Homi Baseline Evidence

- Collection date: 2026-08-26
- Source kind: user_supplied_homi_workspace_export
- Homi Pilot status: partial
- Static profile complete: False
- Standard files present: True
- Combination findings: 4
- Simulation steps: 5
- Report-only: True
- Runtime verified: False
- CI blocked: False
- Acceptance ready: False

## Safety assertions

- Scanned content executed: False
- Network accessed: False
- Runtime tools invoked: False
- Target modified by scan: False
- Sensitive value leak count: 0
- API/CLI reports byte-identical: True
- Target/output overlap guard observed: True

## Finding IDs

- `HOMI-COMB-001`
- `HOMI-COMB-002`
- `HOMI-COMB-003`
- `HOMI-COMB-004`

## Limitations

- This is one user-supplied Homi workspace export, not a production runtime.
- The scan is static and report-only; it does not prove Tool, OAuth, scheduler, or exploit reachability.
- No independent human TP/FP/FN labels are included in P2-EXIT-06-02.
- This baseline does not satisfy the full 20-scan/10-PR acceptance contract.
