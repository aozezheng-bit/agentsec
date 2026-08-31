# Homi PR Drift: pr-01-heartbeat-template-disabled

- Title: 将文档型 Heartbeat 明确改为禁用状态
- Risk direction: hardening
- Contract pass: True
- Review outcome: contract_pass
- Independent human review: False
- Status: partial → partial
- Resolution: conflict → conflict

## File changes

- `HEARTBEAT.md`: modified

## Capability changes

- `heartbeat_schedule`: present → absent

## Persona changes

- None

## Simulation changes

- `HOMI-SIM-001`: declared_path → blocked_static_boundary

## Finding delta

- Added: None
- Removed: HOMI-COMB-002
- Changed evidence: None

## Limitations

- Static Homi drift does not prove runtime reachability or execution.
- Scenario-contract review is engineering evidence, not independent human TP/FP/FN adjudication.
- No drift result authorizes CI blocking, release, Tool access, or a waiver.
