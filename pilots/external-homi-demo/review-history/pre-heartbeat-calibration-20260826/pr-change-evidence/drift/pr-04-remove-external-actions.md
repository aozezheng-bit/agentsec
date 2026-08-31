# Homi PR Drift: pr-04-remove-external-actions

- Title: 移除 Web、日历、天气和外部消息声明
- Risk direction: hardening
- Contract pass: True
- Review outcome: contract_pass
- Independent human review: False
- Status: partial → partial
- Resolution: conflict → conflict

## File changes

- `AGENTS.md`: modified

## Capability changes

- `external_message_send`: conditional → unknown
- `external_network_read`: present → unknown

## Persona changes

- None

## Simulation changes

- `HOMI-SIM-001`: declared_path → unknown_coverage
- `HOMI-SIM-002`: declared_path → blocked_example_only

## Finding delta

- Added: None
- Removed: HOMI-COMB-001, HOMI-COMB-002
- Changed evidence: None

## Limitations

- Static Homi drift does not prove runtime reachability or execution.
- Scenario-contract review is engineering evidence, not independent human TP/FP/FN adjudication.
- No drift result authorizes CI blocking, release, Tool access, or a waiver.
