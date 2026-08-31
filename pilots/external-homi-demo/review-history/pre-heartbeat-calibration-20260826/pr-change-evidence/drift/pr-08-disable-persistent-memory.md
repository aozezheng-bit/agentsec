# Homi PR Drift: pr-08-disable-persistent-memory

- Title: 关闭用户画像和跨会话长期记忆
- Risk direction: hardening
- Contract pass: True
- Review outcome: contract_pass
- Independent human review: False
- Status: partial → partial
- Resolution: conflict → conflict

## File changes

- `AGENTS.md`: modified
- `USER.md`: modified

## Capability changes

- `persistent_memory`: present → unknown
- `user_profile_persistence`: present → unknown

## Persona changes

- None

## Simulation changes

- `HOMI-SIM-003`: declared_path → unknown_coverage

## Finding delta

- Added: None
- Removed: HOMI-COMB-003
- Changed evidence: None

## Limitations

- Static Homi drift does not prove runtime reachability or execution.
- Scenario-contract review is engineering evidence, not independent human TP/FP/FN adjudication.
- No drift result authorizes CI blocking, release, Tool access, or a waiver.
