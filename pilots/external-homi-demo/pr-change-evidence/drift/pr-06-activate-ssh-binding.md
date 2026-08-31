# Homi PR Drift: pr-06-activate-ssh-binding

- Title: 将 TOOLS 示例替换为实际 SSH 与 TTS 绑定声明
- Risk direction: risk_increase
- Contract pass: True
- Review outcome: contract_pass
- Independent human review: False
- Status: partial → partial
- Resolution: conflict → conflict

## File changes

- `TOOLS.md`: modified

## Capability changes

- `camera_access`: example_only → unknown
- `ssh_access`: example_only → conditional
- `tts_output`: example_only → conditional

## Persona changes

- None

## Simulation changes

- `HOMI-SIM-005`: blocked_example_only → declared_path

## Finding delta

- Added: HOMI-COMB-005
- Removed: None
- Changed evidence: HOMI-COMB-001

## Limitations

- Static Homi drift does not prove runtime reachability or execution.
- Scenario-contract review is engineering evidence, not independent human TP/FP/FN adjudication.
- No drift result authorizes CI blocking, release, Tool access, or a waiver.
