# Homi PR Drift: pr-05-remove-external-approval-boundary

- Title: 移除 SOUL 中的外部行为审批边界
- Risk direction: governance_risk
- Contract pass: True
- Review outcome: contract_pass
- Independent human review: False
- Status: partial → partial
- Resolution: conflict → conflict

## File changes

- `SOUL.md`: modified

## Capability changes

- None

## Persona changes

- `external_approval`: present → unknown

## Simulation changes

- None

## Finding delta

- Added: None
- Removed: None
- Changed evidence: None

## Limitations

- Static Homi drift does not prove runtime reachability or execution.
- Scenario-contract review is engineering evidence, not independent human TP/FP/FN adjudication.
- No drift result authorizes CI blocking, release, Tool access, or a waiver.
