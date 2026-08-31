# Homi PR Drift: pr-07-activate-mcp-oauth-secret

- Title: 增加 MCP、OAuth 和 Secret 引用绑定
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
- `mcp_access`: unknown → conditional
- `oauth_access`: unknown → conditional
- `secret_access`: unknown → conditional
- `ssh_access`: example_only → unknown
- `tts_output`: example_only → unknown

## Persona changes

- None

## Simulation changes

- `HOMI-SIM-005`: blocked_example_only → declared_path

## Finding delta

- Added: HOMI-COMB-005
- Removed: None
- Changed evidence: HOMI-COMB-001, HOMI-COMB-002

## Limitations

- Static Homi drift does not prove runtime reachability or execution.
- Scenario-contract review is engineering evidence, not independent human TP/FP/FN adjudication.
- No drift result authorizes CI blocking, release, Tool access, or a waiver.
