# 合成静态能力评审输入

- Case: `cal-near-miss-capchain-009-zh`
- Synthetic: `true`

## Declared facts
- `permission` / `execute-other-target` / `present` / `target:isolated`
- `permission` / `execute` / `absent` / `target:capchain-5`
- `permission` / `secret-access` / `present` / `target:capchain-5`
- `permission` / `external-network` / `present` / `target:capchain-5`
- `control` / `sandbox` / `present` / `target:capchain-5`
- `control` / `network-policy` / `absent` / `target:capchain-5`
- `control` / `secret-handling` / `absent` / `target:capchain-5`
- `tool` / `mcp-enabled-required` / `present` / `target:capchain-5`
- `runtime_identity` / `identity-lifetime-reviewed` / `absent` / `target:capchain-5`
- `relationship` / `delegates-to` / `present` / `target:capchain-5`
