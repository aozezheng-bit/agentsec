# 合成静态能力评审输入

- Case: `cal-near-miss-prodauto-009-zh`
- Synthetic: `true`

## Declared facts
- `permission` / `state-changing` / `present` / `target:prodauto-5`
- `permission` / `production-state-change` / `present` / `target:prodauto-5`
- `control` / `human-approval` / `present` / `target:prodauto-5`
- `control` / `human-approval-allow` / `absent` / `target:prodauto-5`
- `permission` / `production-admin` / `present` / `target:prodauto-5`
- `control` / `sandbox` / `absent` / `target:prodauto-5`
- `control` / `network-policy` / `absent` / `target:prodauto-5`
- `control` / `secret-handling` / `present` / `target:prodauto-5`
- `tool` / `mcp-enabled-required` / `present` / `target:prodauto-5`
- `runtime_identity` / `identity-lifetime-reviewed` / `absent` / `target:prodauto-5`
- `relationship` / `memory` / `present` / `target:prodauto-5`
