# 合成静态能力评审输入

- Case: `cal-near-miss-externalprod-009-zh`
- Synthetic: `true`

## Declared facts
- `runtime_identity` / `external-privileged` / `present` / `target:externalprod-5`
- `runtime_identity` / `external-session` / `absent` / `target:externalprod-5`
- `permission` / `production-admin` / `absent` / `target:externalprod-5`
- `permission` / `production-state-change` / `present` / `target:externalprod-5`
- `permission` / `production-write` / `absent` / `target:externalprod-5`
- `tool` / `mcp-enabled-required` / `present` / `target:externalprod-5`
- `control` / `human-approval` / `absent` / `target:externalprod-5`
- `runtime_identity` / `authentication-short-lived` / `present` / `target:externalprod-5`
- `control` / `sandbox` / `absent` / `target:externalprod-5`
- `control` / `network-policy` / `absent` / `target:externalprod-5`
- `control` / `secret-handling` / `absent` / `target:externalprod-5`
- `tool` / `mcp-enabled-required` / `absent` / `target:externalprod-5`
- `runtime_identity` / `identity-lifetime-reviewed` / `present` / `target:externalprod-5`
- `relationship` / `memory` / `absent` / `target:externalprod-5`
