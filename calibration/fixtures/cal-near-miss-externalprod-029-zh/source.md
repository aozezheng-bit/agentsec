# 合成静态能力评审输入

- Case: `cal-near-miss-externalprod-029-zh`
- Synthetic: `true`

## Declared facts
- `runtime_identity` / `external-privileged` / `present` / `target:externalprod-1`
- `runtime_identity` / `external-session` / `absent` / `target:externalprod-1`
- `permission` / `production-admin` / `absent` / `target:externalprod-1`
- `permission` / `production-state-change` / `present` / `target:externalprod-1`
- `permission` / `production-write` / `absent` / `target:externalprod-1`
- `tool` / `mcp-enabled-required` / `present` / `target:externalprod-1`
- `control` / `human-approval` / `absent` / `target:externalprod-1`
- `runtime_identity` / `authentication-oauth` / `present` / `target:externalprod-1`
- `control` / `sandbox` / `absent` / `target:externalprod-1`
- `control` / `network-policy` / `present` / `target:externalprod-1`
- `control` / `secret-handling` / `present` / `target:externalprod-1`
- `tool` / `mcp-enabled-required` / `absent` / `target:externalprod-1`
- `runtime_identity` / `identity-lifetime-reviewed` / `present` / `target:externalprod-1`
- `relationship` / `memory` / `absent` / `target:externalprod-1`
