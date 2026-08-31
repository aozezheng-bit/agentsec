# P2-15B：Policy-controlled CI Enforcement

## 状态

- 实现状态：完成最小可控链路
- 日期：2026-08-24
- 当前可用 Gate：`HG-CAPCHAIN-001`
- 默认行为：不阻断

## 目标与边界

P2-15B 将“报告展示”与“CI 阻断”分离。只有用户显式提供并通过严格校验的
Policy，且 Gate 已通过人工证据 Qualification，才允许返回退出码 `1`。

- 确定性 Rule / 已接受 Gate 结果拥有 CI 决策权；
- LLM 输出不能作为授权或阻断依据；
- 不修改 Finding 的 `hard_gate`、Severity、Score、Confidence 或 Shadow Gate；
- 不证明运行时 Tool、OAuth、Permission 可达性；
- Coverage 不完整或 Unknown 不得被风险阻断覆盖，优先返回 `2`；
- 未通过 Qualification 的 Gate 在 enforce 模式下 fail closed，返回 `3`；
- 不自动生成 Waiver、发布 Rule 或修改规则库。

## Policy 文件

格式：`agentsec-capability-ci-policy`，Schema `0.2.0`（P2-EXIT-01 升级）。
列出 `qualified_gates` 的 Policy 必须同时提供 `qualification` 信任绑定
（显式 `registry_path` 与批准的 `registry_sha256`），否则在加载阶段
fail closed 返回 `3`。示例：

```json
{
  "format": "agentsec-capability-ci-policy",
  "schema_version": "0.2.0",
  "policy_id": "org-capchain-enforce",
  "policy_version": "0.2.0",
  "enabled": true,
  "enforcement_mode": "enforce",
  "fail_on": {"qualified_gates": ["HG-CAPCHAIN-001"]},
  "qualification": {
    "registry_path": "../calibration/p2-15a-capchain-40/human-evidence/qualified-gate-registry.yaml",
    "registry_sha256": "19cc7f19b63b01b4479ecdd92da53c6bc5d3dae2a0985b5903bd77f4e4bfabfd"
  },
  "coverage": {"require_complete": true, "require_unknown_free": true},
  "safety": {"allow_llm_authority": false, "allow_runtime_unverified_authority": false}
}
```

仓库提供：

- `policies/capability-ci-policy.json`：默认关闭、report-only；
- `policies/capability-ci-enforce-example.json`：显式 enforce 示例，
  已绑定仓库内的可信资格注册表。

Loader 拒绝未知字段、未知 Gate、重复 Gate、非法启用组合、缺少资格
信任绑定的 Gate 列表、LLM/runtime authority、Symlink Policy 和非法
JSON。

## Qualified Gate Registry（P2-EXIT-01）

格式：`agentsec-qualified-gate-registry`，Schema `0.1.0`
（ADR-0062）。Gate 资格不再从固定仓库相对路径自动获得；资格授权必须
来自显式钉扎的注册表，并完整验证证据绑定链：

- 注册表使用有界、`O_NOFOLLOW` 的严格 YAML 加载器：拒绝别名、锚点、
  显式 Tag、重复 Key、未知字段、Symlink 和超限文件；
- 每个 Gate 条目钉扎 `qualification_report_path`（注册表目录内的
  安全文件名）、`qualification_sha256`、`qualification_artifact_id`、
  `evidence_mode=human`、`qualification_status=accepted` 和
  `allowed_floor=high`；
- Policy 中的 `registry_sha256` 必须与注册表文件摘要一致；
- 资格报告通过摘要钉扎、重复 Key 拒绝、Gate/Rule 绑定、完成状态、
  接受结论、空阻断原因、全部检查通过、安全 Policy 标志，以及
  `artifact_id` 重算三重校验后才获得授权；
- 资格证据永远不从被扫描项目内容自动发现；
- 任何缺失、截断、伪造或摘要不匹配的信任证据在 enforce 模式下
  fail closed 返回 `3`，report-only 策略继续记录 `not_qualified`。

冻结 JSON Schema：`schemas/policy/qualified-gate-registry.schema.json`。

## CLI

```bash
# 只做报告，不会因为 Finding 阻断
agentsec capability assess ./agent --format json

# 显式加载 Policy，输出 CI 决策报告
agentsec capability enforce ./agent \\
  --policy policies/capability-ci-policy.json \\
  --format json

# 输出中文文本报告
agentsec capability enforce ./agent \\
  --policy policies/capability-ci-enforce-example.json \\
  --language zh
```

`capability assess` 保持原有 report-only 行为；只有新的 `capability enforce`
命令会执行 Policy 决策。

## 退出码

| 条件 | 退出码 |
|---|---:|
| Policy report-only/disabled，未命中阻断 | `0` |
| 已 Qualification Gate 命中且显式 enforce | `1` |
| Assessment Coverage、Rule 执行或 Policy 要求的 Unknown-free 不满足 | `2` |
| Policy Schema 无效、未知 Gate、未 Qualification Gate | `3` |
| 必需分析失败 | `5` |

## JSON 决策证据

当前输出格式为 `agentsec-capability-ci-enforcement` / `0.4.0`
（P2-EXIT-01 从 `0.3.0` 升级，新增 `qualification_registry` provenance
块）。报告包含：

- `policy_id` / `policy_version`；
- `decision`、`exit_code`、Assessment 完整性；
- `qualification_registry`：注册表是否存在、`registry_id`、
  `registry_version` 与钉扎 `registry_sha256`；
- 每个 Gate 的 `qualification`、`matched`、`blocks`、匹配 Finding ID 和原因；
- `boundary`，明确 `hard_gate=false`、`llm_authority=false`、
  `runtime_verified=false`；
- 不输出原始 Secret 或扫描项目运行时内容。

## 验证

```bash
.venv/bin/ruff check src tests scripts
.venv/bin/mypy src tests
PYTHONPATH=src .venv/bin/python -m pytest -q
```

## P2-27 Organization Policy YAML

`capability enforce --policy` now also accepts `agentsec-organization-policy` YAML `0.1.0`. The Capability section is adapted to the same Qualification-aware Gate engine. CI Report Output `0.2.0` records Policy source format, schema version, and SHA-256. See `docs/organization-policy.md`.

## P2-EXIT-01 / P2-EXIT-02 信任边界

Organization Policy YAML 自 `0.3.0`（P2-EXIT-02）起携带
`capability.qualification` 注册表绑定，与 JSON Capability Policy 使用同一条
已验证的资格证据链；缺少绑定的 Gate 列表仍在加载阶段 fail closed
（退出码 `3`）。P2-EXIT-02 同时引入 `--trust-root` 与
`--expect-policy-sha256` / `--expect-registry-sha256` 信任钉扎，详见
`docs/trusted-ci.md` 与
`docs/decisions/0062-trusted-policy-and-qualification-root.md`。
