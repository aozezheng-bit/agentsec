# RISK-06：Runtime Attestation / Evidence Reconciliation

- **日期**：2026-09-04
- **状态**：本地实现完成；保持 report-only，未向 Homi 发布
- **前置任务**：RISK-01 Operation Context、RISK-04 Context Risk、RISK-05 Context Risk Quantification

## 1. 目标

RISK-06 为外部运行时系统提供一个受约束的证据入口：Homi 沙箱、平台遥测或组织批准的运行时验证器可以提交脱敏的 Runtime Attestation，AgentSec 对其进行格式验证、Snapshot/Context/RISK-04 三重绑定和确定性对账。

AgentSec **不执行**被扫描 Agent，不运行其 Hook、Skill、MCP、Scheduler 或命令，也不自行生成运行时证明。Runtime Attestation 被视为不可信输入，不能因为字段名叫 `verified` 就直接改变权限或策略。

## 2. 输入与绑定

运行时证据必须包含：

- `agent_snapshot_sha256`：外部运行时证据对应的 Homi Pilot JSON 快照 SHA-256；
- `context_sha256`：对应 Operation Context Set 的规范化 SHA-256；
- `issuer`、`method`、`verification_status`；
- 每条观察的 `operation_id`、`action`、`target`、`observed`、证据摘要 SHA-256、脱敏来源引用和时间元数据；
- `limitations` 和固定的 report-only authority 字段。

`agentsec homi reconcile-runtime` 只读取以下已生成产物：

```text
homi-pilot-report.json
homi-operation-context.json
homi-context-risk.json
runtime-attestation.json    # 外部生成，脱敏后提交
```

它验证：

1. Pilot JSON 原始字节 SHA-256 等于 `agent_snapshot_sha256`；
2. Operation Context Set 的规范化 SHA-256 与 Homi Operation Context 报告一致；
3. RISK-04 的规范化报告 SHA-256 与对账输入一致；
4. Attestation 自身格式、版本、ID、观察排序、Authority 和 Evidence Confidence 一致；
5. 所有输出仍是 `report_only=true`、`policy_authority=false`、`ci_blocked=false`。

## 3. 确定性对账状态

| 状态 | 条件 | Evidence Confidence | 当前态势可用 |
|---|---|---:|---:|
| `reconciled` | 已验证、所有声明操作均匹配、无未声明观察、无动作/目标冲突、Context 覆盖完整 | A | 是 |
| `partial` | 已验证，但存在未观察声明、风险 Finding 未覆盖或 Unknown/coverage gap | B | 否 |
| `conflict` | 已验证，但存在动作/目标不一致或观察到未声明操作 | B | 否 |
| `unverified` | 外部 Attestation 未验证或被拒绝 | D | 否 |

`observed=false` 不算已匹配；对应的声明操作会进入 `declared_not_observed_operation_ids`。观察到的未声明操作必须进入 `observed_not_declared_operation_ids`，不得静默忽略。

只有 `reconciled` 才允许将本次**证据**标记为 Confidence A。Confidence A 不等于风险严重级别，也不等于漏洞已被利用。

## 4. 安全边界

Runtime Attestation 和 Evidence Reconciliation：

- 不授予 Tool、OAuth、Permission 或其他运行时权限；
- 不认证 Agent 身份，不替代 DID/身份快照流程；
- 不修改 Policy、Hard Gate 或 CI 结果；
- 不证明漏洞可利用性或实际攻击成功；
- 不把运行时观察自动写回静态报告；
- 不把 LLM 输出当作 Runtime Attestation；
- 不包含原始日志、Secret、Credential、用户原文、完整 URL 或 IP；
- 对账失败关闭：哈希不匹配、Authority 篡改和结构错误直接拒绝。

## 5. CLI

```bash
agentsec homi reconcile-runtime \
  --report-dir /tmp/agentsec-homi-report \
  --attestation /tmp/runtime-attestation.json \
  --force
```

默认生成：

```text
/tmp/agentsec-homi-report/homi-runtime-reconciliation.json
```

输出只包含脱敏元数据、哈希、匹配统计、冲突和限制说明。该命令不会重新扫描 Workspace，也不会执行 Workspace 内容。

## 6. Bundle 展示

如果 `homi-pilot-report.json` 所在目录存在合法且绑定的 `homi-runtime-reconciliation.json`，`agentsec homi bundle` 会在 JSON、Markdown 和 HTML 中展示：

- 对账状态；
- 运行时是否由外部系统验证；
- 当前态势是否具备资格；
- Evidence Confidence；
- 已匹配、声明但未观察、观察但未声明的操作数量；
- 动作/目标冲突；
- Context 覆盖和 Unknown 维度；
- 不授权、不认证、不阻断、不证明 exploitability 的边界。

Bundle 仍然是展示层，不会把运行时证据改写成新的权限或 CI 决策。

## 7. 验证

新增测试覆盖：

- Observation/Attestation ID 确定性和排序；
- Verified/Unverified 的 Confidence 规则；
- 完全匹配、部分覆盖、冲突、未声明操作；
- `observed=false` 的显式语义；
- Agent Snapshot、Operation Context、RISK-04 哈希绑定；
- Authority 篡改和格式篡改拒绝；
- JSON Schema 导出；
- Homi CLI sidecar 生成和 Bundle HTML 展示。

当前验证命令：

```bash
PYTHONPATH=src .venv/bin/pytest -q \
  tests/test_runtime_attestation.py \
  tests/test_runtime_homi_integration.py \
  tests/test_homi_bundle.py \
  tests/test_homi_cli.py \
  tests/test_homi_provenance.py \
  tests/test_provenance_registry.py
.venv/bin/ruff check src tests
.venv/bin/mypy src tests
```

## 8. 外部前置条件

要进行真实 Runtime Attestation Pilot，Homi/平台仍需单独完成：

- sandbox 或遥测采集器；
- endpoint、凭据、数据驻留、保留周期和费用审批；
- 运行时操作到 Operation Context 的映射；
- Attestation issuer 的信任与密钥管理；
- 脱敏和最小化数据协议。

在这些条件满足前，仓库只提供导入、验证、对账和报告能力，不声称“Real Provider”或“真实运行时安全验证”已经完成。

## RISK-07 follow-up

RISK-07 adds trust verification around this RISK-06 input. A self-declared
`verification_status=verified` is not trusted without an approved issuer/key,
valid signature and time window, and first-use nonce in a persistent replay
Store. See `docs/tasks/RISK-07-runtime-attestation-trust-replay-hardening.md`.
