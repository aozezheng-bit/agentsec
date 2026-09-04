# RISK-03：Homi Operation Context Extraction

- Status: Complete (local implementation)
- Date: 2026-09-03
- Scope: deterministic extraction from parsed Homi static evidence
- Depends on: RISK-01 Operation Context Contract, RISK-02 Homi state classification

## Objective

将 Homi Markdown 中已经被解析、定位和摘要化的动作声明转换为
RISK-01 `OperationContextSet`，为后续上下文规则和风险量化提供结构化输入。
本任务不计算风险分，也不把关键词本身当作漏洞。

## Extracted dimensions

每条上下文尽量填充：

```text
action
target
data_scope.classification
trigger
purpose
authorization
approval / controls
reversibility
scope
frequency
evidence
status
```

无法从同一证据行确定的字段保持 `unknown`，上下文状态为
`needs_context`；没有识别到动作声明时生成一个显式
`homi.operation.unknown`，而不是返回空集或假设安全。

## Supported static operation families

当前确定性提取器覆盖：

- 工作区读取；
- 公开网络/外部服务读取；
- 心跳触发的周期性读取；
- 外部消息发送；
- 用户上下文/记忆持久化；
- Homi 控制文件修改；
- Secret/Token/Password/Credential 读取；
- SSH 连接；
- MCP 调用；
- OAuth 使用。

人格、自我介绍、头像、长期记忆泛化模板和工具文档示例不会单独变成操作上下文。
工具示例文件会被跳过；用户资料模板不会被当作真实持久化操作。

## Evidence rules

- Evidence 只引用相对文件路径、精确行号、文件 SHA-256、提取方法和置信度；
- 不复制源文本、Secret、Token、密码、IP、URL 或凭据值；
- Evidence 行范围会从 Markdown block 收窄到匹配动作的具体行，避免把同一段中无关的审批或触发语句错误带入上下文；
- 静态声明使用 `static_declaration` 和静态 D 级证据置信度；
- 文件变更或 Pilot 重扫期间若摘要不一致，提取失败关闭，不拼接不同快照。

此外，`build_manifest_operation_context_set()` 可以消费已经验证的
`AgentManifest`，将 Manifest Permission 和 Tool Side Effect 映射为同一份
`OperationContextSet`。Manifest Evidence 使用 `manifest` 提取方法和 C 级静态
证据置信度；被拒绝的 Permission 不会被当作可执行路径，未解析的工具/权限
覆盖会写入 `unknown_dimensions`。

## 输出

`HomiOperationContextReport` 是绑定到 Pilot 报告的 report-only 包装：

```text
homi-operation-context.json
```

它包含：

- `source_report_sha256`：精确绑定的 Pilot JSON 摘要；
- `context_set`：RISK-01 `agentsec-operation-context-set`；
- `unknown_dimensions` 和 `coverage_complete`；
- 固定的 `report_only=true`、`runtime_verified=false`、`ci_blocked=false`。

`agentsec homi report` 和 `DeterministicHomiReportOnlyPilot.run_and_write()` 均会生成该文件。
`agentsec homi bundle` 会自动校验绑定并在 Markdown/HTML/JSON 联合报告中展示提取数量、覆盖状态和 Unknown 维度数量。

Schema：

```text
schemas/risk/homi-operation-context.schema.json
```

## 设计边界

- `OperationContext` 是规则输入，不是 Finding；
- `active`/`latent`/`template`/`unknown` 来自 RISK-02，不直接等价于风险等级；
- `runtime_attested` 不能由静态提取器伪造；
- `authorization=unknown` 不等价于“无授权”，而是等待平台或人工上下文；
- 提取器不调用 LLM、Provider、网络、工具或调度器；
- 提取器不改变 Finding、Severity、Score、Policy、Hard Gate 或 CI 结果。

## Verification

```text
RISK-03 extraction tests: 6 passed
Homi Pilot / Bundle integration tests: 16 passed
Schema export: passed
Ruff check and format: passed for affected files
Mypy: passed for affected files
```

## Follow-up

- RISK-04：消费 Operation Context，重构组合风险规则；
- RISK-05：计算 potential impact、current posture、control effectiveness 和 residual risk；
- RISK-06/RISK-07：将上下文纳入 Snapshot、Behavior Drift 和 Risk Drift。
