# RISK-04：Context-aware Deterministic Rules

## 目标

RISK-04 在 RISK-03 `OperationContextSet` 的结构化证据之上，识别“操作、目标、数据、触发器、目的、授权、控制、范围、频率和可逆性”的确定性风险组合。

本任务的核心校准是：**审查实际操作语境，而不是把能力存在本身当成风险**。

因此，以下内容单独出现时不构成高风险 Finding：

- 读取公开网页或公开数据；
- 具有长期记忆、人格描述、身份描述；
- 在 `TOOLS.md` 中保留环境说明；
- 声明可使用外部工具但没有对应的敏感操作上下文。

## 范围与安全边界

- 规则是 deterministic、可复现、report-only。
- RISK-04 只输出风险模式、严重性、定性 likelihood/impact、Evidence 和限制条件。
- RISK-04 **不计算数值风险分**；残余风险、潜在影响、当前态势和漂移分由后续 RISK-05 负责。
- RISK-04 不验证 Tool、OAuth、Permission、Identity、Scheduler 或漏洞可达性。
- RISK-04 不授予权限、不进行 Agent 身份认证、不修改 Finding、不修改 Rule Pack、不修改 Agent 文件、不阻断 CI。
- LLM 不在 RISK-04 决策链路中；后续 LLM 只能对已脱敏的 Finding 做非权威解释。
- Unknown 表示上下文覆盖不足，输出为 `coverage` 观察，不等于风险，也不等于安全通过。
- 输出只包含相对路径、哈希、枚举、Finding ID 和受控 rationale，不包含原始源文本、Secret 或凭据值。

## 内置规则

| Rule ID | 风险模式 | 触发条件摘要 |
| --- | --- | --- |
| `CTX-RISK-001` | 敏感数据外传 | `send/write` + 外部服务或外部消息渠道 + `personal/sensitive/credential/secret` + `sharing=external` |
| `CTX-RISK-002` | 自动化敏感操作 | `scheduled/proactive/autonomous` + 敏感数据 + 外部/邮箱/生产/Secret 目标 |
| `CTX-RISK-003` | 高影响操作缺少授权 | `delete/modify_policy/modify_identity/execute` + 特权/生产/控制/工具/Secret 目标 + 授权未知或缺失 |
| `CTX-RISK-004` | Secret 到外部传输链 | 一个上下文读取 Secret/Credential，另一个上下文向外部目标发送或写入 |
| `CTX-RISK-005` | 敏感数据无限期外部持久化 | `store/write` + `retention=indefinite` + 外部/组织共享 + 敏感数据 |
| `CTX-RISK-006` | 控制文件修改缺少授权 | 修改策略/身份/控制文件 + 授权未知或缺失 |
| `CTX-COVERAGE-001` | Operation Context 覆盖不足 | `coverage_complete=false`、存在 Unknown 维度或规则执行失败 |

`CTX-RISK-003` 和 `CTX-RISK-006` 可以针对同一个控制文件修改同时命中：前者表达高影响操作风险，后者表达控制文件授权缺口；Finding ID 通过 Rule、Context、Evidence 和 rationale code 稳定生成。

## 严重性与证据

严重性和 Evidence Confidence 分开记录：

- Secret/Credential 外传且授权缺失、无脱敏时可为 `critical`；
- 敏感外传、敏感自动化、高影响未授权、无限期外部持久化可为 `high`/`medium`；
- 静态证据的 Confidence 由关联 Evidence 的最保守等级汇总；
- 静态证据不会伪造 `runtime_verified=true`，也不会产生运行时证明。

## 产物

- `schemas/risk/context-risk-report.schema.json`
- `homi-context-risk.json`：由 `agentsec homi report` 生成，绑定同目录的 `homi-operation-context.json`。
- 组合报告会自动读取并校验该 sidecar，展示风险 Finding 数量、覆盖观察数量、最高严重级别和命中规则。

绑定校验要求：

1. `homi-context-risk.json` 必须是 `agentsec-context-risk-report`；
2. authority 固定为 report-only、非 runtime verified、非 policy authority、非 CI blocked；
3. `source_context_sha256` 必须等于 `homi-operation-context.json` 中 `context_set` 的规范化 SHA-256；
4. `risk_finding_count` 和 `coverage_finding_count` 必须与 `findings` 内容一致；
5. 任意绑定失败均拒绝合并，不静默拼接不同 Agent 或不同快照的结果。

## 使用方式

```bash
agentsec homi report /path/to/homi-workspace \
  --output-dir /tmp/agentsec-homi-report \
  --language zh \
  --force
```

生成的目录中包含：

```text
homi-pilot-report.json
homi-pilot-report.md
homi-pilot-report.html
homi-operation-context.json
homi-context-risk.json
homi-risk-score.json
homi-risk-state.json
homi-posture.json
homi-calibration.json
homi-build-fingerprint.json
```

组合展示：

```bash
agentsec homi bundle \
  --pilot /tmp/agentsec-homi-report/homi-pilot-report.json \
  --format html --language zh \
  --output /tmp/agentsec-homi-report/homi-security-report.html
```

## 测试要求

`tests/test_context_rules.py` 覆盖：

- 公开网页读取 + 公开数据不命中风险；
- Secret 外传；
- 定时敏感操作；
- 控制文件高影响修改和授权缺口；
- Secret 读取到外部发送的跨上下文组合；
- 无限期外部持久化；
- Unknown / Coverage；
- 确定性输出和 Finding ID；
- 规则失败隔离；
- authority 不可伪造及输出值最小化。

## 后续接口

RISK-05 已接收 RISK-04 `ContextRiskReport` 作为风险信号输入，负责：

- residual risk；
- potential impact；
- current posture；
- risk drift；
- 与既有 Technical / Drift / Governance / Overall Score 的审慎集成。

RISK-05 不得把公开网页读取、人格描述、长期记忆或单纯 capability presence 自动升级为高风险；必须继续保留操作语境、影响和控制条件。
