# ADR-0116：Context-aware Deterministic Rules

- **状态**：Accepted for AgentSec 0.4.x source development
- **日期**：2026-09-03
- **任务**：RISK-04

## 背景

Agent 能力声明、人格描述、长期记忆和网络读取意图本身不能代表真实风险。此前仅依据 capability presence 或关键词组合容易把“可用于正常服务用户”的能力误报为高风险，也无法解释具体影响和控制条件。

RISK-03 已将 Homi 静态证据转换为中性的 `OperationContextSet`，因此需要一个只依赖结构化操作语境的确定性规则层。

## 决策

采用 `DeterministicContextRuleEngine` 作为 RISK-04 的唯一内置上下文规则入口。规则必须组合判断以下信息：

- action、target；
- data classification、sharing、retention；
- trigger、purpose；
- authorization、controls；
- scope、frequency、reversibility。

内置规则固定为 `CTX-RISK-001` 至 `CTX-RISK-006`，并使用 `CTX-COVERAGE-001` 单独表达上下文覆盖不足。

以下情况不单独命中风险规则：

- 公开网页读取 + 公开数据；
- persona、identity、长期记忆文本；
- 单纯存在外部工具或网络能力而没有敏感操作上下文。

## 权限与决策边界

RISK-04 输出的是带 Evidence 的 report-only Finding：

- 不计算数值风险分；
- 不验证运行时 Tool、OAuth、权限、调度器或漏洞可达性；
- 不授予权限，不认证 Agent；
- 不修改 Finding、规则库或 Agent 文件；
- 不阻断 CI；
- 不允许 LLM 改写 Rule、Severity、Score、Policy 或 Hard Gate。

后续 RISK-05 才能在保留上下文和证据绑定的前提下进行 residual risk、potential impact、current posture 和 drift 量化。

## 证据与可复现性

每个 Finding 的 ID 由 Rule ID、Context ID、Evidence ID 和 rationale code 的规范化内容计算 SHA-256。上下文规则报告通过 `source_context_sha256` 绑定唯一的 `OperationContextSet`，Homi bundle 必须拒绝绑定不一致的 sidecar。

Unknown/needs_context 只能产生 Coverage Finding，不能被解释为风险，也不能被解释为安全通过。

## 备选方案

1. **沿用 capability 关键词直接打分**：拒绝。无法区分能力声明与实际操作意图，误报不可解释。
2. **仅依赖 LLM 语义判断**：拒绝。不可复现，且不能成为策略或 CI 权威。
3. **直接把 RISK-04 接入 Hard Gate**：拒绝。当前阶段只有静态证据，缺少运行时可达性和真实影响证明。
4. **Unknown 直接升级为高风险**：拒绝。Unknown 是覆盖状态，应驱动补充证据而非制造风险结论。

## 后续影响

- 新增 `schemas/risk/context-risk-report.schema.json` 和 `homi-context-risk.json` sidecar；
- Homi report 生成 Operation Context 后运行 RISK-04；
- Combined HTML 展示风险 Finding、Coverage、最高严重级别和命中规则；
- 需要通过人工评审和真实运行时证据继续校准 RISK-05 的量化口径。
