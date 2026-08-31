# P2-18：十项 Agentic Factor

- 状态：完成
- 日期：2026-08-24
- 依赖：P2-16、P2-17、P2-11

## 目标

将最终 `AgentManifest` 中的工具、权限、控制、运行时身份、指令解析和关系事实，
确定性地转换为后续评分模块可消费的十项 Agentic Factor Vector。

## 产出

```text
src/agentsec/risk/agentic_factors.py
src/agentsec/risk/__init__.py
src/agentsec/versioning.py
tests/test_agentic_factors.py
docs/decisions/0048-agentic-factor-model.md
```

## Factor

```text
instruction_override
code_execution
secret_access
external_network
production_access
persistent_memory
subagent_delegation
external_identity
autonomous_action
approval_bypass
```

每项值只能是 `0.0`、`0.5` 或 `1.0`。输出独立的 Evidence Confidence、证据定位、
Relevant Unknown、限制和 rationale。

## 安全约束

- 只读取已验证的 `AgentManifest` 对象；
- 不读取原始 Source Value；
- 不执行扫描项目代码、脚本、Skill、Hook、MCP 或命令；
- 不访问网络、环境变量或运行时权限；
- 不将静态声明描述为 Runtime Proof；
- 不影响现有 Finding、Severity、CVSS 或 Hard Gate；
- LLM 不参与 Factor 提取。

## 验收标准

- [x] 十项 Factor 具有固定 ID 和固定输出顺序；
- [x] 值域严格限制为 0/0.5/1；
- [x] 直接静态证据保留 Value-free Source Evidence；
- [x] Relevant Unknown 和 Coverage 缺口可见；
- [x] Manifest Hash 可复现；
- [x] JSON 输出确定性；
- [x] 安全、危险、不完整和非法模型测试存在；
- [x] 未修改现有 NIST/CVSS 语义；
- [x] 未启用新的 CI Blocking 或 Hard Gate。

## 未包含内容

以下内容属于后续任务：

```text
P2-19 Threat / Mitigation
P2-20 Technical Score
P2-21 Drift Score
P2-22 Governance Score
P2-23 Overall Score / Hard Gate
P2-24 Scoring Replay
```
