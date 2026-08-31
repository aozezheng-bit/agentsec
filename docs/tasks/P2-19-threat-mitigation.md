# P2-19：Threat 和 Mitigation

- 状态：完成
- 日期：2026-08-24
- 依赖：P2-18 Agentic Factor Model

## 目标

将 P2-18 Agentic Factor Vector 转换为独立的 Threat Signal，并根据最终
`AgentManifest` 的静态控制声明生成保守的 Mitigation Assessment。

## 产出

```text
src/agentsec/risk/threat_mitigation.py
src/agentsec/risk/__init__.py
src/agentsec/versioning.py
tests/test_threat_mitigation.py
docs/decisions/0049-threat-mitigation-model.md
```

## Threat State

```text
absent
unknown
present_static
```

`present_static` 只能表示静态能力信号，不等价于漏洞、运行时可达或实际利用。

## Mitigation State

```text
not_applicable
absent
declared
disabled
unknown
```

静态控制声明最多使用：

```text
multiplier = 0.9
```

没有控制、控制禁用、控制状态 Unknown 或 Threat 本身 Unknown 时，不得降低风险：

```text
multiplier = 1.0
```

## 安全约束

- 不执行被扫描项目、脚本、Skill、Hook、MCP 或命令；
- 不读取环境变量、Credential、Token 或运行时权限；
- 不将 Control Declaration 解释为 Runtime Attestation；
- 不将 Unknown 解释为有效 Mitigation；
- 不修改 Finding、Severity、CVSS 或现有 Hard Gate；
- 不启用 CI Blocking；
- 不调用 LLM。

## 验收标准

- [x] 十个 Factor 都有稳定 Threat ID；
- [x] Threat State 与 Factor Value 严格绑定；
- [x] 相关 Control Kind 有确定性映射；
- [x] 静态 Mitigation multiplier 有明确上限；
- [x] Unknown Threat 不得获得 Mitigation reduction；
- [x] Disabled / Unknown / Absent Control 可区分；
- [x] 输出包含 value-free Evidence；
- [x] Manifest Hash 和 Factor Model Version 绑定；
- [x] JSON 输出确定；
- [x] 安全、危险、缺失控制和不完整 Coverage 测试通过。

## 未包含内容

```text
P2-20 Technical Score
P2-21 Drift Score
P2-22 Governance Score
P2-23 Overall Score / Hard Gate
P2-24 Scoring Replay
```
