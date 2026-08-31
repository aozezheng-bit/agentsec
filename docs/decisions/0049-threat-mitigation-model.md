# ADR-0049：Threat and Mitigation Model 0.1.0

- Status: Accepted
- Date: 2026-08-24
- Task: P2-19
- Threat/Mitigation Model: `0.1.0`
- Agentic Factor Model: `0.1.0`

## Context

P2-18 固定了十项 Agentic Factor，但 Factor 只能表达静态能力信号。后续
Technical Score 需要知道：

1. 哪些 Factor 构成潜在 Threat Signal；
2. 哪些 Manifest Control 与该 Threat 相关；
3. 控制声明是否存在、是否禁用或状态未知；
4. 在没有 Runtime Attestation 时，Mitigation 能降低到什么程度。

如果把“声明了控制”直接解释为风险大幅下降，会产生不安全的假设：配置声明
不等于运行时生效、权限实际收敛或攻击路径不可达。

## Decision

1. 每个 Agentic Factor 映射到一个稳定 Threat ID，共十个 Threat Signal。
2. Threat State 只有三类：

   ```text
   absent
   unknown
   present_static
   ```

   `present_static` 只表示静态 Manifest 中存在能力信号，不表示漏洞成立或运行时可利用。
3. 每个 Threat 独立评估相关 Manifest Controls：

   ```text
   not_applicable
   absent
   declared
   disabled
   unknown
   ```
4. 只有 `present_static` Threat 才允许使用静态 Mitigation multiplier。
5. 静态控制的最大降幅固定为 10%：

   ```text
   static multiplier = 0.9
   no mitigation / unknown = 1.0
   ```

   P2-19 不允许静态控制获得更强降幅；运行时证明和更复杂公式留给后续任务。
6. Unknown Threat 永远不能获得 Mitigation reduction，即使存在静态 Control。
7. `human_approval`、`sandbox`、`network_policy`、`secret_handling`、
   `tool_filter`、`trust`、`prefix_rule` 和 `timeout` 根据 Factor 进行相关性映射。
8. Threat、Mitigation、Confidence、Factor Value 和后续 Score 独立保存。
9. Evidence 继续使用 P2-18 的 value-free source locator 和 Source SHA-256。
10. Threat/Mitigation Vector 单独版本化为：

    ```text
    agentsec-threat-mitigation-vector / 0.1.0
    ```

## Consequences

### Positive

- Threat Signal 不再与 Factor Value 或 Finding Severity 混淆；
- 静态 Control Declaration 不能强行把风险降为低风险；
- Unknown 会 fail-safe，不会被当作有效 Mitigation；
- 后续 Technical Score 可以消费稳定、可回放的 Threat/Mitigation Vector；
- 不需要执行扫描项目、连接 MCP 或访问运行时权限。

### Limitations

- `present_static` 不证明 Runtime Reachability 或 Exploitability；
- `0.9` 是当前 AgentSec 的保守 Policy multiplier，不是 NIST 或 CVSS 原生公式；
- P2-19 不计算 Technical、Drift、Governance 或 Overall Score；
- P2-19 不启用 CI Blocking 或 Hard Gate；
- 具体组合攻击链由后续确定性组合规则和评分任务负责。
