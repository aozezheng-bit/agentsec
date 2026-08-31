# ADR-0048：Agentic Factor Model 0.1.0

- Status: Accepted
- Date: 2026-08-24
- Task: P2-18
- Agentic Factor Model: `0.1.0`
- Agent Manifest Schema: `0.3.0`（不变）
- Capability Risk Model: `0.1.0`（不改变既有 Capability Finding 语义）

## Context

P2-16/P2-17 已提供 NIST 基础风险和 CVSS 输入能力。后续 Technical、Drift、Governance
和 Overall Score 需要一个稳定的 Agentic 能力向量作为输入。直接从 Manifest 原始字段
计算后续分数会让各个评分器重复解释权限、工具、控制和关系，造成版本和证据语义漂移。

## Decision

1. 新增独立的 `agentsec.risk.agentic_factors` 模块，不修改现有 NIST/CVSS 输入语义。
2. 固定十个 Factor ID：

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

3. Factor 值只允许 `0.0`、`0.5`、`1.0`：

   - `0.0`：未发现正向声明，或存在直接静态 deny/disable；
   - `0.5`：存在 relevant Unknown、Coverage 缺口或范围无法完整确认；
   - `1.0`：存在直接、支持范围内的正向 Manifest 声明。

4. Factor Value、Evidence Confidence、Severity、Technical Score 和 Runtime
   Reachability 保持独立，不互相替代。
5. Factor 直接静态证据使用 Confidence `B`；Relevant Unknown 或 Coverage 缺口使用
   `D`；没有正向或明确负向声明时值为 `0.0`，但 Confidence 仍为 `D`，不将缺失证据
   解释为运行时安全。
6. Evidence 只保留：

   ```text
   source scope
   root_id
   relative path
   field_path
   line range
   source content SHA-256
   ```

   不复制命令、URL、Header、环境变量值、Credential、Token 或原始 Source Value。
7. 每次提取都生成 `manifest_sha256`，并输出完整十项 Factor 的稳定顺序。
8. P2-18 只生成 Factor Vector，不实现 Technical、Drift、Governance、Overall Score、
   Hard Gate、CI Blocking 或 LLM 解释。
9. Factor Vector 使用独立格式：`agentsec-agentic-factor-vector` / `0.1.0`。

## Consequences

### Positive

- 后续评分模块共享同一份能力语义和证据契约；
- Unknown 和 Coverage 不会被默默降成安全的 `0.0`；
- 现有 Phase 1 风险模型和 P2I Capability Rule Pack 保持兼容；
- 结果可稳定 Hash、序列化和回放；
- 不需要读取原始文件内容或执行被扫描项目。

### Limitations

- 静态 Factor 不证明运行时 Tool、OAuth、Permission 可达性；
- `0.0` 只表示当前支持范围内未物化正向声明，不能作为全局安全结论；
- Factor 的权重和组合公式留给 P2-19～P2-23；
- 当前 Factor Vector 尚未接入最终 Capability Assessment CLI 报告。
