# P2-15A-PILOT-02：Capability Shadow Gate

- Task ID: `P2-15A-PILOT-02`
- Status: Complete for source development / Shadow-only
- Completion date: 2026-08-24
- Gate: `HG-CAPCHAIN-001`
- Component Rule: `CAP-CHAIN-001`
- Gate version: `0.1.0`
- Capability Assessment Output: `0.2.0`
- Enforcement mode: `shadow`
- CI blocking: disabled
- Formal P2-15A qualification: not decided

## 1. 目标

在正式 P2-15A Report-only Hard Gate 资格尚未完成前，先打通一个不产生授权
决策的技术链路：

```text
Manifest
  → deterministic Capability Rule Finding
  → Capability Shadow Gate assessment
  → English/Chinese Text report and strict JSON report
```

本任务验证的是 Gate 技术链路和边界，不是 Gate 资格本身。

## 2. HG-CAPCHAIN-001 条件

当前 Shadow Gate 只评估：

```text
execute + secret-access + external network
```

只有同时满足以下条件，才产生 `matched=true`：

```text
1. CAP-CHAIN-001 Finding 的 correlation 为 same_target 或 parent_child；
2. Manifest Coverage complete；
3. 相关 Unknown 数量为 0；
4. Finding 具有稳定、非空的 related_ids；
5. Finding 的 Gate 版本与 CAPABILITY_SHADOW_GATE_VERSION 一致。
```

以下证据不能命中：

```text
agent_wide；
incomplete_coverage；
任何相关 Unknown；
缺少来源或 related_ids 的伪造 Finding；
非当前 Shadow Gate 版本；
```

`parent_child` 仅允许 High-floor Shadow Gate。当前没有 Critical-floor Shadow
Gate。

## 3. 报告契约

命中或未命中都会保留 Shadow Gate 结构，便于解释为什么没有命中：

```text
mode = shadow
qualification = pilot_only
blocks = false
hard_gate = false
```

Shadow Gate 不改变：

```text
AgentSec score
Severity
Evidence Confidence
Finding ID
Capability Risk Model
CLI exit code
CI 状态
```

Text 报告展示 Gate 状态；JSON 报告使用
`capability_shadow_gate` 和 `summary.shadow_gate_matches`。输出 Schema 中的
`gate_version` 必须为 `0.1.0`。

## 4. 安全边界

Shadow Gate 引擎：

- 只消费已验证的 `AgentManifest` 和确定性 Rule Finding；
- 不读取原始文件内容；
- 不执行扫描项目代码、脚本、Hook、Skill 或 MCP；
- 不连接网络；
- 不读取 OAuth、Runtime Tool 或生产权限的真实状态；
- 不调用 LLM；
- 不读取 Ground Truth 或生成正式人审结论；
- 不设置 `hard_gate=true`；
- 不启用 `--fail-on` 或 CI Blocking。

## 5. 验收标准

```text
same-target complete/no-Unknown chain 可以命中；
Agent-wide D 证据不能命中；
相关 Unknown 不能命中；
不完整 Coverage 不能命中；
Gate 版本、Gate ID、Finding ID 和 Match 关系严格绑定；
非 Gate-eligible correlation 不能构造为命中；
English/Chinese Text 和 JSON 都能显示 Shadow 状态；
Shadow 不能改变评分、严重性、置信度、hard_gate 或退出码；
不泄露 fixture 中的 Secret、URL 查询参数或 Token；
全量 Ruff、Format、Mypy、Pytest 通过。
```

## 6. 与正式 P2-15A 的关系

本任务完成后，P2-15A 仍然需要独立的资格流程：

```text
真实独立 Reviewer A/B
→ Adjudication
→ Human Evidence 导入
→ 每个候选 Gate 至少 20 Positive + 20 Eligible Negative/Near-miss
→ Precision/Recall/Confidence/Coverage/Unknown 检查
→ Report-only Gate 资格决策
```

Joint Expert Review Evidence 只能用于 Pilot 校准和技术演示，不能直接解锁
正式 P2-15A，也不能作为独立 Reviewer Agreement 或 Cohen's Kappa 的输入。
