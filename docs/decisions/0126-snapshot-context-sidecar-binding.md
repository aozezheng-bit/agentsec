# ADR-0126：Snapshot CLI Context Sidecar 与 Risk Baseline Binding

- 日期：2026-09-05
- 状态：Accepted（Candidate 修复）
- 任务：RISK-10A follow-up

## 问题

`homi snapshot create` 与独立 `homi report` 会产生不同的 Session-bound
`source_report_sha256`。Snapshot 与 Context 内容可能完全一致，但旧 Risk CLI 仍要求两者
Pilot digest 完全一致，导致：

```text
snapshot create
→ homi-operation-context.json from another report
→ homi risk --baseline --baseline-context
```

失败。

## 决策

1. `homi snapshot create --output <snapshot>` 自动在同一目录写出：

```text
homi-operation-context.json
```

2. 支持显式 `--context-output <path>` 覆盖 Sidecar 路径；Sidecar 与 Snapshot 在同一次
Pilot 中生成。
3. Unified Risk Baseline 绑定继续校验稳定：

```text
canonical_operation_context_sha256(context_set)
== snapshot.operation_context_sha256
```

4. 不再用 Session-bound `source_report_sha256` 作为 Snapshot/Context 跨命令绑定条件。
Operation Context 自身仍必须绑定它对应的 Pilot JSON，防止伪造 Context。
5. Homi Skill 文档改为优先使用 Snapshot 自动 Sidecar，再调用 Risk CLI。

## 安全边界

- 不降低 Operation Context 对 Pilot JSON 的自身绑定；
- 不接受不同 Workspace 的 Context Digest；
- 不执行 Workspace 内容；
- 结果继续 report-only、runtime-unverified、non-blocking。
