# P3-HOMI-RECAL-07：HEARTBEAT 导出边界标记误报修复

- 日期：2026-09-03
- 状态：本地修复完成；候选包需重新构建并在 Homi 隔离环境复验
- 触发证据：Homi 候选版本隔离验证中的实际 JSON 字段

## 问题

Homi 导出 Workspace 文件时可能保留传输边界标记，例如：

```text
\\=== HEARTBEAT.md ===
\\=== END HEARTBEAT.md ===
```

这些标记不是 Agent 指令，但旧适配器会把它们当成普通正文。对于只有
模板说明、Markdown 标题、反斜杠和边界标记的 `HEARTBEAT.md`，这会导致：

- `files["HEARTBEAT.md"].state=present`；
- `heartbeat.tasks_present=true`；
- 错误触发 `HOMI-COMB-002`；
- 纯模板被呈现为 `8.0/high`。

## 修复

在 Homi 适配器中增加严格的边界标记识别，只忽略六个固定标准文件的：

- `=== FILE.md ===`；
- `=== END FILE.md ===`；
- 可选的转义反斜杠。

任意其他 `===` 文本不会被忽略。修复后，边界标记不会贡献任务内容；纯
Heartbeat 模板会被识别为 `empty` 或 `example_only`，不触发
`HOMI-COMB-002`。包含真实任务列表的 Heartbeat 仍然识别为 `present`，并
继续保留 report-only 静态 Finding。

## 验证

新增回归测试覆盖：

- Homi 导出边界标记；
- 模板说明文字；
- 反斜杠转义行；
- `HOMI-COMB-002` 不因导出包装标记误触发。

该修复不改变：

```text
runtime_verified=false
report_only=true
ci_blocked=false
```

也不把静态文件分类提升为运行时 Attestation。
