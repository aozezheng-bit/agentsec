# RISK-10A Formal Acceptance Evidence

2026-09-05 本地、离线、report-only 验收证据。

- `acceptance-report.json`：验收摘要、Artifact SHA-256、Authority Boundary；
- `results/baseline/`：无风险 Baseline Homi JSON/Markdown/HTML；
- `results/scenario-08/`：定时邮箱读取；
- `results/scenario-10/`：无审批自动外发；
- `results/scenario-12/`：审批策略移除；
- `results/replay/`：16 场景确定性回放。

所有目标 Workspace 均视为不可信静态输入。未执行文件、命令、Hook、Skill、MCP 或 Scheduler。
