# Homi Capability Drift Demo（中文）

这是一个脱敏、不可执行的 Homi Workspace 漂移演示，用于验证 AgentSec 从
“配置文件变化”到“能力变化”和“风险变化”的完整链路。

## 场景

- `baseline/`：经过评审的静态基线。
- `drift-add-external-message/`：新增经过审批的外部消息能力声明。
- `drift-modify-memory-policy/`：放宽用户画像和长期记忆保留策略。
- `drift-remove-safety-control/`：移除控制文件人工审批边界，并加入人格/身份自修改指引。

所有文件仅作为静态文本读取。Demo 不执行 Markdown、脚本、Skill、Hook、Plugin 或 MCP，
也不连接外部网络、不读取凭据、不证明运行时能力。

## 运行

```bash
PYTHONPATH=src .venv/bin/python scripts/run-homi-drift-demo.py --language zh
```

指定输出目录：

```bash
PYTHONPATH=src .venv/bin/python scripts/run-homi-drift-demo.py \\
  --language zh \\
  --output-dir /tmp/agentsec-homi-drift-demo
```

## 现场故事

```text
1. 先扫描 baseline，建立可信静态基线。
2. 展示三个变更分支：新增外部消息、放宽记忆策略、移除控制边界。
3. 运行 Manifest、Capability Diff、Finding Delta 和 Score Delta。
4. 强调结果是静态、报告型证据，不是运行时漏洞证明。
5. 使用人工审批和运行时策略决定是否发布，不把报告自动升级为权限。
```
