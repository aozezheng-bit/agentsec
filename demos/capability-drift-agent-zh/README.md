# AgentSec Capability Drift 中文 Demo

- 任务：`P2I-05`
- 状态：已验收
- 日期：2026-08-20
- 受众：开发者、安全评审人员、管理层

## 故事主线

一个经过评审、只做本地只读检查的发布 Agent，因配置漂移新增：

```text
STDIO MCP 执行潜力
Secret / 环境变量引用
必选外部 HTTP MCP
OAuth 类外部身份
自动审批模式
Sub-Agent 委派
发布状态持久化记忆
```

AgentSec 将这些静态声明归一化为 Agent Manifest，通过确定性组合规则输出
17 个 Findings，并使用 Capability Diff 展示能力变化。整改移除外部 MCP、凭证
引用、委派和持久化后，当前 Capability Rule Finding 回到 0。

这不是运行时攻击演示。所有文件都是合成的不可信数据，AgentSec 不启动 MCP、
不执行 Command/Skill/Sub-Agent、不读取凭证、不访问示例地址，也不调用 LLM。

## 场景

| 场景 | 预期结果 |
|---|---|
| `baseline/` | Coverage Complete，0 Findings |
| `risky-drift/` | 17 Findings，16 个 Rule ID，最高 High |
| `incomplete/` | Override 非 UTF-8，退出码 `2` |
| `remediated/` | Coverage Complete，0 Findings |

## 运行自动化 Demo

```bash
scripts/run-capability-demo.sh --language zh
```

保留产物：

```bash
scripts/run-capability-demo.sh \
  --language zh \
  --output-dir /tmp/agentsec-capability-demo-zh
```

## 运行现场讲解 Demo

```bash
scripts/demo-capability-drift.sh --language zh
```

无停顿预演：

```bash
scripts/demo-capability-drift.sh --language zh --no-pause
```

离线 fallback：

```bash
scripts/demo-capability-drift.sh --language zh --offline --no-pause
```

## 管理层一屏摘要

```text
新增能力：执行 + Secret 访问 + 外部网络
治理漂移：自动审批 + 凭证化必选外部 MCP + 委派 + 持久化
最高风险：High
证据：17 个 Findings，覆盖 16 个确定性 Capability Rule ID
整改：移除外部集成、凭证引用、委派和持久化，恢复本地评审
策略：Report-only，不自动阻断 CI
```

人工建议是在整改前暂停发布；这不是 AgentSec 的授权或阻断决定。

## 冻结产物

`expected/` 保存中英文 Text 对应的确定性 Manifest、Assessment、Diff 和管理层
摘要。验证命令：

```bash
PYTHONPATH=src .venv/bin/python \
  scripts/validate_capability_demo_outputs.py \
  demos/capability-drift-agent-zh/expected
```

所有产物由 `checksums.sha256` 防止静默漂移。

## 边界说明

Demo 不证明运行时 Tool 可用、实际权限已授予、攻击链可达、漏洞可利用或 Agent
全局安全。Capability Findings 仍为 `hard_gate=false`，CI Blocking 关闭。
