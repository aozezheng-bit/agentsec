# AgentSec 中文 Release Agent Demo

该 Demo 使用完全中文的 Agent 控制文件，展示一个经过评审、仅做本地只读
检查的发布 Agent，如何因 Markdown 指令漂移而声明命令执行、凭据访问、
外部传输、生产写入、自动部署、隐藏行为和可执行脚本能力。

所有内容都是合成的不可信测试数据。AgentSec 不执行任何被扫描指令、脚本、
Skill 或命令，也不会访问示例中的 `.invalid` 地址。

## 场景

| 场景 | 资产数 | 预期结果 |
|---|---:|---|
| `baseline/` | 2 | Coverage Complete，0 Findings |
| `risky-drift/` | 2 | 10 Findings，9 个唯一 Rule ID，最高 High |
| `prompt-injection/` | 1 | `MD-INSTR-001`、`MD-INSTR-002` |
| `malformed/` | 1 | Coverage Incomplete，退出码 `2` |
| `remediated/` | 2 | Coverage Complete，0 Findings |

## 运行中文现场 Demo

从仓库根目录执行：

```bash
scripts/demo-developer.sh --case-language zh
```

展示完整中文规则清单：

```bash
scripts/demo-developer.sh --case-language zh --show-rules
```

无交互预演：

```bash
scripts/demo-developer.sh \
  --case-language zh \
  --no-pause \
  --output-dir /tmp/agentsec-release-demo-zh
```

规则清单也可以单独查看：

```bash
agentsec rules list --language zh
```

## 策略边界

```text
enforcement_mode=report_only
ci_blocking_enabled=false
global_safety_claimed=false
```

High Finding 不会被 AgentSec 0.1.0 自动阻断。Demo 中“整改前暂停发布”是人工
治理建议，不是 CLI 授权或阻断决定。零 Finding 也不证明 Agent 全局安全。
