# Homi Capability Drift Demo 现场脚本

## 开场

> 我们不直接判断 Agent “安不安全”，而是审计它的控制文件声明：它声明了什么、
> 和基线相比改变了什么、这些变化是否组合成新的风险。

## 第一幕：基线

运行 baseline 扫描，说明：

- 六类控制文件齐全；
- 能力画像来自静态证据；
- Baseline 只记录经过确认的当前状态；
- 当前不做运行时验证，也不会阻断 CI。

## 第二幕：新增外部消息能力

展示 `drift-add-external-message/`：

```text
AGENTS.md 新增“sending emails or public posts”声明
→ external_message_send 从 unknown/absent 变为 conditional
→ Capability Diff 报告 modified/added 变化
→ 与主动行为组合后产生 HOMI-COMB-001
```

## 第三幕：放宽记忆策略

展示 `drift-modify-memory-policy/`：

```text
USER.md 新增长期画像保留指引
→ user_profile_persistence 变为 present
→ 与 persistent_memory 组合
→ 产生 HOMI-COMB-003
```

## 第四幕：移除控制边界

展示 `drift-remove-safety-control/`：

```text
AGENTS.md 允许修改控制文件
SOUL.md 允许自我演化
IDENTITY.md 允许自赋值
→ 控制文件、人设和身份边界同时变化
→ 产生 HOMI-COMB-004
```

## 收束

> AgentSec 告诉我们“哪里变了、为什么值得关注、证据在哪”。
> 它不替代 Homi 的运行时权限系统，也不把静态结果伪装成漏洞利用证明。

## 可重复的“修改 MD → 检测漂移 → 注入风险”现场演示

推荐使用隔离副本，不要直接修改真实 Homi Workspace：

```bash
PYTHONPATH=src .venv/bin/python scripts/run-homi-mutation-demo.py \
  --output-dir /tmp/agentsec-homi-mutation-demo
```

脚本会自动完成五幕：

1. `00-baseline`：扫描未修改的六类标准文件，作为基线。
2. `01-external-message`：向 `AGENTS.md` 加入外部邮件/公开发帖声明，并在 `SOUL.md` 加入主动行为；验证文件摘要变化和 `HOMI-COMB-001`。
3. `02-heartbeat-network`：向 `HEARTBEAT.md` 加入邮件、日历、提及和天气巡检；验证 `HOMI-COMB-002`。
4. `03-persistent-memory`：向 `USER.md` 加入长期画像/记忆保留指引；验证 `HOMI-COMB-003`。
5. `04-self-modifying-controls`：在 `AGENTS.md`、`SOUL.md`、`IDENTITY.md` 加入控制文件、人设和身份自修改指引；验证 `HOMI-COMB-004`。

每一幕同时输出：

- Pilot JSON / Markdown / HTML；
- Baseline / 当前阶段 Manifest JSON；
- Agentic Score JSON（Technical / Drift / Governance / Overall）；
- 文件级 SHA-256、大小和行数变化；
- Capability Diff JSON / HTML；
- Finding Delta；
- 传入 Score 的综合 Bundle HTML（包含评分总览、三轴雷达图和四个评分卡）；
- 汇总文件 `demo-summary.json` 和 `demo-summary.md`。

现场讲解时依次打开：

```text
reports/00-baseline/homi-pilot-report.json
reports/01-external-message/homi-pilot-report.html
diffs/01-external-message/capability-diff.html
diffs/04-self-modifying-controls/combined-report.html
demo-summary.md
```

如果需要单独查看评分输入，可打开：

```text
scores/04-self-modifying-controls/agentic-assessment.json
```

综合报告的评分数据必须来自这个 Agentic Score JSON，并通过以下参数注入：

```text
agentsec homi bundle --pilot <pilot.json> --diff <diff.json> \
  --score <agentic-assessment.json> --format html --language zh
```

演示结论应表述为：AgentSec 识别了 Markdown 文件的摘要变化，并将变化映射到新的静态能力和确定性风险 Finding；这不等于证明运行时工具已注册、权限已生效或漏洞可利用。
