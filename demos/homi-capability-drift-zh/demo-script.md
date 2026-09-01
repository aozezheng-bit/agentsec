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
