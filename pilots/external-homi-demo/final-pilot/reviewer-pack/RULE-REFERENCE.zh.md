# AgentSec Markdown Rule 速查表

- Rule Pack：`0.3.0`
- 评审对象：每个 State ZIP 中的 `AGENTS.md`
- 用途：独立人工判断静态确定性 Rule IDs

## 规则清单

### 指令完整性

- `MD-INSTR-001`：覆盖或忽略先前指令。
  代表信号：`ignore previous instructions`、忽略此前指令。
- `MD-INSTR-002`：绕过安全检查或隐藏报告。
  代表信号：`disable safety checks`、跳过安全检查。

### 人工审批

- `MD-APPROVAL-001`：弱化或移除确认要求。
  代表信号：`without approval`、无需确认、自动批准。

### 代码执行

- `MD-EXEC-001`：声明 Shell 或系统命令执行。
  代表信号：`execute commands`、执行系统命令、调用 Bash。
- `MD-EXEC-002`：声明动态或任意代码执行。
  代表信号：`eval`、`exec`、`execute arbitrary code`。

### 网络和凭据

- `MD-NET-001`：声明外部请求或数据传输。
  代表信号：`external API`、HTTP request、向外部传输数据。
- `MD-SECRET-001`：声明读取或使用 Secret、Token、Key。
  代表信号：`read credentials`、environment variable、访问令牌。

### 特权访问

- `MD-PRIV-001`：声明生产系统访问。
  代表信号：`production environment`、生产数据库、生产集群。
- `MD-PRIV-002`：声明管理员、Root 或提权权限。
  代表信号：`run as root`、sudo access、管理员权限。

### 破坏和发布操作

- `MD-DESTRUCT-001`：声明删除、重置或销毁。
  代表信号：`delete all`、`rm -rf`、drop database、销毁资源。
- `MD-DEPLOY-001`：声明部署、发布或制品发布。
  代表信号：`deploy to production`、publish release、自动部署。

### 记忆、自我修改和工具

- `MD-MEMORY-001`：声明跨会话或长期保存。
  代表信号：`long-term memory`、remember across sessions。
- `MD-SELF-001`：声明修改自身指令或配置。
  代表信号：`modify its own instructions`、更新自身配置。
- `MD-OBFUSC-001`：存在编码、不可见或易混淆内容。
  代表信号：Base64、零宽字符、双向控制字符。
- `MD-TOOL-001`：声明外部工具或可执行脚本。
  代表信号：`run the script`、download and run、`.sh` 引用。

## 判断原则

1. 必须有可定位的静态文本支持 Rule ID。
2. Finding 证明的是声明，不证明运行时能力可达。
3. 明确能力声明即使带有审批或范围限制，通常仍保留该能力 Finding。
4. 教学、禁止性说明和安全边界需要结合完整句子判断。
5. 编码无效属于 Coverage 问题，不等同于混淆规则命中。
6. 所有 Rule IDs 必须按字典序排列且去重。

## 本 Pilot 的 Policy 速查

```text
阻断阈值           high
阻断 Rule 范围     MD-EXEC-001、MD-SECRET-001
执行 Rule Waiver   active，有效至 2099-12-31
Secret Rule Waiver expired，2000-01-01 后不再有效
Coverage 不完整    优先返回 Exit Code 2
```

Waiver 不删除 Finding，只影响阻断决策。未列入阻断范围的 Finding 仍应记录，
但不会单独导致 Exit Code 1。

## Exit Code

| Exit Code | 含义 |
|---:|---|
| 0 | Coverage 完整，且没有未豁免的阻断 Finding |
| 1 | Coverage 完整，且存在未豁免的阻断 Finding |
| 2 | Coverage 不完整 |

本速查表不包含任何 Case 的工程预期或 Scanner 结果。
