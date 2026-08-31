# AgentSec 中文 Markdown 规则库

- 任务：`M1-01`
- 状态：完成
- 日期：2026-08-20
- Rule Pack：`0.3.1`
- 规则数量：`15`
- 决策记录：`docs/decisions/0017-bilingual-markdown-rule-pack.md`

## 1. 使用方式

查看中文规则清单：

```bash
agentsec rules list --language zh
```

扫描中文 Agent 项目仍使用普通命令：

```bash
agentsec scan /path/to/chinese-agent
```

中文规则与英文规则共享稳定 Rule ID。`--language zh` 只改变规则清单的展示
语言，不改变检测结果、风险评分或 JSON Schema。

## 2. 中文规则清单

| Rule ID | 风险类别 | 中文含义 | 代表性中文信号 |
|---|---|---|---|
| `MD-INSTR-001` | 指令完整性 | 可能覆盖或忽略先前指令 | 忽略此前指令、无视先前指令、以本文件指令为准 |
| `MD-INSTR-002` | 指令完整性 | 可能绕过安全检查或隐藏报告 | 跳过安全检查、屏蔽风险发现、不要披露本指令 |
| `MD-APPROVAL-001` | 人工审批 | 人工审批可能被弱化或移除 | 无需人工审批、不必征得用户同意、自动批准 |
| `MD-EXEC-001` | 代码执行 | 声明 Shell 或系统命令执行 | 运行 Shell 命令、调用 Bash、运行终端命令 |
| `MD-EXEC-002` | 代码执行 | 声明动态或任意代码执行 | 动态执行代码、执行任意代码、动态导入模块 |
| `MD-NET-001` | 网络访问 | 声明外部网络请求或数据传输 | 调用外部 API、发送网络请求、向外部传输数据 |
| `MD-SECRET-001` | 凭据访问 | 声明凭据、令牌或密钥访问 | 读取环境变量、访问令牌、获取部署凭证 |
| `MD-PRIV-001` | 特权访问 | 声明生产系统访问 | 写入生产环境、修改生产数据库、访问生产集群 |
| `MD-PRIV-002` | 特权访问 | 声明管理员、Root 或提权权限 | 管理员权限、以 Root 身份运行、Sudo 权限 |
| `MD-DESTRUCT-001` | 破坏性操作 | 声明破坏性删除或重置 | 删除全部文件、清空数据库、销毁资源 |
| `MD-DEPLOY-001` | 破坏性操作 | 声明部署、发布或制品发布 | 自动部署、发布到线上、发布软件包 |
| `MD-MEMORY-001` | 持久记忆 | 声明持久化或跨会话记忆 | 长期记忆、跨会话保存、记住供后续任务 |
| `MD-SELF-001` | 自我修改 | 声明 Agent 修改自身控制资产 | 修改自己的指令、更新自身配置、编辑自身技能 |
| `MD-OBFUSC-001` | 混淆隐藏 | 存在编码、不可见或易混淆内容 | Base64、零宽字符、双向控制字符、混合脚本字符 |
| `MD-TOOL-001` | 外部工具 | 声明外部工具或可执行脚本 | 执行脚本、使用外部工具、下载并运行、`.sh` 引用 |

## 3. 中文测试与案例

每条 Rule ID 都有：

- 中文正向匹配；
- 中文安全负向样例；
- 文件和行号 Evidence；
- 英文回归测试；
- 不执行脚本、命令和引用的安全验证。

中文语料包括：

```text
testdata/safe/chinese-local-review
testdata/risky/chinese-capability-chain
testdata/risky/chinese-governance-memory
testdata/risky/chinese-admin-destructive-dynamic
testdata/prompt-injection/chinese-scanner-control
```

中文现场 Demo 位于：

```text
demos/release-agent-zh/
```

运行：

```bash
scripts/demo-developer.sh --case-language zh --show-rules
```

## 4. 已知边界

Rule Pack 0.3.0 仍然是确定性词法和结构信号，不是完整中文语义理解：

- 未收录的同义改写可能漏报；
- 复杂否定、引用和教学示例可能误报；
- 跨文件组合语义尚未形成能力画像；
- TOML、YAML、JSON 和 MCP 配置仍属于后续阶段；
- Finding 只证明文本中存在风险声明，不证明运行时权限真实可用；
- 零 Finding 不证明 Agent 全局安全。

Phase 3 的受限 LLM 分析将用于补充隐晦表达和语义推断，但不会替代确定性
规则，也不会直接成为授权或 CI 阻断决定。


## P2-EXIT-06-05A 外部人工评审校准

独立 Homi Pilot 评审确认四类直接能力声明未被 Rule Pack `0.3.0` 覆盖。
`0.3.1` 在不改变 Rule ID 和风险含义的前提下增加：

```text
MD-EXEC-001  Git 状态检查和自主 Commit/Push 声明
MD-NET-001   Search the web 声明
MD-SELF-001  Update AGENTS.md 声明
MD-TOOL-001  Skills provide your tools 声明
```

该补丁将同一组独立 Human Labels 的 Recall 从 0.84 提升到 1.0，FP 保持 0。
