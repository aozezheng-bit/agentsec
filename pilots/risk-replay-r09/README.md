# RISK-09 回放语料（Homi Workspace 风险回放）

本目录是 RISK-09 的静态回放语料：16 套 Homi 标准六文件 workspace
（AGENTS.md、SOUL.md、IDENTITY.md、USER.md、TOOLS.md、HEARTBEAT.md），
用于回放验证 AgentSec 的 Operation Context、`CTX-RISK-*` 确定性规则与风险方向。
旧 `HOMI-COMB-*` 只作为声明信号展示，不作为权威风险真值。

## 语料说明

- 基础模板取自 `demos/homi-capability-drift-zh/baseline/`（scenario-01/02/15
  与其字节级一致），风险文案写法参考 `demos/homi-capability-drift-zh/drift-*/`
  已验证可触发的措辞。
- 全部文件均为脱敏演示数据：不含真实 URL、IP、token、私钥或任何凭据，
  不含可执行内容，均为纯 Markdown 文本，仅供静态扫描。
- 场景文件正文使用英文（与基础模板一致），保证静态 marker 可稳定匹配。

## 16 个场景

| 场景 | 目录 | 变更内容（相对默认模板） | 预期 Findings | 预期风险方向 |
|------|------|--------------------------|---------------|--------------|
| 01 默认模板 | `scenario-01/` | 无（baseline 原样，无风险声明） | 无 | low |
| 02 完全相同 | `scenario-02/` | 与 scenario-01 完全相同（验证相同输入相同快照） | 无 | low |
| 03 仅空白变化 | `scenario-03/` | 仅改空格/换行/注释行，语义不变（验证快照哈希变化但 Findings 不变） | 无 | low |
| 04 文案变化 | `scenario-04/` | 仅改 SOUL.md 欢迎语/人格风格文案，无能力声明 | 无 | low |
| 05 身份外观 | `scenario-05/` | 仅改 IDENTITY.md 名称与 emoji | 无 | low |
| 06 良性偏好 | `scenario-06/` | USER.md 增加"保存非敏感用户偏好（如主题色）" | 无 | low |
| 07 无限期对话保存 | `scenario-07/` | USER.md 增加"无限期保存完整对话记录" | CTX-RISK-007 | high |
| 08 Heartbeat 任务 | `scenario-08/` | HEARTBEAT.md 增加"每 30 分钟检查邮件"；AGENTS.md 声明定时邮箱访问 | CTX-RISK-002 | high |
| 09 外部读取 | `scenario-09/` | AGENTS.md 增加"可访问外部网络读取公开资料"（无主动人格配合，仅能力面扩大） | 无 | review |
| 10 主动外发 | `scenario-10/` | AGENTS.md 增加"自动向外部发送邮件/公开发帖（无需逐次审批）" | CTX-RISK-008 | elevated |
| 11 敏感工具声明 | `scenario-11/` | TOOLS.md 声明 Secret/SSH/OAuth/Shell 访问绑定（无 Skill 发现与主动人格配合） | 无 | review |
| 12 移除审批 | `scenario-12/` | AGENTS.md 写明"执行操作无需人工审批"，移除 Ask-first 审批边界 | CTX-RISK-003、CTX-RISK-006 | high |
| 13 移除 Secret 排除 | `scenario-13/` | TOOLS.md 声明"不排除 Secret 目录访问" | 无 | review |
| 14 控制文件政策 | `scenario-14/` | AGENTS.md 增加"允许修改自身控制文件/配置"；SOUL.md、IDENTITY.md 含自演化文案 | CTX-RISK-003、CTX-RISK-006 | high |
| 15 篡改测试 | `scenario-15/` | 与 scenario-01 相同；本场景用于快照篡改测试，目录内放正常内容 | 无 | low |
| 16 覆盖不完整 | `scenario-16/` | 仅含 AGENTS.md 与 SOUL.md，其余四个标准文件缺失 | 无 | review |

## 预期值文件

`expectations.json`：每个场景的 `expected_rule_ids`（预期触发的 Context Rules）
与 `expected_risk_direction`（low / elevated / high；不确定或需人工复核的
标 `review`）。

## 权威规则速查

- `CTX-RISK-002`：定时/主动/自主敏感操作；
- `CTX-RISK-003`：高影响操作缺少授权；
- `CTX-RISK-006`：控制文件修改缺少授权；
- `CTX-RISK-007`：个人或敏感数据无限期保留且缺少 Retention/Consent Control；
- `CTX-RISK-008`：外部 Send/Write 自主执行且缺少 Approval。

## 回放抽验命令

```bash
PYTHONPATH=src .venv/bin/python -m agentsec homi scan pilots/risk-replay-r09/scenario-07 --format json
PYTHONPATH=src .venv/bin/python -m agentsec homi scan pilots/risk-replay-r09/scenario-08 --format json
PYTHONPATH=src .venv/bin/python -m agentsec homi scan pilots/risk-replay-r09/scenario-10 --format json
```

在 Unified Risk JSON 的 `context_findings[].rule_id` 中核对 `expected_rule_ids`。

## 铁律

- 所有文件是脱敏演示数据：不含任何真实 URL、IP、token、私钥。
- 不含可执行内容；全部为纯 Markdown 文本。
- 结果均为静态、报告型证据，不证明运行时能力。
