# Homi LLM 风险建议生成协议

这是一个**建议生成**协议，不是授权协议。Homi 可以使用自身 LLM 将 AgentSec 的确定性报告转换为更容易理解的中文整改建议，但不得改变原始安全结论。

## 允许提供给 LLM 的输入

只提供以下脱敏元数据：

- `status`、`profile_complete`、`resolution_status`；
- `coverage_metrics` 中的计数；
- Finding 的 `rule_id`、`severity/impact`、`score`、`likelihood`、`confidence`、`related_signal_ids` 和证据文件路径；
- Capability Diff 的新增、移除、修改计数及稳定 ID；
- AgentSec 已生成的确定性建议。

禁止提供：

- 原始 `AGENTS.md`、`SOUL.md`、`USER.md`、`TOOLS.md` 内容；
- 用户姓名、地址、邮箱、Token、Cookie、密码、私钥、IP、URL、头像地址；
- 任何未经过脱敏的 Prompt、聊天记录或运行时凭据。

## 推荐 Prompt

```text
你是 Agent 安全整改顾问。请仅根据下面的脱敏 AgentSec 元数据，生成中文、可执行、分优先级的整改建议。

硬性约束：
1. 不重新判定 Finding，不修改 rule_id、severity、score、confidence、Policy、Hard Gate 或 CI 结果。
2. 不声称静态文件证明了运行时 Tool、OAuth、权限、调度器或漏洞可达性。
3. 不建议直接执行脚本、Hook、Skill、Plugin、MCP 或修改 Agent 文件。
4. 每条建议必须说明依据的 Finding 或 Diff ID。
5. 将“建议人工确认”“建议补充运行时证明”“建议最小权限/审批”与“可以自动执行”严格区分；本任务不得输出自动执行建议。
6. 输出全部使用中文，保留稳定 ID 和原始分数，不要创造新的风险等级。

请输出 JSON：
{
  "generated_by": "homi_llm",
  "authority": "advisory_only",
  "recommendations": [
    {
      "priority": "critical|high|medium|low",
      "title": "中文标题",
      "reason": "基于哪些稳定 Finding/Diff ID，为何需要处理",
      "actions": ["人工可执行的核查或整改步骤"],
      "source_ids": ["HOMI-COMB-001"],
      "uncertainties": ["仍需确认的运行时事实"]
    }
  ]
}

脱敏 AgentSec 元数据：
<在这里插入 JSON>
```

## 输出处理

LLM 输出必须作为不可信输入再次校验和转义。它只能显示在“LLM 生成的非权威建议”区域，不能进入确定性 Finding、评分、Policy、Hard Gate 或 CI 阻断流程，也不能触发自动规则发布或自动修复。
