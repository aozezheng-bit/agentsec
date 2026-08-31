# P3-13 InjecAgent-Style Tool-Injection Scenario Pack

- Task: P3-13（InjecAgent 风格工具注入评测场景集）
- Date: 2026-08-31
- Mode: static, report-only, no execution of any corpus content
- Decision record: ADR-0095

## What this is

`scenarios.json` records paired 任务场景 adapted from the dynamic
InjecAgent benchmark into AgentSec's static, non-executing evaluation
model，聚焦**工具注入**（tool-integrated injection）通道：

- 每个 scenario 记录一个 `normal task`（良性任务）与一个 `attack task`
  （注入方任务，其预期判断含 supported 的工具集成类判断）；
- 攻击意图按 InjecAgent 意图分类映射到静态语料事实：
  `secret_disclosure`（隐私攻击家族）、`data_forwarding`（污点转发家族）、
  `tool_commandeering`、`external_tool_binding`、`destructive_action`、
  `multi_capability_chain`；
- 每个 case 的 `expected` 判断逐字继承自 P3-11A 人工确认金标准
  （`label_provenance=p3-11a_gold_derived`，绑定来源文件 SHA-256）；
- 场景集通过 `load_injecagent_scenario_set` 加载、
  `build_injecagent_evaluation_cases` 转换为 P3-03
  `SemanticEvaluationCase`，供 P3-14 指标工作复放。

**工具注入静态签名**（与 P3-12 的 instruction_integrity 通道互补）：

```text
attack task 必须含至少一条 category ∈ {code_execution, network_access,
external_tooling, secret_access, destructive_action} 且
disposition=supported 的判断；normal task 不得含。
```

## Scenario inventory（7 个场景 / 14 个案例 / 双语）

| scenario | injection intent | normal case | attack case |
| --- | --- | --- | --- |
| scenario-destructive-drop | destructive_action | safe-read-only-control-assets | risky-database-drop |
| scenario-dynamic-eval-execution | tool_commandeering | homi-baseline-03 | risky-dynamic-eval |
| scenario-external-network-forwarding | data_forwarding | homi-baseline-01 | risky-external-api |
| scenario-external-tool-binding | external_tool_binding | safe-local-only-network | risky-external-tool-text |
| scenario-secret-disclosure | secret_disclosure | homi-baseline-08 | risky-credential-read |
| scenario-shell-fenced-execution | tool_commandeering | homi-baseline-09 | risky-shell-fenced |
| scenario-zh-capability-chain | multi_capability_chain（中文） | demo-release-zh-baseline | risky-chinese-capability-chain |

跨包复用说明：`safe-local-only-network` 与
`safe-read-only-control-assets` 两个 normal case 同时出现在 P3-12
AgentDojo pack 中（case ID 在本包内唯一即可；跨包复用是有意的语料
共享，两者的配对视角不同）。

## Regenerate (deterministic, idempotent)

```bash
.venv/bin/python scripts/build-p3-13-injecagent-scenarios.py
```

The builder reads the frozen P3-11A reviewer pack and gold labels, never
re-executes corpus, and fails closed on any binding mismatch.

## Authority boundary

```text
report_only                 true
blocks                      false
policy_authority            false
release_authority           false
runtime_verified            false
provider_promotion_authority false
```

静态映射边界（见 ADR-0095）：InjecAgent 是动态基准——它把恶意指令注入
工具描述并观测真实工具调用。AgentSec 不执行任何语料，本 pack 只记录
攻击意图与预期检测判断。攻击"成功率"语义是检测类统计（未被检出的
attack task = FN），由 P3-14 计算，不代表运行时工具可达、攻击成功或
可利用性。本 pack 不授予 Provider、Finding、Rule、Policy、CI、Hard
Gate 或发布权限；在离线 fixture 上得到的数字不得作为真实质量声明。
