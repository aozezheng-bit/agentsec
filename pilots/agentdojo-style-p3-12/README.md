# P3-12 AgentDojo-Style Paired Injection Scenario Pack

- Task: P3-12（AgentDojo 风格评测场景集）
- Date: 2026-08-31
- Mode: static, report-only, no execution of any corpus content

## What this is

`scenarios.json` records paired 任务场景 adapted from the dynamic
AgentDojo benchmark into AgentSec's static, non-executing evaluation model:

-每个 scenario 记录一个 `normal task` 与一个 `attack task`（同一语料家族）；
- attack task 来源于真实注入语料（`testdata/prompt-injection`、demo 与
  Homi 快照），normal task 来源于对应的良性语料；
- 每个 case 的 `expected` 判断逐字继承自 P3-11A 人工确认金标准
  （`label_provenance=p3-11a_gold_derived`，绑定来源文件 SHA-256）；
- 场景集通过 `load_agent_dojo_scenario_set` 加载、
  `build_scenario_evaluation_cases` 转换为 P3-03 `SemanticEvaluationCase`，
  供后续 P3-14 指标工作复放。

## Scenario inventory（9 个场景 / 18 个案例 / 双语）

| scenario | injection family | normal case | attack case |
| --- | --- | --- | --- |
| scenario-auto-approval | auto_approval | demo-release-remediated | inj-auto-approve |
| scenario-command-execution | command_execution | safe-shell-explanation | inj-execute-command |
| scenario-finding-suppression | finding_suppression | safe-read-only-control-assets | inj-suppress-findings |
| scenario-hidden-instruction | hidden_instruction | safe-document-reference | inj-hide-instruction |
| scenario-homi-approval-override | instruction_override | homi-baseline-02 | homi-pr-01 |
| scenario-release-injection-demo | scanner_control | safe-local-only-network | demo-release-injection |
| scenario-release-review | instruction_override | demo-release-baseline | inj-disregard-prior |
| scenario-scanner-control | scanner_control | safe-minimal-agent | inj-ignore-scanner |
| scenario-scanner-control-zh | scanner_control（中文） | safe-chinese-local-review | inj-chinese-scanner-control |

## Regenerate (deterministic, idempotent)

```bash
.venv/bin/python scripts/build-p3-12-agentdojo-scenarios.py
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

静态映射边界（见 ADR-0094）：AgentDojo 是动态执行基准；本 pack 只记录
normal/attack 配对任务与预期判断。攻击“成功率”语义是检测类统计
（未被检出的 attack task = FN），由 P3-14 计算，不代表运行时攻击成功或
可利用性。本 pack 不授予 Provider、Finding、Rule、Policy、CI、Hard Gate
或发布权限；在离线 fixture 上得到的数字不得作为真实质量声明。
