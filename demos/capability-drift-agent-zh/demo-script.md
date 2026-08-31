# Capability Drift 中文讲解稿

- 时长：7～8 分钟
- 受众：开发者与管理层
- 命令：`scripts/demo-capability-drift.sh --language zh`

## 1. 背景

Agent 的 Markdown、TOML、Rules 和 MCP 配置都可能改变能力边界。AgentSec 只把
它们作为静态数据，不执行任何声明。

## 2. 安全基线

展示 Manifest：一个本地 Review Skill、Coverage Complete、0 Findings。说明零
Finding 仅代表当前规则未匹配。

## 3. 风险漂移

展示 17 个 Findings 和 16 个 Rule ID，重点解释：

```text
执行 + Secret + 外部网络
无有效审批的状态变更能力
必选凭证化外部 MCP
委派到高权限能力
持久化记忆 + 敏感能力
高影响能力 + Unknown
```

## 4. Capability Diff

展示 Tool、Permission、Control、Identity、Relationship、Unknown 的标准化
新增/移除，以及 Source、Field、Line 和 SHA-256。强调不输出原始 before/after
敏感值。

## 5. 不完整 Coverage

展示非 UTF-8 Override，命令退出 `2`。零 Findings 不能视为安全通过。

## 6. 整改

移除外部 MCP、凭证引用、委派和持久化。整改后 Coverage Complete、0
Findings；Remediation Diff 显示风险能力被移除。

## 7. 管理层结论

最高报告风险为 High。人工建议整改前暂停发布。AgentSec 仍为 Report-only，
没有自动阻断 CI，也没有证明运行时漏洞。

## 离线模式

```bash
scripts/demo-capability-drift.sh --language zh --offline --no-pause
```

## 8. Report-only Gate 展示（P2-15A-PILOT-04）

使用已经完成 Human Evidence、Confidence v2 和 Qualification 的
`HG-CAPCHAIN-001`：

```bash
scripts/run-report-only-gate-demo.sh \
  --language zh \
  --format text
```

重点展示：

```text
Qualification：accepted
Precision：1.0
Recall：1.0
Confidence 校准：1.0
Report-only 命中：2
Report-only 未命中：3
blocks=false
hard_gate=false
CI blocking=false
```

演示重点：

1. 规则已经通过最小 Gate Qualification；
2. 同一 Target 和 Parent/Child 场景可以展示命中；
3. Agent-wide、Relevant Unknown、Incomplete Coverage 场景不会命中；
4. Gate 资格只影响报告展示，不产生授权；
5. AgentSec 不证明运行时可达性或实际漏洞利用；
6. 当前不阻断 CI，也不启用 `--fail-on`。

离线查看冻结结果：

```bash
cat demos/capability-drift-agent-zh/expected/report-only-gate-demo.txt
```
