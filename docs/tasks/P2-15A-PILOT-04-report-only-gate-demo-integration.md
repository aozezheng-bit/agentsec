# P2-15A-PILOT-04：HG-CAPCHAIN-001 Report-only Gate 展示与 Demo 集成

- Task ID: `P2-15A-PILOT-04`
- Status: Complete
- Date: 2026-08-24
- Gate: `HG-CAPCHAIN-001`
- Audience: Developers and Management

## 1. 目标

将已经通过最小 Qualification 的 `HG-CAPCHAIN-001` 接入一个明确的
Report-only 展示层：

```text
Qualification Report
  → deterministic Shadow Gate scenario evaluation
  → Report-only Gate presentation
```

本任务不改变既有 Shadow Gate Finding Contract，也不把 `hard_gate` 设置为 true。

## 2. 运行命令

中文现场演示：

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec

scripts/run-report-only-gate-demo.sh \
  --language zh \
  --format text
```

英文现场演示：

```bash
scripts/run-report-only-gate-demo.sh \
  --language en \
  --format text
```

JSON 输出：

```bash
scripts/run-report-only-gate-demo.sh \
  --language zh \
  --format json \
  --output /tmp/agentsec-report-only-gate.json
```

指定 Qualification 报告：

```bash
scripts/run-report-only-gate-demo.sh \
  --qualification-report \
  calibration/p2-15a-capchain-40/human-evidence/\
  hg-capchain-001-qualification-report-v2.json
```

## 3. 当前 Qualification 输入

```text
calibration/p2-15a-capchain-40/human-evidence/
└── hg-capchain-001-qualification-report-v2.json
```

Qualification 结果：

```text
status = accepted
eligible_for_report_only_gate = true
Precision = 1.0
Recall = 1.0
Confidence calibration = 1.0
```

## 4. Demo 场景

| 场景 | 结果 | 说明 |
|---|---|---|
| `same-target-match` | Match | 同一 Target 的三项能力链路成立 |
| `parent-child-match` | Match | 父子工具族关系满足 Gate 关联条件 |
| `agent-wide-no-match` | No-match | Agent-wide 关联不具备 Gate 资格 |
| `unknown-no-match` | No-match | Relevant Unknown 阻止命中 |
| `incomplete-coverage-no-match` | No-match | Coverage 不完整阻止命中 |

现场演示结果：

```text
Report-only matches = 2
Report-only no-match = 3
```

## 5. 输出契约

Report-only Gate 输出包含：

```text
mode = report_only
qualification = accepted
blocks = false
hard_gate = false
ci_blocking = false
```

每个场景保留：

```text
correlation
coverage_complete
relevant_unknowns
related_ids
risk_unchanged
```

## 6. 安全边界

Demo：

- 只运行 AgentSec 自身的确定性分析；
- 只使用合成、不执行的 Manifest 场景；
- 不执行被扫描项目、脚本、Hook、Skill 或 MCP；
- 不连接网络；
- 不读取 OAuth、Runtime Tool 或生产权限；
- 不调用 LLM；
- 不进行实际漏洞利用；
- 不进行授权决策；
- 不设置 `hard_gate=true`；
- 不启用 `--fail-on`；
- 不阻断 CI。

Qualification 只改变报告层对 Gate 状态的呈现，不改变 Finding 的 Score、Severity、
Evidence Confidence、Finding ID 或 CLI Exit Code。

## 7. 冻结 Demo 产物

中文：

```text
demos/capability-drift-agent-zh/expected/report-only-gate-demo.json
demos/capability-drift-agent-zh/expected/report-only-gate-demo.txt
```

英文：

```text
demos/capability-drift-agent/expected/report-only-gate-demo.json
demos/capability-drift-agent/expected/report-only-gate-demo.txt
```

两套 Demo 的 `expected/checksums.sha256` 已更新。

## 8. 下一步边界

本任务完成后，项目可以：

```text
展示 Qualified Report-only Gate
```

但仍不能直接执行：

```text
生产 Hard Gate
CI Blocking
--fail-on
运行时权限验证
漏洞利用证明
```

这些能力需要单独的 P2-15B、运行时验证和生产策略任务。
