# P2-15A-PILOT-03：Shadow Gate Demo、Coverage 统计和 Match/No-match 报告

- Task ID: `P2-15A-PILOT-03`
- Status: Complete for source development / Shadow-only
- Completion date: 2026-08-24
- Gate: `HG-CAPCHAIN-001`
- Demo Report Schema: `0.1.0`
- Enforcement mode: `report_only`
- CI blocking: disabled

## 1. 目标

为 P2-15A-PILOT-02 提供一个可以现场运行、可以复核、可以展示的技术 Demo，
同时输出：

```text
1. Shadow Gate 的实时命中与未命中场景；
2. P2-CAL-04A Gate Coverage 统计；
3. Matrix 中的期望 Match/No-match 分布；
4. Shadow-only、report-only 和 no-CI-blocking 边界。
```

## 2. 运行方式

中文现场演示：

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec
./scripts/run-shadow-gate-demo.sh --language zh --format text
```

英文 JSON 报告：

```bash
./scripts/run-shadow-gate-demo.sh \\
  --format json \\
  --output /tmp/agentsec-shadow-gate-demo.json
```

也可以直接运行 Python CLI：

```bash
PYTHONPATH=src .venv/bin/python scripts/run-shadow-gate-demo.py \\
  --corpus calibration \\
  --format json
```

输出文件使用 `O_EXCL` 和 `0600`，不会覆盖已有文件。

## 3. 实时 Shadow Gate 场景

Demo 使用临时目录中的惰性静态数据构造 Manifest，不执行任何项目代码、脚本、
Skill、Hook、MCP 或网络请求。当前包含 5 个场景：

| 场景 | 预期 | 说明 |
|---|---|---|
| `same-target-match` | Match | execute、secret-access、external-network 在同一目标 |
| `parent-child-match` | Match | 三项能力分布在同一父子工具族 |
| `agent-wide-no-match` | No-match | Agent-wide 声明不能证明目标可达链路 |
| `unknown-no-match` | No-match | 相关 Unknown 阻断命中 |
| `incomplete-coverage-no-match` | No-match | Coverage 不完整阻断命中 |

当前演示预期结果：

```text
demo_match_count = 2
demo_no_match_count = 3
```

每个场景报告：

```text
expected_match
actual_match
passed
finding_correlation
rejection_reason / rejection_reasons
coverage_complete
relevant_unknowns
related_ids
gate_id / gate_version / mode / qualification / blocks
risk_unchanged
```

## 4. Coverage 和 Match/No-match 统计

Coverage 统计复用现有的有界 Coverage Check：

```text
scripts/check-gate-calibration-coverage.py
```

它会验证 Corpus、Matrix、Semantic Fingerprint、Case 绑定、Coverage、Unknown、
Source Asset 和 Gate 定义，然后只选取：

```text
HG-CAPCHAIN-001
```

当前矩阵统计：

```text
期望 Match：25
期望 No-match：25
其中 Eligible No-match：21
Unknown Boundary：4
Eligible Positive：25
Eligible Negative/Near-miss：21
Coverage Status：ready
```

矩阵中的 Match/No-match 是校准语料的期望元数据，当前仍为 `seeded`，不是
独立 Reviewer 的真实结论，也不是正式 P2-CAL-04 Human Evidence。

## 5. 输出边界

Demo 报告固定声明：

```text
format = agentsec-capability-shadow-gate-demo
schema_version = 0.1.0
mode = shadow
qualification = pilot_only
blocks = false
hard_gate_enabled = false
fail_on_enabled = false
ci_blocking_enabled = false
runtime_capability_verified = false
global_safety_claimed = false
```

Coverage 不足时命令可返回 `2`，表示数据不完整；这不是风险阻断，也不是 CI
授权决策。输入格式或安全校验失败返回 `4`，Demo 契约失败返回 `5`。

## 6. 明确不代表的内容

本 Demo 不证明：

```text
运行时 Tool 存在且可达
OAuth Scope 有效
真实 Permission 已授权
Agent 可以成功执行操作
存在实际漏洞或可利用路径
正式 P2-15A Gate 已获批准
生产 Hard Gate 已启用
```

## 7. 后续工作

完成真实独立 Reviewer A/B、Adjudication 和 Human Evidence 后，才可以将本
Demo 的 Coverage 统计与正式评审结果进行对照，评估：

```text
Precision
Recall
False Positive / False Negative
Evidence Confidence
Coverage / Unknown Rate
```

本任务不启用 `hard_gate=true`、`--fail-on`、CI Blocking 或 P2-15B。
