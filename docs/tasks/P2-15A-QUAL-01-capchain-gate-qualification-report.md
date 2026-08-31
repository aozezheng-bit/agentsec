# P2-15A-QUAL-01：HG-CAPCHAIN-001 Gate Qualification Report

> **Superseded (P2-EXIT-05).** The v1 artifact
> `hg-capchain-001-qualification-report.json` produced by this task is
> superseded by
> `calibration/p2-15a-capchain-40/human-evidence/hg-capchain-001-qualification-report-v2.json`
> (P2-15A-QUAL-02 confidence recalculation). The v1 report is historical and
> immutable; it grants no Gate authority. Only the pinned v2 report bound to
> the Qualified Gate Registry (ADR-0062) carries qualification evidence.

- Task ID: `P2-15A-QUAL-01`
- Status: Complete — Report-only qualification not yet eligible
- Date: 2026-08-24
- Gate: `HG-CAPCHAIN-001`
- Rule: `CAP-CHAIN-001`
- Evidence scope: `calibration/p2-15a-capchain-40/human-evidence/`

## 1. 执行命令

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec

PYTHONPATH=src .venv/bin/python \
  scripts/qualify-capchain-subset.py
```

输出：

```text
Gate: HG-CAPCHAIN-001
Status: more_data_required
Report-only eligible: False
Precision: 1.0
Recall: 1.0
Confidence calibration: 0.0
```

## 2. 评估方法

Qualification Runner 读取：

```text
calibration/corpus
calibration/p2-15a-capchain-40/selection.json
calibration/p2-15a-capchain-40/human-evidence/human-capchain-40-resolutions.json
calibration/p2-15a-capchain-40/human-evidence/human-capchain-40-confidence.json
calibration/p2-15a-capchain-40/human-evidence/human-capchain-40-adjudications.json
```

它通过受控的 Reviewer Case blind-ID 映射回已验证的 Corpus Case，然后使用
`DeterministicFactBundleEvaluator` 重放 `CAP-CHAIN-001` 的事实条件：

```text
execute + secret-access + external-network
```

Qualification Runner：

- 不执行 Fixture、Source View、脚本、Hook、Skill 或 MCP；
- 不连接网络；
- 不调用 LLM；
- 不把 Ground Truth 直接作为人工标签；
- 仅将确定性 Detector 的重放结果与最终 Human Resolution 对比；
- 由确定性逻辑计算 TP/FP/FN/TN；
- 不修改 Rule、Risk Model 或 Hard Gate 配置。

## 3. 样本与 Coverage

| 指标 | 结果 |
|---|---:|
| Case 总数 | 40 |
| Human Positive | 20 |
| Human Negative/Near-miss | 20 |
| Positive 样本要求 | 20 |
| Negative/Near-miss 样本要求 | 20 |
| Coverage complete | `true` |
| Relevant Unknown free | `true` |
| Adjudication rows | 5 |

样本量和 Coverage 条件通过。

## 4. Detector 混淆矩阵

| | Human Match | Human No-match |
|---|---:|---:|
| Detector Match | TP=20 | FP=0 |
| Detector No-match | FN=0 | TN=20 |

| 指标 | 结果 | 门槛 | 状态 |
|---|---:|---:|---|
| Precision | 1.0 | >= 0.95 | Pass |
| Recall | 1.0 | >= 0.90 | Pass |
| F1 | 1.0 | — | — |
| False Positive Rate | 0.0 | — | — |

在这 40 条合成静态 Case 上，Detector 与最终人工 Match/No-match 判断完全一致。

## 5. Reviewer Agreement 与 Confidence

| 指标 | 结果 |
|---|---:|
| Reviewer Confidence Agreement | 40/40 |
| Reviewer Confidence Kappa | 1.0 |
| Correlation Agreement（裁决前） | 35/40 = 0.875 |
| Correlation Kappa（裁决前） | 0.466667 |
| Correlation Agreement（裁决后） | 40/40 |
| Human Confidence 分布 | A=40 |
| Detector Match Confidence 分布 | B=20 |
| Human vs Detector Confidence Agreement | 0/20 = 0.0 |

## 6. Qualification 结论

当前 Qualification 结论为：

```text
status = more_data_required
eligible_for_report_only_gate = false
```

唯一阻断原因：

```text
confidence-calibration-below-threshold
```

原因是：

```text
Reviewer 最终 Confidence：A
Deterministic CAP-CHAIN-001 静态 Match Confidence：B
Human vs Detector Confidence Agreement：0%
```

根据项目 Confidence Model：

```text
A = Runtime attestation or reproducible runtime evidence
B = Same normalized target with direct source provenance
```

当前输入是静态合成 Source View，没有 Runtime Attestation，因此静态 Rule 的
Detector Confidence 为 B。Reviewer A/B 虽然彼此高度一致，但共同给出 A，说明
Reviewer Confidence 与项目 Confidence 定义尚未校准。

本结论不是 Detector 误报或漏报：

```text
Precision = 1.0
Recall = 1.0
```

而是 Evidence Confidence 语义校准未通过。不能为了让 Gate 通过而直接修改人工
评审结果或篡改 Confidence 定义。

## 7. 当前安全边界

```text
formal_human_evidence = true
gate_qualification = false
hard_gate = false
ci_blocking = false
fail_on = false
runtime_capability_verified = false
llm_used = false
```

## 8. 下一步建议

需要先完成 Evidence Confidence 校准，再重新运行 Qualification：

1. 向两位 Reviewer 明确 A/B/C/D 的项目定义；
2. 使用相同 40 条 Case 或新增小规模校准集重新确认 Confidence；
3. 重点修复“静态同 Target 直接证据被标为 A”的系统性偏差；
4. 保留原始 A/B 提交，不覆盖历史证据；
5. 生成新的 Human Confidence artifact；
6. 重新运行 `P2-15A-QUAL-01`。

只有当 Confidence 校准达到内部目标（当前设定为 >=90%）后，才可以重新评估
Report-only Gate 资格。

即使 Qualification 通过，也不会自动启用：

```text
hard_gate=true
--fail-on
CI Blocking
生产权限阻断
运行时漏洞验证
```
