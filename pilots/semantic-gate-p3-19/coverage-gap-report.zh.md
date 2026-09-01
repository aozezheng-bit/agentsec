# P3-19 Corpus Coverage Gap Report

- 生成日期：2026-09-01
- Gate：`SG-INSTRUCTION-INTEGRITY-001`
- Final Corpus：`semantic-gate-human-corpus-sha256:6d29a8ae28dc12a29732fdad65784f0ada54967ccf131f0fa80dce79b2ef5e10`

## 当前统计

| 指标 | 当前值 | 要求 | 状态 |
|---|---:|---:|---|
| Case 总数 | 40 | 40 | 通过 |
| Positive | 19 | >= 20 | 未通过 |
| Eligible Negative | 20 | >= 20 | 通过 |
| Near-miss | 1 | 可计入 Negative/Near-miss | 通过 |
| Eligible Negative + Near-miss | 21 | >= 20 | 通过 |
| Unknown | 0 | 0 | 通过 |
| Unresolved | 0 | 0 | 通过 |
| Reviewer 数量 | 2 | >= 1 | 通过 |

## 结论

当前 Corpus 不能直接满足 P3-18 Candidate 的最小 Positive 条件，因为缺少 1 条
Positive。虽然总样本为 40，Negative/Near-miss 覆盖为 21，但 Positive 只有 19。

因此当前状态应保持：

```text
conditionally_qualified / not eligible for report-only Gate
```

不要通过把 `p3-19-15` 从 Near-miss 强行改为 Positive 来满足数量要求。它属于 Gate
定义范围的真实边界争议，应由项目负责人明确裁决；如果 Gate 仍然是
Instruction Integrity，建议保留为 Near-miss，并新增 1 条独立 Positive Case。

## 最小补充方案

新增 1 条经过两位专家独立评审的 Positive Case，推荐主题：

```text
Heartbeat / 外部输入 / 审批边界被明确绕过
```

新增 Case 必须：

- 使用新的 Case ID，例如 `p3-19-41`；
- 有独立 Evidence Digest；
- 不能复用已有 Case 的文本或 Digest；
- 先分别发给 Reviewer A/B；
- 新增结果同样记录 `expected`、Confidence 和理由码；
- 若 A/B 分歧，再单独 Adjudication；
- 不修改已有 40 条 Case 的历史判断。

补充完成后，预计：

```text
Positive: 20
Eligible Negative + Near-miss: 21
Case total: 41
```

此时仍需重新运行 Provider Pilot。不能复用旧的 45 Case 真实 Provider 结果，因为
Corpus Digest 已经变化。
