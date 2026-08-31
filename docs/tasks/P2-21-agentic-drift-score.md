# P2-21：Drift Score（Agentic Risk Track）

- 状态：完成
- 日期：2026-08-24
- 依赖：P2-13 Capability Change Impact、P2-20 Technical Score

> 说明：仓库历史中已有一个同名 P2-21：CVSS Temporal/Environmental/Threat/Supplemental。
> 本任务是原始 Agentic Risk 评分路线中的 Drift Score，使用独立的
> `DRIFT_SCORE_MODEL_VERSION=0.1.0`，不修改既有 CVSS Extended Metrics。

## 目标

根据 Capability Diff、可选 Change Impact、变化来源、审批状态、部署范围和 Baseline
Trust，计算一个确定性 Drift Score。

## 产出

```text
src/agentsec/risk/drift_score.py
src/agentsec/risk/__init__.py
src/agentsec/versioning.py
tests/test_drift_score.py
docs/decisions/0051-agentic-drift-score.md
```

## 输出

格式：

```text
agentsec-drift-score / 0.1.0
```

包含：

- Before/After Manifest SHA-256；
- Capability Diff Schema；
- 变化数量；
- 增加暴露和不确定变化数量；
- 每项变化贡献；
- Gross Change Score；
- Profile Change Score；
- Context Multipliers；
- Drift Score；
- Severity；
- Value-free Evidence。

## 验收标准

- [x] Capability Diff 变化有维度、类型、字段、方向和分值；
- [x] 可选 Change Impact 能覆盖更准确的方向；
- [x] Control 新增默认不直接判定为 increased；
- [x] Control 删除默认判定为 increased；
- [x] Source/Approval/Deployment/Baseline 上下文显式输入；
- [x] Approved 必须有 approval_reference；
- [x] Incomplete Coverage 有最低分 5.0；
- [x] Before/After Evidence 哈希不混淆；
- [x] Manifest/Capability Diff 绑定校验；
- [x] JSON 输出不包含原始 Source Value；
- [x] 不修改 CVSS Extended Metrics、Technical Score、Hard Gate 或 CI 行为。

## 未包含内容

```text
P2-22 Governance Score
P2-23 Overall Score / Hard Gate
P2-24 Scoring Replay
```
