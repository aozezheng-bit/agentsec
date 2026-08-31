# P2-22：Governance Score（Agentic Risk Track）

- 状态：完成
- 日期：2026-08-24
- 依赖：P2-18 Agentic Factor、P2-19 Threat/Mitigation、P2-21 Drift Score

> 说明：本任务是 Agentic Risk 评分路线中的 Governance Score，使用
> `GOVERNANCE_SCORE_MODEL_VERSION=0.1.0`，不修改 CVSS Extended Metrics。

## 目标

基于 Control Maturity、Coverage、Approval、Baseline Trust、Change Review、
Deployment Scope、Ownership 和 Waiver 生命周期，计算治理风险分数。

## 产出

```text
src/agentsec/risk/governance_score.py
src/agentsec/risk/__init__.py
src/agentsec/versioning.py
tests/test_governance_score.py
docs/decisions/0052-agentic-governance-score.md
```

## 评分边界

```text
Governance Score 越高 = 治理风险越高
```

Control Maturity 直接消费 P2-19 Mitigation State；静态 declared Control 只获得
有限治理贡献，不被当成 Runtime Enforcement。

## 输出

格式：

```text
agentsec-governance-score / 0.1.0
```

包含：

- Manifest SHA-256；
- Factor / Threat / Drift Model Version；
- Governance Context；
- 八个治理维度贡献；
- Governance Score；
- Severity；
- Owner、Review、Waiver 上下文；
- Value-free Control Evidence；
- Mapping Basis。

## 验收标准

- [x] 八个治理维度都有显式贡献；
- [x] Control Maturity 来自 P2-19 Mitigation State；
- [x] Coverage / Unknown 有治理风险贡献；
- [x] Approved 必须有 Approval Reference；
- [x] Policy Owner / Approval Owner 有界且可审计；
- [x] Waiver 数量和过期数量严格校验；
- [x] Manifest、Factor、Threat Hash 绑定；
- [x] JSON 输出不包含原始 Source Value；
- [x] 不修改 Technical Score、Drift Score、Hard Gate 或 CI 行为。

## 未包含内容

```text
P2-23 Overall Score / Hard Gate
P2-24 Scoring Replay
P2-27 Organization Policy
P2-28 Waiver Enforcement
```
