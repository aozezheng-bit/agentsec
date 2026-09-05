# ADR-0120：统一 Homi Risk 由 Operation Context 风险链负责

- 日期：2026-09-04
- 状态：Accepted（本地候选；未发布）
- 任务：RISK-08

## 背景

旧版 `agentsec homi risk` 直接使用 `HOMI-COMB-*` 能力组合 Finding 的最高分作为
`risk_score`。该口径会把网络、记忆、人格或静态能力声明直接靠近风险结论，未消费
RISK-03 Operation Context、RISK-04 上下文规则和 RISK-05 控制后残余风险。

这与当前风险模型不一致：能力存在不是风险；风险需要操作、目标、数据、触发方式、
目的、授权、控制和影响的组合证据。

## 决策

1. `HomiRiskReport.risk_score` 固定等于 RISK-05 `residual_risk_score`。
2. `risk_level` 固定等于 RISK-05 `residual_risk_level`。
3. RISK-03 的 Pilot-bound `HomiOperationContextReport` 成为必需输入；来源摘要不匹配时失败关闭。
4. RISK-04 Finding 以值最小化摘要进入统一报告，保留 Rule、Finding、Context、Evidence、Confidence、控制覆盖和分数贡献。
5. 旧 `HOMI-COMB-*` 结果保留为 `declaration_signal_*`，仅表示静态声明信号，不参与权威风险分。
6. 无风险 Finding 时 `evidence_confidence=null`，避免给不存在的风险伪造置信度。
7. 静态输入下 `current_posture_score=null`；静态文本不证明运行时可达性。
8. 数值 Risk Drift 只在同时提供以下绑定产物时计算：
   - baseline Homi Snapshot；
   - 其 `source_report_sha256` 完全匹配的 baseline Operation Context。
9. 只有 Snapshot 没有 Context Baseline 时，文件/能力漂移仍报告，但 `drift_risk_score=null`，不伪造零风险。
10. 输出继续固定 `report_only=true`、`runtime_verified=false`、`ci_blocked=false`。

## 影响

- `HOMI_RISK_REPORT_VERSION` 从 `0.1.0` 升至 `0.2.0`。
- Python API 必须显式传入 `operation_context`。
- CLI 会从同一 Workspace 重新执行安全静态提取，并验证 Pilot 绑定。
- `--baseline-context` 与 `--baseline` 配对后才产生 Context Risk Drift。
- RISK-09/10 中以 `HOMI-COMB-*` 和旧分数为真值的断言必须独立重新校准，不能继续证明新版统一风险模型。

## 未包含

- 稳定 `subject_id` / Workspace 身份绑定；
- Operation Context 写入 Snapshot；
- Runtime Attestation 改写静态 Risk Score；
- LLM 进入评分、策略或 CI 决策；
- 自动阻断或身份认证决定。
