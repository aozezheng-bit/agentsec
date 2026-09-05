# ADR-0122：Snapshot 纳入 Operation Context、Context Finding 与 Context Score 摘要

- 日期：2026-09-04
- 状态：Accepted（本地候选；未提交、未发布）
- 任务：RISK-08B

## 背景

Snapshot 0.2 只绑定文件、能力、人格、旧 `HOMI-COMB-*` Finding、Policy Observation 和
Coverage。RISK-03/04/05 已成为统一风险权威链，但其 Operation Context、Context Finding
和量化结果不在 Snapshot 中。

结果：同一 Snapshot 无法说明“当时识别了什么操作、命中了什么上下文风险、风险分如何
形成”；Context Baseline 需要额外 Sidecar 才能验证，身份快照和风险快照脱节。

## 决策

Snapshot 0.3 必须绑定三类值最小化摘要：

1. **Operation Context Summary**
   - Operation ID；
   - Action、Target、Data Classification/Sharing/Retention；
   - Trigger、Purpose、Authorization、Reversibility、Scope、Frequency、Status；
   - 按 `present/absent/unknown/not_applicable` 分组的控制名称；
   - Evidence ID。
2. **Context Finding Summary**
   - Finding ID、Rule ID、Kind、Category；
   - Likelihood、Impact、Severity、Evidence Confidence；
   - Context ID、Evidence ID、Rationale Code。
3. **Context Score Summary**
   - Model Version、Coverage、Unknown Dimensions；
   - Potential Impact、Residual Risk；
   - Current Posture、可空 Current Posture Score；
   - Score Contribution Count。

同时保存并纳入 Snapshot Digest：

```text
operation_context_sha256
context_risk_report_sha256
context_score_report_sha256
```

## 构建与绑定

`build_homi_snapshot()` 必须接收 Pilot-bound `HomiOperationContextReport`：

```python
build_homi_snapshot(
    pilot_report,
    subject_id="homi:agent:<immutable-id>",
    operation_context=operation_context_report,
)
```

若 `operation_context.source_report_sha256` 不等于 Pilot JSON SHA-256，失败关闭。Snapshot
内部重新运行确定性 RISK-04/05，避免接受调用者伪造的 Finding 或 Score。

统一 Risk 使用 Snapshot 内 Context Digest 校验 Baseline Context：

- Pilot 摘要匹配；
- Operation Context Digest 匹配；
- 重放得到的 Context Risk Digest 匹配；
- 重放得到的 Context Score Digest 匹配。

任一不一致 → 拒绝 Risk Drift。

## Drift 语义

Snapshot Verification 和 Layered Drift 增加：

```text
operation_context_changes
context_finding_changes / context_findings_added / context_findings_removed
context_score_changed
```

Context Digest 差异进入 Baseline Binding。上下文或评分变化可独立解释，不再只能从文件变化
间接猜测。

## 数据最小化

Snapshot 不包含：

- 原始 Markdown 文本或摘录；
- Secret、Token、Credential 值；
- URL、IP、Avatar；
- 用户消息或长期记忆正文；
- LLM Prompt/Response；
- Runtime Log。

Snapshot 只保存枚举、稳定 ID、摘要、计数和分数。

## 权限边界

- Snapshot 仍为 `report_only=true`；
- 静态摘要不产生 `runtime_verified`；
- Snapshot 不授权 Tool/OAuth/Permission；
- Snapshot 不认证 `subject_id` 归属；
- Snapshot 不修改 Policy、Hard Gate 或 CI；
- Context Score 是确定性静态风险证据，不是实际损失概率。

## 版本影响

```text
Homi Snapshot      0.2.0 → 0.3.0
Homi Drift Report  0.2.0 → 0.3.0
Homi Risk Report   0.3.0 → 0.4.0
```

旧 Snapshot 不包含 Context 摘要，不能自动补齐或猜测。必须从相同 Agent Workspace、稳定
`subject_id` 和当前引擎重新创建 Baseline。
