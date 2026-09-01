# ADR-0113：Provider Evaluation Import 与 Semantic Gate Qualification

- **日期**：2026-09-01
- **状态**：Accepted

## Context

P3-19 已建立 41 Case Gate-specific Human Corpus 和 fail-closed Real Provider Pilot。
但 Pilot Evaluation 需要绑定当前 Candidate、Corpus、Provider、Model 和 Prompt Contract，
否则历史 Evaluation 或不同 Gate 的结果可能被错误复用。

## Decision

1. Provider Evaluation 必须通过 `SemanticGateEvaluationImport` 进入 Gate Qualification；
2. Import 必须绑定 Candidate ID、Corpus ID/SHA、Evaluation SHA、Provider/Model 和当前
   Prompt Contract；
3. Case ID 集合必须与 Human Corpus 完全一致；
4. Draft、Unknown、Unresolved Corpus 不能进入 Evaluation Import；
5. Qualification 只能消费已生成的 Evaluation Report，不重复调用 Provider；
6. Qualification 和 Promotion 仅输出 Report-only Evidence；
7. Provider 质量合格不等于 CI、Rule、Policy、Waiver、Runtime 或 Release 授权；
8. `preflight_blocked`、失败或缺少 Evaluation 的 Pilot 不得被转换成质量报告。

## Consequences

- 旧 Provider Evaluation 不能直接替代当前 Corpus 的新 Evaluation；
- 真实 Pilot 只需生成一份绑定正确的 Report，后续 Qualification 可离线完成；
- Digest 和 Prompt 绑定会增加调用前后的工件管理工作，但避免了证据错配；
- 如果需要 CI Blocking，必须另行设计确定性 Rule / Policy Gate，不能从本任务自动升级。
