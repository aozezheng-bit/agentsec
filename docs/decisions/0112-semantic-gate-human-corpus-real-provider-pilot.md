# ADR-0112：Semantic Gate Human Corpus 与 Real Provider Pilot

- **日期**：2026-09-01
- **状态**：Accepted for implementation

## Context

P3-18 已定义 Semantic Gate 的质量和证据资格，但示例资格报告仍缺少 Gate-specific
人工语料和当前 Provider 试验绑定。直接把已有 Fixture 指标当作真实质量结论会形成
自证循环；直接外呼又可能绕过端点、费用、数据驻留、保留策略和凭据审批。

## Decision

1. 每个 Gate 使用独立的 Digest-bound Human Corpus；
2. Corpus 只保留脱敏 Evidence，不执行其中的命令、Hook、Skill、MCP 或脚本；
3. Positive 至少 20 条，Eligible Negative/Near-miss 至少 20 条，Unknown 和未裁决
   Case 不得进入资格结论；
4. Review Submission 与 Adjudication 必须绑定 Corpus Digest；
5. Real Provider Pilot 默认关闭，只有显式 `--allow-live` 且通过所有组织审批才可外呼；
6. Pilot 每个 Case 至多一次调用，并且只能输出 Shadow/Report-only Evidence；
7. LLM/Provider 质量资格与 Gate/CI/Rule/Release 授权严格分离。

## Consequences

- 可以先在无网络、无凭据环境运行 Schema、Digest、Coverage 和 preflight 测试；
- 真实 Provider Pilot 需要组织外部输入，不得由代码或测试伪造“真实质量”；
- 真实指标必须在当前 Corpus、Candidate、Prompt 和 Model 版本下重新计算；
- 后续若要提升权限，必须新增 ADR、独立资格证据和确定性授权路径。
