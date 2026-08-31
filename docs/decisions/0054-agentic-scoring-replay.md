# ADR-0054：Agentic Scoring Replay 0.1.0

- Status: Accepted
- Date: 2026-08-25
- Task: P2-24（Agentic Risk Track）
- Scoring Replay Model: `0.1.0`

## Context

P2-18～P2-23 已形成完整评分链路：

```text
Agent Manifest
→ Agentic Factor
→ Threat / Mitigation
→ Technical Score
→ Drift Score
→ Governance Score
→ Overall Score / Hard Gate
```

每个模型都独立版本化，但只有单模块测试无法证明完整链路在相同输入、上下文和版本下
能够稳定重放。P2-24 需要冻结跨阶段结果，防止权重、公式、序列化、Gate Floor 或
上下文解释发生静默漂移。

## Decision

1. 新增 `ScoringReplayRequest`，显式绑定：

   ```text
   case_id
   before Manifest
   after Manifest
   Drift Context
   Governance Context
   optional CVSS
   qualified Overall Gate matches
   ```

2. `DeterministicScoringReplayRunner` 必须按固定顺序执行 P2-18～P2-23，不得跳过或
   重复解释原始 Source Value。
3. 每个阶段产物使用 canonical SHA-256：

   ```text
   factor_vector
   threat_mitigation
   capability_diff
   technical_score
   drift_score
   governance_score
   overall_score
   ```

4. Replay Result 记录完整独立版本向量。版本不一致时拒绝构造结果。
5. Replay 自身和 Replay Suite 分别生成内容寻址 SHA-256：

   ```text
   replay_sha256
   suite_sha256
   ```

6. 冻结七个回放场景：

   ```text
   safe-no-change
   risky-default
   risky-reviewed
   remediation-drift
   incomplete-coverage
   cvss-high-water
   critical-gate-floor
   ```

7. 冻结文件：

   ```text
   testdata/scoring-replay/expected.json
   ```

8. `scripts/run-scoring-replay.py --check` 必须逐字节验证当前结果与冻结产物一致。
9. Replay Output 只包含分数、版本、上下文、Gate 状态和 Hash，不包含源文件原文、
   Secret、Token、Credential 或 URL 值。
10. P2-24 不修改模型权重和公式，不启用 CI Blocking。

## Security boundaries

- 不执行扫描项目、脚本、Skill、Hook、MCP 或命令；
- 不读取环境变量或 Credential Value；
- 不访问网络；
- 不将 Replay 结果描述为 Runtime Exploitability；
- LLM 不参与评分或 Gate Authority；
- Replay mismatch 必须显式失败，不能自动更新冻结结果；
- 冻结更新必须是人工发起的版本评审行为。

## Consequences

### Positive

- 完整评分链路可以稳定回放；
- 单个模型或上下文变化能够定位到对应 Component Hash；
- CVSS High-Water、Incomplete Coverage 和 Critical Floor 都有冻结回归；
- 后续 SARIF、Policy、CI 和 Release 可以引用固定评分语义。

### Limitations

- 当前回放语料主要来自合成 Capability Drift Demo；
- 冻结 Hash 不是数字签名或供应链证明；
- 权重和公式仍需真实试点数据校准；
- P2-24 不实现 SARIF、`--fail-on`、组织 Policy 或 Waiver Enforcement。
