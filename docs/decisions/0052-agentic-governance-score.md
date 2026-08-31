# ADR-0052：Agentic Governance Score 0.1.0

- Status: Accepted
- Date: 2026-08-24
- Task: P2-22（Agentic Risk Track）
- Governance Score Model: `0.1.0`
- Agentic Factor Model: `0.1.0`
- Threat/Mitigation Model: `0.1.0`
- Drift Score Model: `0.1.0`

## Context

Technical Score 表达技术能力暴露，Drift Score 表达相对基线的变化风险。还需要一个
独立的 Governance Score 表达控制成熟度、Coverage、审批、Baseline Trust、变更评审、
部署范围、责任归属和 Waiver 生命周期风险。

治理上下文不能从静态文件中全部推断。没有统一 Policy Owner、Approval Owner、Waiver
系统或签名 Baseline 时，调用方必须显式提供上下文，未知状态不能被当作治理成熟。

## Decision

1. Governance Score 是治理风险分数：

   ```text
   分数越高 = 治理风险越高
   ```

2. 固定八个治理贡献维度：

   ```text
   control_maturity
   coverage
   approval
   baseline_trust
   change_review
   deployment_scope
   ownership
   waiver
   ```

3. Control Maturity 使用 P2-19 Mitigation State：

   | State | Points |
   |---|---:|
   | not_applicable | 0.0 |
   | declared | 0.2 |
   | absent | 0.8 |
   | disabled | 1.0 |
   | unknown | 1.0 |

   静态 declared Control 仍不是运行时证明。

4. 其他上下文贡献使用版本化、可追溯的 AgentSec Policy Points。所有贡献相加后上限
   为 `10.0`，并采用现有 Severity 映射。
5. Governance Context 必须支持：

   ```text
   DriftScoreContext
   review_status
   policy_owner
   approval_owner
   waiver_count
   expired_waiver_count
   ```

6. `approved` Approval 必须带 `approval_reference`；Owner 必须是有界稳定标识符；
   `expired_waiver_count` 不得大于 `waiver_count`。
7. 缺少 Owner、Unknown Review、Unknown Baseline、Incomplete Coverage 和 Unknown
   Control 都增加治理风险，不自动按安全处理。
8. Governance Score 不修改 Technical Score、Drift Score、Finding Severity、Confidence、
   Hard Gate 或 CI Decision。
9. Governance Score 单独版本化为：

   ```text
   agentsec-governance-score / 0.1.0
   ```

## Security boundaries

- 治理声明不等于运行时权限收敛；
- 审批状态不等于 Tool/OAuth/Permission 可达性证明；
- Owner 不等于真实身份认证；
- Waiver 计数不自动覆盖 Finding；
- 不执行扫描项目、脚本、Skill、Hook、MCP 或命令；
- 不访问网络、环境变量或运行时权限；
- 不启用 Hard Gate 或 CI Blocking；
- LLM 不参与治理授权。

## Consequences

### Positive

- 技术风险、漂移风险和治理风险分离；
- 治理缺口可被单独审计；
- Owner、审批和 Waiver 生命周期可以在 P2-27/P2-28 继续接入；
- Unknown 和不完整 Coverage 不会产生干净治理结论。

### Limitations

- 当前 Owner、Review、Waiver 是显式上下文输入，不连接组织系统；
- 当前没有签名 Baseline；
- Governance Score 尚未进入 Overall Score；
- 当前 Score Points 需要 P2-24 回放和 P2-30/P2-31 试点校准。
