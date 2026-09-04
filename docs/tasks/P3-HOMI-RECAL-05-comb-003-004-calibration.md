# P3-HOMI-RECAL-05：HOMI-COMB-003 / HOMI-COMB-004 重新校准

- 日期：2026-09-03
- 状态：本地实现完成；Homi 端复核待发布审批
- 目标：减少初始化模板造成的误报，同时保留原始静态证据和审计可追溯性。

## 兼容性策略

不直接重写冻结的 Homi Pilot `0.2.0` JSON。新增：

```text
homi-calibration.json
```

它绑定原始 Pilot JSON 的 SHA-256，记录每个原始 Finding 的：

- `retained` / `suppressed`；
- 稳定 `rationale_code`；
- 校准理由；
- 原始 Finding ID、Rule ID、相关信号。

这样既能提供新的校准视图，也不会破坏 P2 外部证据的历史回放。

## HOMI-COMB-003

原始规则：

```text
USER.md persistence + persistent memory
```

校准后：

- `USER.md` 被识别为模板时，抑制 Finding；
- 空字段、占位字段、`Update this as you go` 等模板话术不证明真实用户资料；
- 仅在报告显示非模板 USER.md 且明确存在持久化声明时保留；
- 保留理由码：`user-profile-non-template-persistence`；
- 抑制理由码：`user-profile-template-only`。

## HOMI-COMB-004

原始规则：

```text
SOUL.md self-evolution + IDENTITY.md self-assignment
```

校准后：

- 仅有 `This file is yours to evolve`、`Make it yours`、`Fill this in` 等模板
  话术时，不能证明控制文件可写；
- 没有 `control_file_self_modification` 明确信号时抑制；
- 存在明确控制文件修改声明时保留，但仍标记为静态、运行时未验证；
- 抑制理由码：`persona-identity-template-only`；
- 保留理由码：`explicit-control-file-modification`。

## 权限边界

该校准只改变“当前展示视图是否采纳该静态组合 Finding”，不改变：

- 原始 Finding 的 Severity；
- 潜在影响分；
- Evidence Confidence；
- `runtime_verified=false`；
- Report-only；
- CI / Hard Gate 决策。

## 本地验证

```text
Homi + Provenance + Operationality + Posture + Calibration 定向测试：82 passed
```

P3-HOMI-RECAL-06 负责把各 Sidecar 纳入最终展示闭环，并输出待发布校验清单。
