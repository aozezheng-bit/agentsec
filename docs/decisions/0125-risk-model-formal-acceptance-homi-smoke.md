# ADR-0125：Risk Model Formal Acceptance 与 Homi Installed-CLI Smoke

- 日期：2026-09-05
- 状态：Accepted（本地 Candidate；未发布）
- 任务：RISK-10A

## 背景

RISK-09A 已完成 Context-aware Rule 与固定语料校准，但单元测试和源码回放不足以证明
安装后的 Wheel 能运行同一条 Homi 风险链。正式 Candidate 前必须把以下证据绑定到同一次
可复现验收：固定语料回放、Homi CLI 输出、HTML 报告、Context Finding、Directional
Drift、包指纹和 Authority Boundary。

## 决策

新增 `scripts/run-risk-model-acceptance.py`。脚本只运行静态、只读、离线命令：

```text
agentsec version
agentsec homi fingerprint
agentsec homi report baseline
agentsec homi report scenario-08/10/12 --baseline-dir baseline
RISK-09 deterministic replay
```

正式 Smoke 必须验证：

- Baseline 为 `0.0` 且无 Risk Finding；
- Scheduled Mailbox 为 `CTX-RISK-002 / 8.0 high`；
- Autonomous External Send 为 `CTX-RISK-008 / 5.5 medium`；
- Approval Policy Disable 为 `CTX-RISK-003/006 / 8.0 high`；
- Current Risk 与 Directional Drift 分数一致；
- JSON、Markdown、HTML 报告均生成；
- `report_only=true`、`runtime_verified=false`、`ci_blocked=false`；
- 不访问网络，不执行扫描内容。

Candidate Reconciliation 的隔离 Wheel Smoke 同步增加 Homi Context Risk、Directional Drift
和 HTML 报告校验。Candidate 必须由排除 `.git`、`.venv`、Cache、Build、Dist 的临时源码
副本构建，并执行双构建字节一致性检查。

## 权限边界

验收通过只证明静态风险模型和安装包技术链路一致。它不证明运行时工具权限、OAuth、身份、
调度器或可利用性，不授予发布、Policy、CI 或 Runtime Authority。
