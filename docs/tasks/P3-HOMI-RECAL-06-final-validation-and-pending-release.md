# P3-HOMI-RECAL-06：最终验证与待发布清单

- 日期：2026-09-03
- 状态：干净候选已提交；本地验证和 Release Provenance 已完成；Homi 远端验证/发布明确挂起

## 本轮交付

- `agentsec homi fingerprint --format json|text`
- Homi 报告目录新增 `homi-build-fingerprint.json`
- Homi 报告目录新增 `homi-operationality.json`
- Homi 报告目录新增 `homi-posture.json`
- Homi 报告目录新增 `homi-calibration.json`
- HEARTBEAT 模板回归保持通过
- `HOMI-COMB-003` / `HOMI-COMB-004` 校准以 Sidecar 方式输出
- Homi Skill 增加指纹、Operationality、Posture、Calibration 使用说明
- `homi bundle` 自动消费同目录且 SHA-256 绑定的 Sidecar，并在联合报告中使用校准视图
- 未修改冻结的 Homi Pilot `0.2.0` 历史 JSON，保持历史回放兼容
- 建立干净候选分支 `codex/homi-release-candidate-20260903` 并创建本地提交
- 重建 `dist/candidates/0.4.0-p3-rel-01/` 的 Reconciliation、Release Manifest、Provenance Bundle 和校验文件

## 本地验证结果

```text
Homi 定向测试（候选代码）：22 passed
全仓测试：1634 passed
Ruff 全仓 lint：passed
Ruff 全仓 format check：passed
Mypy strict：passed（382 source files）
Byte-level Reconciliation：reconciled；wheel/sdist/schema/metadata 全部匹配
Reproducible build：passed（Source Date Epoch=0，双构建字节一致）
Release Manifest / Provenance Bundle：created；report_only=true
候选 Wheel：agentsec-0.4.0-py3-none-any.whl
候选 Wheel SHA-256：6b045e11f37ccb3acaf0a9ee11d005b986bacb24ae3b5748af49269367776d96
Wheel-target 安装后 fingerprint：passed；package_digest 与源码读取一致

安全边界：network_accessed=false；scanned_content_executed=false；
runtime_verified=false；CI/publication authority=false
```

## 当前候选证据

- Reconciliation：`dist/candidates/0.4.0-p3-rel-01/reconciliation-report.json`
- Release Manifest：`dist/candidates/0.4.0-p3-rel-01/release-manifest.json`
- Provenance Bundle：`dist/candidates/0.4.0-p3-rel-01/provenance-bundle.json`
- 候选包和 Source Inventory 已绑定；历史 `dist/0.4.0/` 候选未被覆盖。
- 当前候选只在本地存在，未推送 GitHub，未安装到真实 Homi，也未执行真实 Homi Workspace 内容。

## 发布前仍需完成

1. 获得明确的 Homi 安装/试点审批；
2. 在隔离 Homi 测试 Workspace 安装**同一 SHA-256 Wheel**；
3. 执行 `agentsec homi fingerprint --format json`，并核对：
   `package_version`、适配器/画像/规则包版本、`build_commit`、
   `implementation_digest`、`package_digest`；
4. 对纯模板 Heartbeat、真实 Heartbeat 任务、USER 模板校准、真实用户资料和身份初始化模板各执行一次 Smoke Test；
5. 确认 Homi 端仍为 `report_only=true`、`runtime_verified=false`、`ci_blocked=false`；
6. 通过审批后，再决定是否推送 GitHub 或发布 Homi Skill/包。

在上述 Homi 端审批和核对完成前，`agentsec 0.4.0` 只能称为“本地已验证候选”，不能声称 Homi 远端已经同步、运行时能力已经证明或生产可用。
