# P3-HOMI-RECAL-06：最终验证与待发布清单

- 日期：2026-09-03
- 状态：本地验证完成；发布/远端验证明确挂起

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

## 本地验证结果

```text
Homi 定向测试（含历史回放）：82 passed
全仓测试（排除未重建发布候选库存的 2 个测试文件）：1613 passed
Ruff 本轮文件：passed
Ruff 全仓 lint：passed；全仓 format check 仅剩 pre-existing
`scripts/run-homi-mutation-demo.py` 的格式问题，未在本轮混合修改中调整
Mypy 本轮文件：passed
Mypy 全仓：passed（383 source files）
Wheel 构建：passed
Wheel 安装后指纹读取：passed
```

完整 `pytest -q` 当前有 3 个与发布候选库存有关的失败：

1. `test_reconciled_candidate_report_drives_candidate_acceptance`
2. `test_release_manifest_and_bundle_validate`
3. `test_release_bundle_generation_is_deterministic`

原因是当前工作树包含未提交的历史 WIP 与本轮新增源文件，既有
`dist/candidates/0.4.0-p3-rel-01/` 的 Source Inventory 和 Reconciliation
Report 尚未重新生成。该动作会把混合 WIP 纳入候选包，因此没有在本轮直接覆盖或
发布候选产物。

## 发布前必须完成

1. 从当前历史 WIP 中隔离本轮 Homi Recalibration 文件；
2. 在干净候选工作树重新生成 Reconciliation / Provenance Bundle；
3. 固定 `AGENTSEC_BUILD_COMMIT`；
4. 构建 Wheel 并记录 `package_digest` / `implementation_digest`；
5. 在 Homi 端安装相同 Wheel；
6. 执行 fingerprint 对比；
7. 用纯模板 Heartbeat 和真实 Heartbeat 任务各执行一次 Smoke Test；
8. 确认 `HOMI-COMB-003/004` 读取的是校准 Sidecar；
9. 获得发布审批后再同步 GitHub / Homi。

在上述清单完成前，`agentsec 0.4.0` 只能称为本地候选，不能声称 Homi
远端已经同步，也不能声称生产可用。
