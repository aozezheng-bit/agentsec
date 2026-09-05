# RISK-09：Risk Replay 固定语料与确定性回放

- 日期：2026-09-05
- 状态：RISK-09A 重校准完成；report-only；未向 Homi 发布
- 前置任务：RISK-08（Snapshot/Drift/Risk 链）、RISK-09A（Context 真值迁移）

## 交付

1. `pilots/risk-replay-r09/`：16 套 Homi 标准六文件 Workspace；
2. `expectations.json`：记录权威 `CTX-RISK-*` 预期和风险方向；
3. `scripts/run-risk-replay.py`：执行 Pilot → Operation Context → Snapshot → Drift → Risk；
4. `replay-summary.json/.md`：记录规则、当前风险、漂移风险和 Authority。

## 回放结果

```text
16/16 scenarios passed
report_only=true
runtime_verified=false
ci_blocked=false
```

关键风险场景：

```text
07 无限期完整对话保留  CTX-RISK-007      8.0 high
08 定时邮箱读取          CTX-RISK-002      8.0 high
10 无审批自动外发        CTX-RISK-008      5.5 medium
12 审批策略移除          CTX-RISK-003/006  8.0 high
14 控制文件自修改        CTX-RISK-003/006  8.0 high
```

良性文案、人格、外观、非敏感偏好和公开网络读取不产生权威风险分。旧 `HOMI-COMB-*` 仅保留
为 Declaration Signal，不再作为 RISK-09 验收真值。

## 边界

- 语料为脱敏纯 Markdown，无真实 URL/IP/Token/私钥；
- 不执行场景内容，不触碰真实 Homi Workspace；
- 静态结果不证明运行时可达性，不阻断 CI。
