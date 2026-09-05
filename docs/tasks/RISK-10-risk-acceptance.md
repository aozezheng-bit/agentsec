# RISK-10：风险模型验收（场景 A~F 与十二条标准）

- 日期：2026-09-05
- 状态：RISK-09A 后本地验收完成（12/12 通过，无 xfail）
- 前置任务：RISK-08、RISK-09、RISK-09A

## 场景 A~F

| 场景 | 语料 | 实测 |
|---|---|---|
| A 默认模板 | scenario-01 | 0.0 none |
| B 只修改欢迎语 | scenario-04 | drifted，漂移风险 0.0 |
| C 保存非敏感偏好 | scenario-06 | 0.0 none |
| D 新增定时读取邮箱 | scenario-08 | CTX-RISK-002，8.0 high |
| E 无审批自动外发 | scenario-10 | CTX-RISK-008，5.5 medium |
| F 删除安全控制 | scenario-12/14 | CTX-RISK-003/006，8.0 high |

## 十二条验收

1. 仅访问互联网不判高风险；
2. 仅保存非敏感偏好不判高风险；
3. 仅人格或身份描述不判自修改风险；
4. 文案变化产生文件漂移，但风险漂移为 0；
5. 定时敏感读取和无审批外发产生可解释风险；
6. 审批移除和控制文件修改进入 High；
7. 相同可信基线漂移为 0；
8. 基线已有风险不重复计入漂移；
9. 文件、能力、人格、Finding、Control、Operation Context 可分别解释；
10. Score、Level、Confidence、Runtime Status 保持分离；
11. 固定语料和 Snapshot Digest 可确定性回放；
12. 所有输出保持 report-only、runtime-unverified、non-blocking。

## 边界

验收为静态报告证据，不证明运行时操作成功，不执行身份认证，不授予 Policy Authority，
不阻断 CI。
