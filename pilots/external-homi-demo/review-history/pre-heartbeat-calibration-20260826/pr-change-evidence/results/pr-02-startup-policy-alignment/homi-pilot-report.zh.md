AgentSec Homi 真实项目仅报告试点
Pilot：pr-02-startup-policy-alignment
项目：Homi PR Snapshot pr-02-startup-policy-alignment
状态：complete
模式：external_report_only；不可用于验收；不阻断 CI

覆盖情况
  扫描完整：True
  能力画像完整：True
  六类标准文件均存在：True
  解析状态：resolved

组合风险
  Findings：4
  Rule Failures：0

安全模拟
  声明路径：4
  Unknown 覆盖：0
  示例阻断：1
  静态边界阻断：0
  已执行：false
  已产生副作用：false
  已完成运行时验证：false

限制
  - This is an external report-only Pilot; acceptance_ready is always false.
  - The target workspace is untrusted input and no project code, hooks, skills, commands, MCP, or scheduler was executed.
  - Static Homi declarations do not prove runtime Tool, OAuth, permission, identity, scheduler, or exploit reachability.
  - No raw User, tool, credential, IP address, URL, Avatar, or Secret value is included in the report.
  - Human review and real runtime attestation are outside this Pilot run.
