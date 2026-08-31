AgentSec Homi 真实项目仅报告试点
Pilot：pr-10-tools-coverage-missing
项目：Homi PR Snapshot pr-10-tools-coverage-missing
状态：partial
模式：external_report_only；不可用于验收；不阻断 CI

覆盖情况
  扫描完整：True
  能力画像完整：False
  六类标准文件均存在：False
  解析状态：partial

组合风险
  Findings：3
  Rule Failures：0

安全模拟
  声明路径：3
  Unknown 覆盖：1
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
