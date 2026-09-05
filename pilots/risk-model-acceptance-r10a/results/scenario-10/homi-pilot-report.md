AgentSec Homi 真实项目仅报告试点
Pilot：homi-cli-pilot
项目：scenario-10
状态：complete
模式：external_report_only；不可用于验收；不阻断 CI

风险口径
  原始静态潜在影响最高分：5.5
  最高潜在影响分：5.5
  当前安全态势：静态活跃/未验证
  当前态势分：尚未建立（没有运行时证明）
  校准后 Findings：1/1；抑制：0

覆盖情况
  扫描完整：True
  能力画像完整：True
  六类标准文件均存在：True
  解析状态：resolved

Unknown 指标（口径分离）
  能力 Unknown：16
  能力 example_only：0
  标准文件缺失：0
  运行时 Unknown：未采集运行时证明
  Manifest Unknown：本报告未提供 Manifest

组合风险
  校准后 Findings：1
  Rule Failures：0

安全模拟
  声明路径：1
  Unknown 覆盖：3
  示例阻断：0
  静态边界阻断：1
  已执行：false
  已产生副作用：false
  已完成运行时验证：false

限制
  - This is an external report-only Pilot; acceptance_ready is always false.
  - The target workspace is untrusted input and no project code, hooks, skills, commands, MCP, or scheduler was executed.
  - Static Homi declarations do not prove runtime Tool, OAuth, permission, identity, scheduler, or exploit reachability.
  - No raw User, tool, credential, IP address, URL, Avatar, or Secret value is included in the report.
  - Human review and real runtime attestation are outside this Pilot run.
