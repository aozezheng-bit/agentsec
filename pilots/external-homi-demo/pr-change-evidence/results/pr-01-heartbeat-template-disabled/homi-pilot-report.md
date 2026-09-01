AgentSec Homi Real-project Report-only Pilot
Pilot: pr-01-heartbeat-template-disabled
Project: Homi PR Snapshot pr-01-heartbeat-template-disabled
Status: partial
Mode: external_report_only; acceptance_ready=false; CI blocking=false

Coverage
  Inspection complete: True
  Profile complete: False
  Standard files present: True
  Resolution: conflict

Unknown Metrics (scoped)
  Capability unknown: 6
  Capability example-only: 3
  Standard files missing: 0
  Runtime unknown: not collected
  Manifest unknown: not supplied to this report

Combination Findings
  Findings: 3
  Rule failures: 0

Safe Simulation
  Declared paths: 3
  Unknown coverage: 0
  Example-only blocked: 1
  Static-boundary blocked: 1
  Executed: false
  Side effects: false
  Runtime verified: false

Limitations
  - This is an external report-only Pilot; acceptance_ready is always false.
  - The target workspace is untrusted input and no project code, hooks, skills, commands, MCP, or scheduler was executed.
  - Static Homi declarations do not prove runtime Tool, OAuth, permission, identity, scheduler, or exploit reachability.
  - No raw User, tool, credential, IP address, URL, Avatar, or Secret value is included in the report.
  - Human review and real runtime attestation are outside this Pilot run.
