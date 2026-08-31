AgentSec Homi Real-project Report-only Pilot
Pilot: pr-02-startup-policy-alignment
Project: Homi PR Snapshot pr-02-startup-policy-alignment
Status: complete
Mode: external_report_only; acceptance_ready=false; CI blocking=false

Coverage
  Inspection complete: True
  Profile complete: True
  Standard files present: True
  Resolution: resolved

Combination Findings
  Findings: 4
  Rule failures: 0

Safe Simulation
  Declared paths: 4
  Unknown coverage: 0
  Example-only blocked: 1
  Static-boundary blocked: 0
  Executed: false
  Side effects: false
  Runtime verified: false

Limitations
  - This is an external report-only Pilot; acceptance_ready is always false.
  - The target workspace is untrusted input and no project code, hooks, skills, commands, MCP, or scheduler was executed.
  - Static Homi declarations do not prove runtime Tool, OAuth, permission, identity, scheduler, or exploit reachability.
  - No raw User, tool, credential, IP address, URL, Avatar, or Secret value is included in the report.
  - Human review and real runtime attestation are outside this Pilot run.
