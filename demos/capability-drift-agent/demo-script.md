# Capability Drift Presenter Script

- Audience: developers and management
- Duration: 7–8 minutes
- Command: `scripts/demo-capability-drift.sh --language en`
- Policy: report-only

## 1. Context — 45 seconds

Agent configuration behaves like executable security policy even when it is
stored as Markdown or TOML. AgentSec reads those files as inert data and builds a
source-backed capability model.

Say explicitly:

```text
This is static analysis.
No Command, Skill, Sub-Agent, Hook, plugin, or MCP server is executed.
No runtime exploit or global safety claim is made.
```

## 2. Reviewed baseline — 60 seconds

```bash
agentsec manifest demos/capability-drift-agent/baseline \
  --agent-id release-agent
agentsec capability assess demos/capability-drift-agent/baseline \
  --agent-id release-agent
```

Show Complete Coverage, one local review Skill, and zero Capability Findings.
Zero Findings means no current structured Rule matched, not that the Agent is
universally safe.

## 3. Risky capability drift — 90 seconds

```bash
agentsec capability assess demos/capability-drift-agent/risky-drift \
  --agent-id release-agent
```

Show:

```text
17 Findings
highest Severity High
16 Rule IDs
report-only policy
```

Explain the declared combinations:

```text
execution + Secret access + external network
automatic state-changing capability without prompt
required credentialed external MCP
Sub-Agent delegation into powerful capability
persistent memory plus sensitive capability
high-impact capability with unresolved static facts
```

Open one Finding and point to Rule ID, correlation, related IDs, source field,
line, SHA-256, Confidence, and recommendation.

## 4. Capability Diff — 75 seconds

```bash
agentsec capability diff \
  --before /tmp/baseline.manifest.json \
  --after /tmp/risky.manifest.json
```

Explain that file Diff answers “what text changed,” while Capability Diff answers
“what normalized Tool, Permission, Control, Identity, Relation, or Unknown
changed.” It retains changed fields, hashes, and provenance without raw values.

## 5. Incomplete Coverage — 45 seconds

```bash
agentsec capability assess demos/capability-drift-agent/incomplete \
  --agent-id release-agent
```

Expected exit is `2`. The malformed Override cannot be read as UTF-8. Zero
Findings must not be interpreted as a clean pass.

## 6. Remediation — 60 seconds

```bash
agentsec capability assess demos/capability-drift-agent/remediated \
  --agent-id release-agent
```

Show Complete Coverage and zero current Findings. Then show the remediation Diff
removing external MCP, execute/network/secret permissions, credentialed identity,
delegation, and persistence facts.

## 7. Management close — 45 seconds

```text
What changed:
  a reviewed local Agent acquired a high-impact capability chain
Why it matters:
  credentials, external trust boundary, release integrity, persistence,
  and delegated blast radius
Evidence:
  17 deterministic Findings across 16 Rule IDs with source provenance
Remediation:
  remove risky integrations and relationships; restore reviewed local behavior
Decision:
  human reviewer should hold release until remediation
AgentSec policy:
  report-only; no automatic CI block
```

## Offline fallback

```bash
scripts/demo-capability-drift.sh --language en --offline --no-pause
```

The command validates `expected/checksums.sha256` before presenting frozen
artifacts.

## 8. Report-only Gate presentation (P2-15A-PILOT-04)

Run the qualified `HG-CAPCHAIN-001` Report-only Gate demo:

```bash
scripts/run-report-only-gate-demo.sh \
  --language en \
  --format text
```

The presenter should call out:

```text
Qualification: accepted
Precision: 1.0
Recall: 1.0
Confidence calibration: 1.0
Report-only matches: 2
Report-only no-match: 3
blocks=false
hard_gate=false
CI blocking=false
```

The qualification affects display only. It does not authorize an Agent, prove
runtime reachability, prove exploitability, block CI, or enable `--fail-on`.

Offline frozen output:

```bash
cat demos/capability-drift-agent/expected/report-only-gate-demo.txt
```
