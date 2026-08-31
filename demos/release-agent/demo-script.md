# Release Agent Demo Script

- Audience: developers and management
- Target duration: 7–8 minutes
- Release: AgentSec 0.1.0
- Policy: report-only

## Presenter command

Run the narrated eight-stage flow from the repository root:

```bash
scripts/demo-developer.sh

# Fully Chinese Agent Assets and Chinese Rule inventory
scripts/demo-developer.sh --case-language zh --show-rules
```

The script pauses before each next stage when attached to an interactive terminal.
Use `--no-pause` for rehearsal automation and `--show-rules` when the audience
should see the full Rule Pack. The detailed commands below remain the presenter
notes and expected talking points.

## 1. Context — 45 seconds

Agent instruction files behave like security-relevant policy. A small Markdown
change can declare a path from local review to command execution, credentials,
external transmission, and production deployment.

AgentSec statically detects those declarations with source Evidence. It does
not prove runtime capability and does not block CI in this release.

## 2. Safe baseline — 60 seconds

```bash
agentsec scan demos/release-agent/baseline
```

Show:

```text
Coverage: Complete
Assets: 2
Findings: 0
Policy: report-only
```

Say explicitly: zero Findings in the supported Markdown scope does not prove the
Agent is globally safe.

## 3. Trusted snapshot — 30 seconds

```bash
agentsec baseline create demos/release-agent/baseline \
  --output /tmp/agentsec-release-baseline.json
```

Explain that the Baseline contains exact sensitive plaintext and hashes. It is a
reviewed comparison point, not a signature or approval identity.

## 4. Risky drift — 75 seconds

```bash
agentsec diff demos/release-agent/risky-drift \
  --baseline /tmp/agentsec-release-baseline.json
```

Show two modified Assets and the lines that introduce:

```text
instruction override and Finding suppression
shell execution
secret/environment access
external network transmission
approval removal
production access
automatic deployment
hidden instructions
executable helper reference
```

Diff reports textual drift and does not assign Severity by itself.

## 5. Risk assessment — 90 seconds

```bash
agentsec scan demos/release-agent/risky-drift --format json \
  > /tmp/agentsec-risky.json
```

Expected:

```text
Coverage: Complete
Findings: 10
Unique Rule IDs: 9
Highest Severity: High
Confidence: D for all Findings
Hard Gate matches: 0
Exit code: 0
```

Developer view: open one High Finding and show Rule ID, file, line, SHA-256,
excerpt, score, Confidence, and remediation.

Management view: the static declaration chain could affect release integrity,
deployment credentials, production systems, and external data exposure.

Policy statement:

```text
ci_blocking_enabled=false
```

Human recommendation: hold the release pending review and remediation. This is
not an AgentSec enforcement decision.

## 6. Prompt Injection — 60 seconds

```bash
agentsec scan demos/release-agent/prompt-injection
```

The source asks the scanner to ignore rules and suppress Findings. The
deterministic host treats it as data and reports:

```text
MD-INSTR-001
MD-INSTR-002
```

## 7. Incomplete Coverage — 45 seconds

```bash
agentsec scan demos/release-agent/malformed --format json
```

Expected:

```text
status=incomplete
issue=unsupported_encoding
exit=2
```

Zero Findings in this report cannot be interpreted as a clean pass because the
Asset was not scanned.

## 8. Remediation — 45 seconds

```bash
agentsec scan demos/release-agent/remediated
```

Show Complete Coverage and zero current Findings after restoring the reviewed,
approval-based instructions. Repeat that this verifies current Rule matches,
not global safety.

## 9. Management close — 30 seconds

```text
What changed: 2 Agent control Assets
Why it matters: command, credential, network, production, and approval declarations
Highest reported risk: High
Evidence: 10 Findings across 9 Rule IDs with direct file/line locations
AgentSec enforcement: report-only
Human recommendation: hold release until remediated
Coverage: Complete for supported Phase 1 Markdown scope
```

## Offline fallback

If a live terminal is unavailable, use the accepted files under `expected/` and
verify them against `checksums.sha256`.
