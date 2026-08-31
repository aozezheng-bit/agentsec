# AgentSec Capability Drift Demo

- Task: `P2I-05`
- Status: Accepted
- Date: 2026-08-20
- Audiences: developers, security reviewers, and management
- Policy: static analysis, report-only, runtime not verified

## Story

A reviewed Release Agent begins as a local read-only reviewer with one inert
review Skill. Configuration drift then adds:

```text
STDIO MCP execution potential
Secret/environment reference
required external HTTP MCP
OAuth-style external identity
approval mode auto
Sub-Agent delegation
persistent release memory
```

AgentSec turns those declarations into an Agent Manifest, detects deterministic
combination Findings, and shows normalized Capability Diff rather than only file
text. Remediation removes the external MCP, credential reference, delegation,
and persistence declarations and returns the current Capability Rule result to
zero Findings.

This is not a live exploit. The Demo never starts an MCP server, executes a
Command or Skill, reads a credential, contacts an endpoint, or calls an LLM.

## Scenarios

| Scenario | Expected result |
|---|---|
| `baseline/` | Complete Coverage, 0 Capability Findings |
| `risky-drift/` | Complete Coverage, 17 Findings across 16 Rule IDs, highest High |
| `incomplete/` | Invalid UTF-8 Override, incomplete report, exit `2` |
| `remediated/` | Complete Coverage, 0 Capability Findings |

The risky Capability Diff currently contains 35 normalized item changes. The
exact added/removed split is versioned output evidence, not a policy threshold.

## Run the automated E2E Demo

```bash
scripts/run-capability-demo.sh --language en
```

Preserve outputs:

```bash
scripts/run-capability-demo.sh \
  --language en \
  --output-dir /tmp/agentsec-capability-demo
```

The runner uses only the production CLI:

```text
agentsec manifest
agentsec capability assess
agentsec capability diff
```

It validates complete, risky, incomplete, and remediated states, plus secret and
endpoint non-disclosure.

## Run the presenter flow

```bash
scripts/demo-capability-drift.sh --language en
```

Rehearsal without pauses:

```bash
scripts/demo-capability-drift.sh --language en --no-pause
```

Offline fallback without running analysis:

```bash
scripts/demo-capability-drift.sh --language en --offline --no-pause
```

The seven-stage presenter flow takes approximately seven to eight minutes:

```text
Context and boundary
→ reviewed baseline
→ risky Capability Assessment
→ Capability Diff
→ incomplete Coverage
→ remediation
→ management close
```

## Developer view

Show:

```text
Tool, Permission, Control, Identity, Relation, and Unknown IDs
added/removed/modified capability items
portable source path, field, line range, and SHA-256
Rule ID, correlation, related IDs, Severity, and Confidence
complete versus incomplete Coverage
canonical Manifest, Assessment, and Diff JSON
```

Capability Diff does not expose complete raw before/after values.

## Management view

One-screen message:

```text
Added capability chain:
  execution + Secret access + external network
Additional governance drift:
  auto approval + credentialed required external MCP
  delegation + persistent memory
Highest reported risk:
  High
Evidence:
  17 Findings across 16 deterministic Capability Rule IDs
Remediation:
  remove external/credential/delegation/persistence declarations
  restore reviewed local behavior
Enforcement:
  report-only; AgentSec does not block CI
```

The human recommendation is to hold the release until remediation. That is a
governance decision, not an AgentSec authorization or enforcement action.

## Frozen offline artifacts

`expected/` contains deterministic Manifest, Capability Assessment, Capability
Diff, Text, and management-summary artifacts. Verify them with:

```bash
PYTHONPATH=src .venv/bin/python \
  scripts/validate_capability_demo_outputs.py \
  demos/capability-drift-agent/expected
```

Regenerate only after reviewed semantic changes:

```bash
PYTHONPATH=src .venv/bin/python scripts/freeze_capability_demo.py
```

`checksums.sha256` covers every frozen file except itself.

## Boundaries

The Demo does not prove:

```text
runtime Tool availability
actual identity or permission grants
end-to-end attack-path reachability
successful exploitation
absence of unsupported risks
global Agent safety
```

Findings remain `hard_gate=false`; CI blocking is disabled.
