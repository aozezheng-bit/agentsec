# AgentSec `scan --fail-on` Policy Gate

- Task: `P2-26`
- Status: Complete
- Completion date: 2026-08-25
- Fail-On Policy version: `0.1.0`
- Fail-On Report Output version: `0.1.0`
- Decision: `docs/decisions/0056-explicit-severity-fail-on.md`

## 1. Purpose

P2-26 adds an explicit local CI exit policy to `agentsec scan`:

```bash
agentsec scan PROJECT --fail-on high
agentsec scan PROJECT --fail-on critical
```

Without `--fail-on`, scan behavior is unchanged and Findings remain report-only.
The option must be supplied explicitly on each invocation; Config Schema `0.1.0`
does not persist a threshold. Organization defaults belong to P2-27.

## 2. Supported thresholds

| Threshold | Blocking Findings |
|---|---|
| `high` | AgentSec Severity `high` or `critical` |
| `critical` | AgentSec Severity `critical` only |

P2-26 deliberately does not accept `low`, `medium`, numeric scores, Rule IDs,
SARIF levels, Evidence Confidence, CVSS thresholds, or LLM conclusions.

The decision basis is:

```text
basis = agentsec_severity
```

It evaluates the final deterministic Finding Severity after the existing scan,
risk, Confidence, Hard Gate, vulnerability enrichment, and CVSS report-only Gate
stages. It does not recalculate risk.

## 3. Decision precedence

```text
required analysis/configuration failure
→ existing exit 3/5

incomplete Coverage or Rule execution
→ decision=incomplete
→ exit 2

complete + Finding at/above explicit threshold
→ decision=block
→ exit 1

complete + no Finding at/above threshold
→ decision=allow
→ exit 0
```

Incomplete Coverage always takes precedence over a threshold match. A partial
scan cannot be represented as an authoritative risk block or a clean allow.
Matching Finding IDs remain visible in the decision for review, but
`blocks=false` when Coverage is incomplete.

## 4. Confidence, Hard Gate, CVSS, and SARIF boundaries

### Evidence Confidence

Confidence remains independent from Severity. P2-26 does not suppress a High or
Critical Finding because its evidence grade is C or D. The threshold is an
explicit operator-selected static risk policy, not a runtime confidence claim.

### Generic and Capability Hard Gates

P2-26 does not require `Finding.hard_gate=true` and does not activate new Hard
Gate rules. Capability Assessment remains outside this flag; qualified
Capability Gate enforcement continues through:

```bash
agentsec capability enforce PROJECT --policy POLICY.json
```

This prevents `capability assess --fail-on high` from bypassing the existing
human Qualification and deterministic Gate policy.

### CVSS

`--fail-on high|critical` evaluates AgentSec Finding Severity only. It does not
use CVSS Base/Effective Score or `CvssHardGateAssessment`. A future explicit
CVSS policy must have its own versioned contract and waiver rules.

### SARIF

SARIF `level` is presentation metadata and is never the authority for the
process decision. When fail-on is enabled, SARIF records the already-computed
AgentSec decision in `run.properties` and Result properties.

## 5. Text output

```bash
agentsec scan demos/release-agent/risky-drift \
  --format text \
  --fail-on high
```

The output begins with:

```text
AgentSec Fail-On Decision
Policy version: 0.1.0
Threshold: HIGH
Basis: AgentSec deterministic Finding Severity
Decision: BLOCK
Exit code: 1
Coverage complete: true
Highest observed severity: HIGH
Matched findings: 4
```

The normal Assessment follows and its Policy header states that the explicit
CLI threshold and CI exit-code blocking are enabled.

## 6. JSON output

```bash
agentsec scan demos/release-agent/risky-drift \
  --format json \
  --fail-on high > agentsec-fail-on.json
```

P2-26 uses an independent wrapper rather than mutating the canonical Assessment
Output `0.7.0`:

```json
{
  "format": "agentsec-assessment-fail-on",
  "format_version": "0.1.0",
  "decision": {
    "policy_version": "0.1.0",
    "threshold": "high",
    "basis": "agentsec_severity",
    "decision": "block",
    "exit_code": 1,
    "coverage_complete": true,
    "blocks": true,
    "highest_observed_severity": "high",
    "matched_finding_ids": ["finding-sha256:<digest>"]
  },
  "assessment_report": {
    "format": "agentsec-assessment",
    "format_version": "0.7.0"
  }
}
```

The embedded `assessment_report` remains the canonical sanitized Assessment and
therefore retains its historical report-only policy object. The authoritative
P2-26 invocation decision is the outer `decision` plus the process exit code.
The strict decoder recomputes the threshold over the embedded Assessment and
rejects a mismatched or tampered decision.

Frozen Schema:

```text
schemas/assessment/assessment-fail-on-report.schema.json
```

Python APIs:

```python
from agentsec.reporting import (
    AssessmentFailOnJsonRenderer,
    decode_assessment_fail_on_json,
    export_assessment_fail_on_json_schema,
)
```

## 7. SARIF output

```bash
agentsec scan demos/release-agent/risky-drift \
  --format sarif \
  --fail-on high > agentsec.sarif
```

The SARIF run records:

```text
agentsecCiBlockingEnabled = true
agentsecEnforcementMode = fail_on_severity
agentsecFailOnPolicyVersion = 0.1.0
agentsecFailOnThreshold = high
agentsecFailOnDecision = block
agentsecFailOnExitCode = 1
agentsecFailOnMatchedFindingIds = [...]
```

Each Result adds:

```text
agentsecFailOnMatched = true|false
```

`invocations[].properties.agentsecReportOnly` becomes `false`. The SARIF
Reporter version advances from `0.1.0` to `0.2.0` because its policy-context
mapping changed.

## 8. Examples

### High blocks the current risky Demo

```bash
set +e
agentsec scan demos/release-agent/risky-drift --fail-on high
code=$?
set -e
printf 'exit=%s\n' "$code"
```

Expected:

```text
exit=1
```

### Critical does not block a High-only result

```bash
agentsec scan demos/release-agent/risky-drift --fail-on critical
```

Expected:

```text
exit=0
Decision: ALLOW
```

### Incomplete Coverage remains exit 2

```bash
set +e
agentsec scan demos/release-agent/malformed \
  --format json \
  --fail-on high > incomplete.json
code=$?
set -e
```

Expected:

```text
exit=2
decision=incomplete
blocks=false
```

## 9. Security properties

- does not execute scanned code, Commands, Hooks, Skills, plugins, or MCP;
- does not access external networks or runtime credentials;
- uses only final deterministic AgentSec Finding Severity;
- does not use Evidence excerpts, Secret values, URLs, Headers, environment
  values, or memory content in policy evaluation;
- matched evidence is represented by stable Finding IDs;
- threshold selection is explicit and cannot be injected by scanned content;
- Coverage incomplete cannot be converted to allow or block;
- Confidence cannot lower Severity;
- SARIF `level` and LLM output have no policy authority;
- Capability Gate Qualification cannot be bypassed through this flag.

## 10. Deferred work

P2-26 does not add:

```text
organization Policy YAML/JSON defaults
per-Rule or per-category thresholds
CVSS-driven fail-on
Overall Score CLI fail-on
risk waivers, Owner, reason, or expiry
branch/environment-specific policy
remote policy retrieval
automatic remediation
runtime exploitability proof
```

P2-27 now provides organization Policy. Waivers and their Owner/reason/expiry governance remain P2-28.
