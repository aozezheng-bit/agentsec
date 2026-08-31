# AgentSec SARIF 2.1.0 Reporter

- Task: `P2-25`
- Status: Complete
- Completion date: 2026-08-25
- SARIF standard version: `2.1.0`
- AgentSec SARIF Reporter version: `0.4.0` (P2-27 organization Policy context)
- Decision: `docs/decisions/0055-sarif-2.1.0-reporter.md`

## 1. Purpose

P2-25 adds a deterministic SARIF delivery adapter for AgentSec Findings and the
P2-23 Overall Score. It allows CI systems and code-scanning consumers to ingest
stable Rule IDs, Severity levels, source locations, fingerprints, Confidence,
Correlation, CVSS/CVE/CWE metadata, Coverage, and report-only policy boundaries.

SARIF is a report format. It does not add a policy decision and does not change
an AgentSec command exit code.

## 2. Supported surfaces

### 2.1 Phase 1 Assessment CLI

```bash
agentsec scan /path/to/project --format sarif > agentsec.sarif
```

The configured `.agentsec/config.yaml` output enum remains `text|json`.
`scan --format sarif` is an explicit CLI-only override in P2-25.

### 2.2 Capability Assessment CLI

Write to stdout:

```bash
agentsec capability assess /path/to/agent \
  --agent-id release-agent \
  --format sarif > capability.sarif
```

Use restricted artifact output:

```bash
agentsec capability assess /path/to/agent \
  --agent-id release-agent \
  --format sarif \
  --output artifacts/capability.sarif
```

Only `capability assess` accepts SARIF. `manifest`, `capability diff`,
`capability impact`, and `capability enforce` retain their existing formats.

### 2.3 Python APIs

```python
from agentsec.reporting import (
    AssessmentSarifRenderer,
    CapabilityAssessmentSarifRenderer,
    OverallScoreSarifRenderer,
    decode_sarif_json,
)

assessment_text = AssessmentSarifRenderer().render(assessment)
capability_text = CapabilityAssessmentSarifRenderer().render(capability_result)
overall_text = OverallScoreSarifRenderer().render(overall_score)
validated = decode_sarif_json(assessment_text)
```

`OverallScoreSarifRenderer` is a public Python adapter in P2-25. There is no
standalone Overall Score CLI yet.

## 3. SARIF contract

Every AgentSec SARIF document contains exactly one SARIF `run`:

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": []
}
```

The AgentSec strict subset requires:

```text
one run
AgentSec tool driver and package version
ordered Rule descriptors
ordered Results
consistent ruleId and ruleIndex
versioned partialFingerprint property names
one Invocation with Coverage/report-only properties
no unknown fields in the AgentSec subset model
```

The implementation follows the OASIS SARIF v2.1.0 Errata 01 specification and
schema:

- https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html
- https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json

P2-25 validates the bounded AgentSec subset with strict Pydantic models. It does
not vendor the complete third-party OASIS JSON Schema or add an online schema
validation dependency.

## 4. Mapping

### 4.1 Severity to SARIF level

| AgentSec Severity | SARIF `level` |
|---|---|
| Critical | `error` |
| High | `error` |
| Medium | `warning` |
| Low | `note` |
| None | `none` |

Severity remains independent from Evidence Confidence. A High/D Finding remains
`error` with `agentsecConfidence=D`; it is not upgraded to runtime proof.

### 4.2 Rule identity

Each distinct AgentSec Rule ID becomes one
`tool.driver.rules[]` reporting descriptor. Every Result carries both:

```text
ruleId
ruleIndex
```

The strict decoder rejects an out-of-range index or a `ruleId`/`ruleIndex`
mismatch.

P2-23 Overall Score uses the stable management Rule ID:

```text
AGENTSEC-OVERALL-001
```

### 4.3 Finding identity and fingerprints

Assessment and Capability Results use:

```text
partialFingerprints.agentsecFindingId/v1
```

Overall Score uses:

```text
partialFingerprints.agentsecOverallManifestSha256/v1
```

The `/v1` suffix is part of the SARIF versioned fingerprint-property contract.
Fingerprint values are stable AgentSec IDs or canonical Manifest hashes; source
text is not used as the fingerprint property name or exposed as its value.

### 4.4 Locations

Source-backed Findings emit:

```text
artifactLocation.uri
artifactLocation.uriBaseId = %SRCROOT%
region.startLine
region.endLine
```

Paths are normalized to POSIX form and URI-encoded. Phase 1 and Capability
Findings retain all safe Evidence locations. The management-level Overall Score
has no single source location and therefore emits an empty `locations` array.

## 5. AgentSec properties

### 5.1 Common Result properties

Depending on the source report, Results preserve:

```text
agentsecFindingId
agentsecCategory
agentsecScore
agentsecSeverity
agentsecConfidence
agentsecHardGate
agentsecCiBlockingEnabled = false
agentsecRuntimeCapabilityVerified = false
```

### 5.2 Capability properties

Capability Results additionally preserve:

```text
agentsecCorrelation
agentsecRelatedIds
agentsecShadowGateId
agentsecShadowGateMatched
agentsecShadowGateBlocks = false
```

### 5.3 Vulnerability properties

When present, Assessment Results preserve bounded vulnerability metadata:

```text
agentsecVulnerabilityId
agentsecCveId
agentsecCweIds
agentsecCvssVersion
agentsecCvssBaseScore
agentsecCvssEffectiveScore
agentsecCvssHardGateMatched
```

P2-25 does not perform a remote vulnerability lookup, runtime exploitability
check, or attack proof.

### 5.4 Overall Score properties

The Overall Score Result preserves:

```text
agentsecTechnicalScore
agentsecDriftScore
agentsecGovernanceScore
agentsecBaseOverallScore
agentsecOverallScore
agentsecHardGateTriggered
agentsecHardGateFloor
agentsecHardGateBlocks = false
agentsecCiBlockingEnabled = false
agentsecRuntimeCapabilityVerified = false
```

A qualified report-only floor remains non-dilutable in the score but does not
become CI enforcement in P2-25.

## 6. Security and privacy boundary

SARIF intentionally excludes untrusted or sensitive payload text, including:

```text
Evidence excerpts
secret, token, credential, or environment values
parsed command arguments
URL query and fragment values
Header values
memory content
raw parser/source values
dependency exception messages
```

Rule titles, descriptions, and recommendations pass through the shared AgentSec
redaction and control-character sanitization layer and are bounded before
serialization. Artifact paths and line ranges remain available so a reviewer can
open the source under the trusted checkout instead of copying source text into
SARIF.

This protects CI code-scanning UIs from receiving prompt-injection content or
recognized secret values from scanned Agent assets.

## 7. Exit-code and enforcement semantics

SARIF selection never changes the existing result semantics:

| Condition | Exit code | SARIF behavior |
|---|---:|---|
| Complete scan/assessment, zero or more Findings | `0` | Valid SARIF emitted |
| Incomplete Coverage or Capability Rule execution | `2` | Partial valid SARIF emitted with Coverage false |
| Invalid configuration/options | `3` | Safe stderr diagnostic; no fake SARIF result |
| Unsafe/incompatible artifact path | `4` | Safe stderr diagnostic |
| Required deterministic analysis failure | `5` | Safe stderr diagnostic |

P2-26 adds explicit `scan --fail-on high|critical`, but SARIF `error` level
remains presentation metadata and is never the decision authority. AgentSec
computes the Severity decision first, records it in SARIF properties, and returns
the corresponding process exit code.

## 8. Artifact safety

`capability assess --output` requires:

```text
--format sarif → .sarif
```

The existing report writer applies:

```text
bounded UTF-8 content
strict AgentSec SARIF validation
capability_assessment report-kind validation
mode 0600
atomic creation
no overwrite by default
no symlink target
--force only for the same valid AgentSec Capability Assessment SARIF kind
```

`agentsec scan` continues to write stdout only. Use shell redirection in CI when
a file is required.

## 9. Determinism

For identical AgentSec input, versioned configuration, report source object, and
execution metadata:

```text
Rule ordering is stable
Result ordering is stable
ruleIndex assignment is stable
JSON keys are sorted
fingerprints are stable
output ends with one newline
```

Assessment timestamps remain execution provenance and can differ between
independent scan invocations.

## 10. Limitations and next steps

P2-25 does not add:

```text
complete third-party OASIS JSON Schema vendoring
SARIF Baseline/ThreadFlow/CodeFlow graphs
SARIF fixes or automated remediation
SARIF output for Manifest, Capability Diff, Impact, or Enforcement
scan --output artifact writing
Overall Score CLI
organization Policy
waivers
runtime Tool/OAuth/Permission verification
LLM semantic analysis
runtime vulnerability proof
```

P2-26 now provides explicit High/Critical Severity fail-on and records the
already-computed decision in SARIF. P2-27 remains responsible for organization
Policy; P2-28 remains responsible for waivers.

## 11. P2-26 fail-on policy context

When `scan --fail-on high|critical` is selected, SARIF Reporter `0.3.0` retains
`agentsecEnforcementMode=fail_on_severity`, threshold, decision, exit code,
matching Finding IDs, and per-Result `agentsecFailOnMatched`. The invocation is
no longer marked report-only. SARIF level still has no policy authority. See
`docs/fail-on.md` and ADR-0056.

## 12. P2-27 organization Policy context

SARIF Reporter `0.3.0` adds explicit organization Policy ID/version/SHA-256, threshold, blocking Rule scope, decision, exit code, matched Finding IDs, and per-Result match state. See `docs/organization-policy.md`.
