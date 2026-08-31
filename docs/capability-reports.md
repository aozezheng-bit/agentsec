# AgentSec Manifest, Capability Assessment, and Capability Diff Reports

- Task: `P2I-03`
- Status: Complete
- Completion date: 2026-08-20
- Decision: `docs/decisions/0030-capability-assessment-report-contract.md`
- Agent Manifest Schema: `0.3.0`
- Capability Diff Schema: `0.1.0`
- Capability Assessment Output: `0.1.0`

## 1. Purpose

P2I-03 provides deterministic Text and JSON delivery for the three Phase 2
security-analysis artifacts:

```text
AgentAnalysisPipeline
├── Agent Manifest Text / canonical JSON
├── CapabilityAssessmentEngine
│   └── Capability Assessment Text / versioned JSON
└── CapabilityDiffer
    └── Capability Diff Text / canonical JSON
```

The reports serve two audiences at the same time:

- management receives status, highest Severity, counts, Coverage, and policy;
- developers receive Stage Trace, normalized capability facts, correlation,
  portable source provenance, hashes, and remediation.

P2I-03 adds no CLI command. P2I-04 will expose these renderers through the
`agentsec manifest` and `agentsec capability` command families.

## 2. Artifact boundaries

### 2.1 Agent Manifest

`AgentManifest` remains the canonical declaration inventory:

```text
schema_version = 0.3.0
```

`ManifestJsonRenderer` calls the existing
`encode_agent_manifest_json(manifest)` codec. The Text renderer accepts the
complete `AgentAnalysisResult` so it can include the safe nine-stage trace and
version vector.

### 2.2 Capability Assessment

`CapabilityAssessmentResult` combines:

```text
AgentAnalysisResult
+ CapabilityRuleRunResult
```

The new public JSON wrapper is:

```text
format = agentsec-capability-assessment
format_version = 0.1.0
```

It embeds the canonical Manifest and adds deterministic Findings, policy,
summary, Stage Trace, and isolated Rule failures.

### 2.3 Capability Diff

`CapabilityDiffResult` remains the canonical normalized comparison:

```text
schema_version = 0.1.0
```

`CapabilityDiffJsonRenderer` calls the existing
`encode_capability_diff_json(diff)` codec. It does not introduce raw before/after
values.

## 3. Application flow

```python
from pathlib import Path

from agentsec.application import (
    AgentAnalysisRequest,
    CapabilityAssessmentEngine,
)

result = CapabilityAssessmentEngine().assess(
    AgentAnalysisRequest(
        project_root=Path("/workspace/release-agent"),
        agent_id="release-agent",
    )
)
```

The application service executes:

```text
AgentAnalysisPipeline
→ final validated AgentManifest
→ DeterministicCapabilityRuleRunner
→ CapabilityAssessmentResult
```

`result.complete` requires complete Manifest Coverage and complete Rule
execution. Findings do not make the result incomplete because P2I-03 remains
report-only.

## 4. Public report APIs

### 4.1 Manifest

```python
from agentsec.reporting import ManifestJsonRenderer, ManifestTextRenderer

text = ManifestTextRenderer().render(result.analysis)
json_text = ManifestJsonRenderer().render(result.analysis.manifest)
```

Text sections include:

```text
Agent / Framework / status / policy
Version Vector
Coverage
Stage Trace
Profile Resolution
Sources
Effective Instructions
Configuration Order
Tools
Permissions
Controls
Runtime Identities
Relationships
Explicit Unknowns
Boundary statement
```

### 4.2 Capability Assessment

```python
from agentsec.reporting import (
    CapabilityAssessmentJsonRenderer,
    CapabilityAssessmentTextRenderer,
)

text = CapabilityAssessmentTextRenderer().render(result)
json_text = CapabilityAssessmentJsonRenderer().render(result)
```

The Text report is management-first:

```text
status and report-only policy
Finding count and highest Severity
Severity and Evidence Confidence distributions
capability inventory counts
Coverage completeness
Rule execution completeness
version vector
Stage Trace
Rule failures
Finding correlation, related IDs, evidence, and remediation
static-analysis boundary
```

The JSON top level is:

```text
format
format_version
status
versions
policy
summary
manifest
findings
stage_trace
rule_failures
```

The fixed policy is:

```json
{
  "enforcement_mode": "report_only",
  "ci_blocking_enabled": false,
  "global_safety_claimed": false,
  "runtime_capability_verified": false
}
```

### 4.3 Capability Diff

```python
from agentsec.manifests import CapabilityDiffer
from agentsec.reporting import (
    CapabilityDiffJsonRenderer,
    CapabilityDiffTextRenderer,
)

diff = CapabilityDiffer().compare(before=before_manifest, after=after_manifest)
text = CapabilityDiffTextRenderer().render(diff)
json_text = CapabilityDiffJsonRenderer().render(diff)
```

The Text report groups changes by dimension and displays:

```text
complete / incomplete status
Agent and schema versions
added / removed / modified counts
profile transitions
safe changed field names
before / after fingerprints
before / after source references
no-raw-values and no-runtime-proof boundaries
```

## 5. Chinese output

All Text renderers accept the reviewed Capability Rule language enum:

```python
from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.reporting import CapabilityAssessmentTextRenderer

text = CapabilityAssessmentTextRenderer(language=CapabilityRuleLanguage.ZH).render(
    result
)
```

Manifest and Diff structural labels are localized. Capability Assessment uses
the trusted Simplified Chinese title, description, and recommendations embedded
in every Capability Rule. Localization never changes rule conditions, Finding
identity, score, Severity, Confidence, or evidence.

JSON retains both reviewed `en` and `zh` Finding texts so automation can select a
presentation language later without rerunning Rules.

## 6. Text display limits

Human output is bounded independently from canonical JSON.

```python
from agentsec.reporting import (
    CapabilityAssessmentTextLimits,
    CapabilityAssessmentTextRenderer,
)

renderer = CapabilityAssessmentTextRenderer(
    limits=CapabilityAssessmentTextLimits(
        max_findings=20,
        max_evidence_per_finding=5,
        max_related_ids_per_finding=10,
        max_recommendations_per_finding=5,
    )
)
```

Other report-specific limits cover Manifest sections, Diff changes and sources,
Stage Trace, Rule failures, and maximum displayed string length. Every omitted
item count remains visible. JSON is not truncated by Text display limits.

## 7. JSON validation and Schema export

```python
from pathlib import Path

from agentsec.reporting import (
    CapabilityAssessmentJsonRenderer,
    decode_capability_assessment_json,
    export_capability_assessment_json_schema,
)

encoded = CapabilityAssessmentJsonRenderer().render(result)
validated = decode_capability_assessment_json(encoded)
schema_path = export_capability_assessment_json_schema(Path("build/schemas"))
```

The exported filename is:

```text
capability-assessment.schema.json
```

Validation is compatibility-first:

1. require a JSON object;
2. validate `format`;
3. validate semantic `format_version`;
4. reject unsupported pre-1.0 minor versions;
5. validate the strict payload and derived summary/status invariants.

Validation errors expose only stable codes and safe field paths, never rejected
payload values or dependency diagnostics.

## 8. Determinism and ordering

- Manifest and Capability Diff JSON use their canonical deterministic codecs.
- Capability Assessment JSON uses sorted keys, strict immutable models, and a
  trailing newline.
- Findings in JSON retain canonical Rule/result order.
- Findings in Text are ordered by Severity descending, score descending, Rule
  ID, and Finding ID so the highest-impact review item appears first.
- Stage Trace always uses the fixed nine-stage application order.
- Rule failures are sorted and unique.

## 9. Output safety

Text dynamic values pass through:

```text
SecretRedactor
→ sanitize_untrusted_text
→ length bound
```

Reports never intentionally include:

```text
source excerpts
parsed Commands or arguments
endpoint values or URL query/fragment values
Header values
environment-variable values
credentials or tokens
memory content
dependency exception messages
```

Capability Finding evidence is value-free:

```text
scope
root_id
relative path
field path
line range
content SHA-256
```

The Capability Assessment JSON embeds the canonical Manifest rather than a
second recursively rewritten representation. Its safety therefore inherits the
Manifest contract: parsed command, URL, environment, Header, and credential
values are omitted before serialization.

## 10. Interpretation boundaries

A complete report means only:

```text
all selected static assets were inspected within supported limits
and all registered deterministic Capability Rules completed
```

It does not prove:

```text
runtime Tool availability
runtime permission or identity grants
end-to-end attack-path reachability
successful exploitation
absence of unsupported semantic risk
global Agent safety
```

Zero Findings means no current Capability Rule matched the supported static
profile. It is not a safety certificate. Incomplete Coverage or Rule execution
is persistently visible and must not be treated as a clean pass.

## 11. Verification

P2I-03 regression tests cover:

- canonical Manifest and Capability Diff JSON equality;
- English and Chinese Manifest/Diff Text;
- management summary, developer evidence, and localization;
- complete and incomplete Capability Assessment JSON;
- strict derived validation and compatibility-first errors;
- deterministic JSON Schema export;
- Text limits and explicit omitted counts;
- secret, URL, terminal-control, and dependency-message non-disclosure;
- Stage Trace, Rule completeness, and no-global-safety wording.

## 12. Next task

P2I-04 now exposes these reports through the Manifest and Capability CLI with
bounded artifact readers/writers. P2I-05 now freezes and demonstrates the same
reports through the bilingual Capability Drift story.

## 13. P2-25 SARIF delivery extension

P2-25 adds `CapabilityAssessmentSarifRenderer` over the same deterministic
`CapabilityAssessmentResult` and exposes it through:

```bash
agentsec capability assess /path/to/agent \
  --agent-id release-agent \
  --format sarif \
  --output artifacts/release-agent.sarif
```

SARIF preserves Rule identity, source locations, versioned Finding fingerprints,
Severity, Evidence Confidence, Correlation, related IDs, Shadow Gate state,
Coverage, and version provenance. It deliberately omits the canonical embedded
Manifest and all raw source values. The Capability Assessment JSON contract and
version remain independent. See `docs/sarif-report.md` and ADR-0055.
