# P2-16-01 Capability Risk Model / P1-21 Gap Audit

- Task ID: `P2-16-01`
- Status: Complete for source audit; P2-16 core behavior is already implemented
- Audit date: 2026-08-24
- Requirement source: Yuque plan, Section `10.4 完整风险评分` (`#NViEw`)
- Current enforcement: `report_only`
- Current Capability Risk Model: `0.1.0`
- Current Phase 1 Risk Model: `0.4.0`

## 1. Audit conclusion

The current repository already implements the core P2-16 requirement through the
existing P1-21 Risk Engine and the Phase 2 Capability Rule materialization path.
P2-16 should **not** be implemented by creating a second NIST matrix or by
rewriting the existing Phase 1 Risk Model.

```text
P2-16 core behavior: implemented in source
P2-16 formal task traceability: missing before this audit
P2-16 dedicated cross-layer acceptance test: recommended
Capability Risk Model version bump: not required for the current semantics
P2-17 CVSS Adapter: not started by this audit
P2-18～P2-24: not started by this audit
Hard Gate / CI enforcement: unchanged and disabled
```

The minimum remaining work to close P2-16 formally is regression hardening and
traceability, not a new risk formula. Any change to the matrix, score mapping,
Impact aggregation, Severity thresholds, or Confidence interaction must be
handled as a separate Risk Model change with an ADR and version review.

## 2. Requirement baseline from the plan

The plan defines P2-16 as:

| Requirement field | Plan requirement |
|---|---|
| Task | Implement NIST Likelihood and Impact |
| Dependency | `P1-21` |
| Primary output | Base Score |
| Acceptance criterion | Use High-Water-Mark Impact |
| Downstream | `P2-17` through `P2-24` |

This task is different from Pilot/Shadow Mode. Pilot/Shadow Mode is a later
operational track and is not the definition of P2-16.

## 3. Source-to-requirement traceability

### 3.1 NIST Likelihood / Impact matrix

**Status: Satisfied.**

The existing mapping in `src/agentsec/risk/mapping.py` provides:

```text
NIST SP 800-30 Rev. 1 five-by-five likelihood/impact matrix
NIST semi-quantitative values: 0 / 2 / 5 / 8 / 10
AgentSec representative Base Scores: 0.0 / 2.0 / 5.5 / 8.0 / 9.5
CVSS v4 qualitative Severity mapping
```

The matrix is explicit rather than computed by an arithmetic approximation.
`src/agentsec/risk/engine.py` applies the matrix to a validated Risk Profile.

### 3.2 Capability likelihood

**Status: Satisfied for the current static Capability model.**

`src/agentsec/capability_rules/base.py` maps the reviewed correlation type to a
static likelihood:

| Correlation | Likelihood | Rationale |
|---|---|---|
| `same_target` | Moderate | Direct target correlation, runtime reachability unproven |
| `parent_child` | Moderate | One MCP/tool family, runtime reachability unproven |
| `same_source` | Moderate | Same reviewed declaration source |
| `explicit_relation` | Moderate | Typed Manifest relation |
| `agent_wide` | Low | Coexistence only; reachability unresolved |
| `incomplete_coverage` | Low | Coverage or relevant dimension unresolved |

This mapping is independent from Evidence Confidence. Confidence is not used as a
score multiplier or as an automatic risk downgrade.

### 3.3 High-Water-Mark Impact

**Status: Satisfied.**

Both the Phase 1 `RiskProfile` and Phase 2 `CapabilityRuleMetadata` retain one or
more `ImpactRating` values. Their effective Impact is the maximum dimension:

```text
Impact = max(
    confidentiality,
    integrity,
    availability,
    safety,
    business/compliance,
    downstream blast radius,
)
```

The implementation does not average Impact dimensions or Findings. The
invariant is enforced in:

```text
src/agentsec/risk/models.py
src/agentsec/capability_rules/base.py
```

### 3.4 Base Score materialization

**Status: Satisfied.**

The Phase 2 path is:

```text
AgentManifest
→ CapabilityRuleContext
→ CapabilityRuleCandidate
→ correlation-derived Likelihood
→ Rule metadata High-Water-Mark Impact
→ NIST risk level
→ NIST semi-quantitative value
→ AgentSec Base Score
→ Severity
→ CapabilityRuleFinding
```

`src/agentsec/capability_rules/pipeline.py` performs this materialization and
stores the result in `CapabilityRuleFinding`.

### 3.5 Evidence and provenance

**Status: Satisfied.**

Capability Findings retain:

```text
Rule ID
Correlation
Related IDs
Likelihood basis
Impact ratings and rationales
Value-free source evidence
Mapping basis
Capability Rule Pack version
Capability Risk Model version
```

Source evidence contains portable locators, fields, line ranges, and content
hashes. It does not copy secret values, command values, URL values, headers,
environment values, or memory content.

### 3.6 Text/JSON reporting

**Status: Satisfied.**

The Capability Assessment Text and JSON reporters expose:

```text
Likelihood
Impact
NIST risk level
NIST semi-quantitative value
Base Score
Severity
Confidence
Correlation
Impact ratings
Mapping basis
Capability Risk Model version
```

Relevant files:

```text
src/agentsec/reporting/capability_assessment.py
src/agentsec/reporting/capability_assessment_json.py
```

### 3.7 Version separation

**Status: Satisfied.**

The repository keeps the Phase 1 and Capability versions separate:

```text
RISK_MODEL_VERSION = 0.4.0
CAPABILITY_RISK_MODEL_VERSION = 0.1.0
CAPABILITY_RULE_PACK_VERSION = 0.2.0
```

ADR-0029 and ADR-0034 explicitly preserve the Capability Risk Model `0.1.0`
while reusing the reviewed NIST, FIPS high-water-mark, score, and Severity
mappings. No current P2-16 gap requires changing `RISK_MODEL_VERSION`.

## 4. Gap matrix

| Area | Current implementation | P2-16 result | Remaining action |
|---|---|---|---|
| NIST matrix | Explicit 25-cell mapping | Pass | Keep unchanged |
| Likelihood levels | P1 profiles and Capability correlation policy | Pass | Add cross-layer regression assertion |
| Impact dimensions | Six typed dimensions | Pass | Keep High-Water-Mark invariant |
| Impact aggregation | `max`, never average | Pass | Add P2-16 acceptance reference |
| NIST value | Explicit 0/2/5/8/10 | Pass | Keep separate from AgentSec score |
| AgentSec Base Score | Explicit 0/2/5.5/8/9.5 | Pass | Add cross-layer regression assertion |
| Severity mapping | CVSS v4 qualitative ranges | Pass | No change |
| Confidence interaction | Separate from score | Pass | Preserve invariant |
| Unknown / incomplete | Visible correlation and Coverage state | Pass | No silent safety interpretation |
| Finding provenance | Value-free evidence and mapping basis | Pass | No change |
| Text report | Displays score and risk fields | Pass | No change |
| JSON report | Strict fields and version checks | Pass | No change |
| Capability version | `0.1.0` with ADR | Pass | No bump without semantic change |
| P2-16 task record | No dedicated audit/completion record before this task | Gap | This report closes traceability |
| P2-16 cross-layer test | Existing tests cover components, but no single named P2-16 contract test | Partial gap | Add a focused regression test before formal closure |

## 5. Existing verification evidence

The following targeted tests were run during this audit:

```bash
.venv/bin/pytest -q \
  tests/test_risk_model.py \
  tests/test_capability_rules.py \
  tests/test_capability_assessment_reporting.py \
  tests/test_capability_assessment_application.py \
  tests/test_versioning.py
```

Result:

```text
71 passed in 0.55s
```

The existing test coverage confirms, among other invariants:

```text
all NIST matrix cells and matrix monotonicity
P1 High-Water-Mark Impact behavior
Capability Rule Pack and Capability Risk Model versions
Capability Finding risk fields and version consistency
Capability Assessment JSON risk fields
report-only hard_gate=false behavior
```

## 6. Required security invariants

P2-16 audit confirms that the current scoring path preserves:

```text
no scanned code, Hook, Skill, Plugin, Sub-Agent, Rule, or MCP execution
no network or runtime permission verification
no environment, Header, credential, or memory value reads
no LLM authorization or CI decision
Severity remains separate from Evidence Confidence
High/Critical results cannot be diluted by averaging
Incomplete Coverage and Unknown remain visible
identical inputs and versions produce deterministic results
```

## 7. Recommended next action

The next implementation task should be a narrow hardening task, not a new scoring
algorithm:

```text
P2-16-02: Capability Risk Score Contract Regression Hardening
```

It should add a named acceptance test covering the complete Phase 2 path:

```text
CapabilityRuleCandidate
→ correlation likelihood
→ metadata High-Water-Mark Impact
→ NIST matrix cell
→ NIST value
→ AgentSec Base Score
→ Severity
→ report Text/JSON
→ Capability Risk Model version
```

The test should also verify:

```text
Confidence does not change Score or Severity
one Very High Impact dimension is not averaged away
D/Agent-wide correlation remains Low likelihood and report-only
Incomplete/Unknown correlation remains visible
JSON and Text expose the same risk semantics
```

After that hardening task, P2-17 can begin. P2-17 must not be started in the same
change because it introduces a separate CVSS Adapter contract.

## 8. Explicit non-goals of this audit

This audit does not:

```text
change the NIST matrix
change the Base Score mapping
change the Capability Risk Model version
add CVSS Base vector ingestion
add Agentic Factors
add Threat/Mitigation multipliers
add Drift or Governance Scores
activate Hard Gates
implement --fail-on or CI blocking
use Pilot Review labels as formal risk evidence
start P2-17 or later scoring tasks
```
