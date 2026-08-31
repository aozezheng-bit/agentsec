# AgentSec Capability Calibration, Hard Gate, and CI Enforcement Plan

- Status: P2-CAL-01～04 complete for source development; P2-15A pending; P2-17 CVSS Base Adapter, P2-18 Finding/Assessment integration, P2-19 Vulnerability Association, P2-20 CVSS v4 calculator, P2-21 extended CVSS metrics, and P2-22 vulnerability-input CLI and P2-23 CVE/CWE source adapters complete
- Date: 2026-08-20
- Applies after: P2-14 Capability Rule Pack `0.2.0`
- Current Capability Risk Model: `0.1.0`
- Current enforcement: report-only, no Capability Hard Gate

## 1. Required delivery order

The next work must be implemented in this order:

```text
P2-CAL: calibrate false positives, false negatives, and Evidence Confidence
→ P2-15A: Report-only Capability Hard Gates
→ Pilot / Shadow Mode
→ P2-15B: Policy-controlled CI Enforcement
```

P2-15A must not be selected only from design intuition. A candidate Gate must
first pass the calibration acceptance criteria in this document. P2-15B must not
begin merely because P2-15A code exists; it requires Pilot evidence, ownership,
waiver, rollout, and policy contracts.


## P2-CAL-01 completion record

P2-CAL-01 is complete in the source tree. It adds:

```text
agentsec.calibration strict immutable Case and Corpus Index models
Calibration Case and Corpus JSON codecs
Draft 2020-12 Schema exports
root-contained bounded UTF-8 Corpus Loader
61 seed Cases: 29 positive, 29 near-miss, 3 boundary Cases
match/no-match labels for all 29 Capability Rule IDs
explicit expected Correlation and Evidence Confidence labels
```

The seed corpus is not statistically calibrated. P2-CAL-02 must add replay and
confusion-matrix metrics; P2-CAL-03 and P2-CAL-04 must complete adjudication
before P2-15A Gate selection.


## P2-CAL-02 completion record

P2-CAL-02 is complete in the source tree. It adds:

```text
CalibrationCaseEvaluator protocol
DeterministicFactBundleEvaluator 0.1.0
TP / FP / FN / TN confusion matrices
Precision / Recall / FPR / F1
Macro / Micro aggregation
Correlation / Evidence Confidence agreement
Coverage / Unknown visibility
Evidence completeness / duplicate / failure metrics
versioned Text / JSON Calibration Report
```

The seed replay reports 32 TP, 0 FP, 0 FN, 29 TN across 61 expectations, but
all 29 Rules are sample-insufficient. These are fact-level seed replay results,
not production parser or runtime calibration.

## 2. Calibration vocabulary

AgentSec separates four different outcomes that are often incorrectly combined
under “false positive” or “false negative”.

### 2.1 Detection false positive

The normalized Manifest facts do not satisfy the documented Rule condition, but
the Rule emits a Finding. This is an implementation defect.

### 2.2 Policy/actionability false positive

The documented static condition is present, but a reviewer decides that the
condition is acceptable under the applicable organization policy. This does not
necessarily mean the Rule engine is incorrect; it may require policy scope,
waiver, or a narrower recommendation.

### 2.3 In-scope false negative

The supported input contains enough deterministic evidence for a documented
Rule condition, but parsing, normalization, correlation, or Rule evaluation
fails to emit it.

### 2.4 Out-of-scope or runtime uncertainty

The condition cannot be established because the framework, field, identity,
OAuth scope, runtime permission, data flow, or reachability is unavailable.
This must become Coverage/Unknown or a lower Evidence Confidence result rather
than being silently counted as safe.

Calibration reports must retain these labels separately.

## 3. P2-CAL work breakdown

### P2-CAL-01: Ground-truth Case Schema and corpus

Create a versioned calibration Case format containing:

```text
case_id
framework / language / format
input roots and inert fixture assets
expected normalized Manifest facts
expected Rule IDs
expected non-matching Rule IDs
expected correlation
expected Evidence Confidence
expected Coverage / Unknown state
reviewer disposition: actionable / accepted-risk / unsupported / ambiguous
reviewer IDs or stable aliases
review rationale code
```

Do not place real secrets, internal hosts, personal data, executable helpers, or
live service dependencies in the corpus.

Initial corpus target:

```text
all 29 Capability Rule IDs represented
at least 8 positive and 8 near-miss/negative Cases per Rule family
at least 20 positive and 20 negative Cases for each proposed Hard Gate
English and Chinese instruction/control examples
complete, incomplete, Unknown, conflicting, disabled, prompt, deny, and allow
same-target, parent/child, explicit-relation, and Agent-wide correlations
```

Rule-family sharing is allowed when one Case intentionally validates several
independent conditions, but metrics must still be calculated per Rule ID.

### P2-CAL-02: Deterministic evaluation runner

Add a calibration runner that replays the labeled corpus and produces machine-
readable JSON plus a bounded Text summary. It must not modify Rules or labels.

Required confusion-matrix metrics per Rule:

```text
TP: expected condition and emitted Finding
FP: condition absent but emitted Finding
FN: condition present but Finding missing
TN: condition absent and no Finding
precision = TP / (TP + FP)
recall = TP / (TP + FN)
false_positive_rate = FP / (FP + TN)
F1 = 2 * precision * recall / (precision + recall)
```

Additional metrics:

```text
Coverage/Unknown visibility rate
correlation-class distribution
evidence-source completeness
Finding duplication rate
rule-failure rate
secret/endpoint leakage count
runtime side-effect count, which must remain zero
macro and micro precision/recall
results by framework, format, language, and scope
```

The runner must report insufficient sample size instead of presenting an
unstable percentage as calibrated.

### P2-CAL-03: Evidence Confidence calibration

Evidence Confidence is not Severity and is not a score multiplier. Calibration
checks whether the assigned grade matches the strength of the evidence path.

Current expected meanings:

| Grade | Evidence path | P2-CAL interpretation |
|---|---|---|
| A | Runtime attestation or reproducible runtime evidence | Not produced by current static Capability Rules |
| B | Same normalized target with direct source provenance | Strong static correlation |
| C | Parent/child, same-source, or explicit typed relationship | Supported but indirect static correlation |
| D | Agent-wide coexistence, incomplete Coverage, or unresolved reachability | Weak/incomplete static evidence |

Required checks:

```text
expected grade versus emitted grade confusion matrix
grade agreement percentage
per-correlation precision and recall
two-reviewer agreement for Gate candidate Cases
Cohen's kappa or an equivalent categorical agreement statistic
```

Internal calibration targets, not external-standard claims:

```text
overall Confidence grade agreement >= 90%
reviewer agreement kappa >= 0.80 for Gate candidate Cases
B-correlation condition precision >= 95%
C-correlation condition precision >= 85%
D Findings remain report-only review signals and cannot activate P2-15A Gates
```

Changing the meaning or mapping of a Confidence grade requires a Capability Risk
Model version change and ADR. A low-confidence Finding must not lower Severity,
and a high Severity must not be represented as high-confidence evidence.

### P2-CAL-03 completion record

P2-CAL-03 is complete for source development. It adds:

```text
independent ConfidenceReviewSet Schema 0.1.0
64 seeded labels for 32 matching Finding Cases
two-reviewer and multi-reviewer pair comparison
Cohen's Kappa over A/B/C/D categories
Expected-vs-Emitted agreement and Kappa
grade matrices and per Rule/Correlation metrics
bilingual Text/JSON report and bounded CLI
```

The seed labels are explicitly `seeded`. Kappa `1.000` is not independent human
review evidence and does not qualify a Rule for a Hard Gate. A-level runtime
Evidence Confidence is not produced by static Rules. The policy remains
`report_only`, CI blocking remains disabled, and Hard Gate eligibility remains
undecided. See `docs/confidence-calibration-report.md` and ADR-0036.

### P2-CAL-04 completion record

P2-CAL-04 is complete for source development. It adds:

```text
independent AdjudicationReviewSet Schema 0.1.0
122 seeded labels for 61 Case/Rule expectations
separate detection FP/FN, policy, scope, and runtime uncertainty categories
consensus and unresolved-adjudication calculation
per-Rule FP/FN metrics and deterministic tuning recommendations
HG-CAPCHAIN-001 / HG-PRODAUTO-001 / HG-EXTERNALPROD-001 candidates
report-only Gate Candidate status and reason codes
bilingual Text/JSON report and bounded CLI
```

The checked-in Seed labels produce 61 consensus results and 0 unresolved results,
but they are not independent production adjudications. All three Gate Candidates
are `more_data_required` because the seed corpus has only one positive and one
negative/near-miss sample per component Rule. No Rule is edited, no Gate is
activated, and CI remains disabled. See `docs/calibration-adjudication-report.md`
and ADR-0037.

### P2-CAL-04: Rule tuning and calibration report

Allowed tuning actions:

```text
narrow a Rule predicate
add same-target or family constraints
require complete Coverage for a Gate candidate
split one broad Rule into independent stable meanings
improve Manifest extraction or explicit Unknown handling
improve recommendation or policy context
```

Prohibited automatic actions:

```text
LLM directly editing or publishing production Rules
deleting a Finding only because Evidence Confidence is low
averaging away High/Critical Findings
changing a Rule without tests and Rule Pack version review
hiding unsupported input instead of producing Coverage/Unknown
```

The calibration report must list per Rule:

```text
sample counts
precision / recall / F1
FP and FN Case IDs
Confidence agreement
known framework and runtime limitations
recommended keep / tune / shadow / retire disposition
Hard Gate candidacy: accepted / rejected / more data required
```

## 4. Calibration acceptance before P2-15A

A Rule combination may become a Report-only Hard Gate candidate only when:

```text
at least 20 reviewed positive Cases
at least 20 reviewed negative or near-miss Cases
condition precision >= 95%
in-scope recall >= 90%
no unresolved secret or source-evidence leakage
no Rule execution failures
Coverage is complete for the matched dimensions
no relevant Unknown affects the Gate condition
correlation is B, or reviewed C for a High-only Gate
D-confidence and Agent-wide-only combinations are excluded
all Gate matches contain direct source provenance
```

A Critical-floor candidate requires same-target B evidence and all required
facts on the same normalized target. Parent/child C evidence may be considered
for a High floor but not a Critical floor in the first P2-15A version.

## 5. P2-15A: Report-only Capability Hard Gates

### 5.1 Product meaning

A Report-only Capability Hard Gate means:

```text
a deterministic high-risk condition matched
a High or Critical minimum floor is visible
the floor cannot be diluted by averaging or Confidence
hard_gate=true is included in the report
blocks=false
CLI exit behavior remains unchanged
CI remains unblocked
```

P2-15A is security metadata and prioritization, not authorization enforcement.

### 5.2 Initial Gate candidates

Final inclusion depends on P2-CAL evidence. Start with three candidates and add
at most two more only after calibration.

#### `HG-CAPCHAIN-001` — High floor

```text
execute + secret_access + external network
same target, or reviewed parent/child family
complete relevant Coverage
no relevant Unknown
```

#### `HG-PRODAUTO-001` — High floor

```text
production write / execute / deploy / publish / admin
+ effective approval allow or no effective prompt/deny
same target
complete relevant Coverage
```

#### `HG-EXTERNALPROD-001` — candidate Critical floor

```text
enabled + required external MCP
+ explicitly privileged external/production identity
+ production write or admin permission
+ no effective prompt/deny
all facts on the same target
```

This candidate must remain rejected or High-only if calibration cannot support a
Critical floor with B-confidence evidence.

Possible later candidates, initially Shadow-only:

```text
production secret access + external network + no approval
delegation + production authority, only after explicit target reachability exists
```

Persistent-memory and Agent-wide delegation combinations remain ineligible for a
Hard Gate while their evidence is D Confidence.

### 5.3 Required architecture and version review

P2-15A requires a new ADR. Adding Capability gate floors changes risk semantics,
so the expected review is:

```text
CAPABILITY_RISK_MODEL_VERSION: 0.1.0 → 0.2.0
```

The Capability Rule Pack changes only if Rule predicates or IDs change.
Capability Assessment and Change Impact output versions must be reviewed if the
serialized artifact adds Gate IDs, floors, effective scores, or Gate matches.

Recommended seam:

```text
CapabilityRuleFinding
→ DeterministicCapabilityHardGateEngine
→ CapabilityGatedFinding / CapabilityHardGateAssessment
→ Text/JSON report
```

The Gate engine accepts trusted deterministic matches only. It must not inspect
raw source text, call an LLM, or derive a Gate from a numeric average.

### 5.4 P2-15A acceptance

Scope amendment (P2-EXIT-04, ADR-0064): the original “3–5 calibrated
Gate IDs” requirement is formally rescoped to one qualified Gate plus the
governed candidate framework:

```text
1 calibrated Gate ID: HG-CAPCHAIN-001 (qualified through P2-CAL-04A)
Shadow candidates retained: HG-PRODAUTO-001, HG-EXTERNALPROD-001
  (no enforcement allow-list entry; promotion still requires the full
   reviewed evidence chain plus external Pilot evidence)
High/Critical floor uses max(base_score, strongest_floor)
Critical/High cannot be averaged away
Confidence remains unchanged and separate
D Confidence cannot match a Gate
complete/Unknown prerequisites enforced
hard_gate=true visible in English/Chinese Text and JSON
blocks=false and exit codes unchanged
Finding Delta exposes Gate added/resolved/changed state
all targeted, integration, Demo, Ruff, Mypy, and full Pytest pass
```

## 6. Pilot and Shadow Mode

P2-15A must run in report-only Shadow Mode before P2-15B. Collect:

```text
Gate match count by Gate ID
confirmed / disputed / waived outcomes
precision and recall from reviewed production-like samples
Confidence distribution
Coverage/Unknown rate
time to review and remediate
repeat-match and duplicate rate
framework and repository segment
```

Minimum promotion evidence:

```text
two calibration rounds
no unresolved Critical false positive
no known in-scope Critical false negative in the challenge set
Gate precision remains >= 95%
owners assigned for every Gate
waiver and expiry process tested
rollback and report-only fallback tested
```

## 7. P2-15B: Policy-controlled CI Enforcement

### 7.1 Preconditions

P2-15B starts only after P2-15A and Pilot acceptance. It requires a separate ADR,
Config/Policy Schema version review, and explicit product approval.

### 7.2 Policy model

Recommended policy fields:

```text
policy_version
mode: report_only / warn / enforce
enabled_gate_ids
minimum_floor
branches / environments / repository scopes
coverage_requirement
unknown_behavior
waiver requirements
policy owner
approval owner
policy hash
```

Default remains:

```text
mode = report_only
ci_blocking_enabled = false
```

Enforcement must be explicitly enabled by a trusted project or organization
policy. Scanned Agent content cannot enable, weaken, or disable the policy.

### 7.3 Waiver model

A waiver must contain:

```text
waiver_id
Gate ID
repository / Agent scope
owner
approver
reason code
creation time
expiry time
optional ticket reference
policy version
```

Waivers must be bounded, auditable, non-secret, and fail closed when expired or
invalid. A free-form comment alone is not a waiver.

### 7.4 CI decision rules

Exit `1` may represent a policy block only when all are true:

```text
analysis completed successfully
required Coverage is complete
active trusted Policy is valid
one enabled deterministic Gate matched
no valid waiver applies
Policy mode is enforce
```

Other outcomes remain separate:

```text
0 = complete, no enforcing block
1 = policy-controlled deterministic Gate block
2 = incomplete Coverage/analysis
4 = invalid artifact/config/policy
5 = required analysis failure
```

LLM output, D-confidence Findings, plain Severity thresholds, total score,
Finding count, and unsupported runtime assumptions cannot directly block CI.

### 7.5 Rollout

```text
report_only
→ warn with CI annotation but exit 0
→ enforce on selected repositories/branches
→ expand only after reviewed metrics remain within target
```

Every enforcement decision must report:

```text
Policy ID/version/hash
Gate ID and floor
direct source evidence
Coverage and Unknown state
waiver decision
exact reason for exit 1
static/runtime limitation
```

## 8. Explicit non-goals

This plan does not authorize:

```text
LLM-based CI blocking
automatic production Rule publication
runtime OAuth or permission proof
MCP exploit execution
financial-loss scoring
global Agent safety claims
unscoped permanent waivers
blocking from an incomplete scan without a separately approved fail-closed policy
```

## 9. Immediate next task

P2-CAL-01 through P2-CAL-04 source-development contracts are complete. Do not
begin P2-15A Gate implementation until the Seed labels are replaced by
independently reviewed/adjudicated Cases and the required positive/negative
sample thresholds are met.

## 27. P2-CAL-04 Independent Adjudication and Gate Candidate Report

- Status: Complete for source development
- Date: 2026-08-21
- Adjudication Review Set Schema: `0.1.0`
- Adjudication Report Output: `0.2.0`
- ADR: `docs/decisions/0037-independent-adjudication-and-gate-candidates.md`

P2-CAL-04 adds a separate adjudication contract for every Case/Rule expectation
and two or more reviewers. It preserves the distinction between deterministic
TP/FP/FN/TN, detection FP, policy-accepted risk, in-scope FN, out-of-scope
uncertainty, runtime uncertainty, and unresolved disagreement.

The Runner computes consensus only when classification, category, and
Disposition all agree. It produces per-Rule FP/FN metrics and recommendations:

```text
more_data / tune / shadow / keep
```

It also evaluates the three approved report-only Gate Candidates:

```text
HG-CAPCHAIN-001
HG-PRODAUTO-001
HG-EXTERNALPROD-001
```

Each candidate is checked against sample count, Precision, Recall, reviewer
Kappa, Confidence grade, Coverage, Unknown, and independent-label requirements.
The current Seed Corpus has 122 seeded adjudication labels for 61 expectations;
all three candidates are `more_data_required`. This is an intentional fail-
closed result and not a production Hard Gate decision.

P2-CAL-04 adds bilingual Text/JSON output and
`scripts/run-calibration-adjudication.py`. It does not modify Rules, publish
Rules, set `hard_gate=true`, enable `--fail-on`, block CI, call an LLM, verify
runtime permissions, or prove vulnerabilities.

## 28. P2-CAL-04A Corpus Expansion and Independent Reviewer Pack

- Status: Engineering preparation complete; independent human review pending
- Date: 2026-08-24
- Corpus ID: `p2-cal-04a-expanded-corpus`, Labels Version `0.2.0`
- Reviewer Pack Schema: `0.3.0`
- Adjudication Resolution Set Schema: `0.1.0`
- Adjudication Report Output: `0.3.0`
- ADR: `docs/decisions/0038-independent-review-import-provenance.md`
- Guide: `docs/calibration-adjudication-reviewer-pack.md`

P2-CAL-04A expands the draft Corpus to 216 Cases and 431 Rule Expectations and
builds a blinded Reviewer Pack with 216 opaque Cases plus 431 Rule questions
per Reviewer (862 independent review rows). ADR-0038 keeps Reviewer A/B labels
unchanged after adjudication, adds a separate `AdjudicationResolutionSet`, and
adds explicit `seed`/`human` evidence modes with no Seed Confidence fallback.
A report-only Gate Calibration Coverage Check CLI
(`scripts/check-gate-calibration-coverage.py`) verifies per-Gate unique
eligible samples with `0/2/4/5` exit semantics.

Current draft Gate coverage (labels still `seeded`):

```text
HG-CAPCHAIN-001:      25 Positive / 21 eligible Negative / 4 Unknown boundary
HG-PRODAUTO-001:      25 Positive / 21 eligible Negative / 4 Unknown boundary
HG-EXTERNALPROD-001:  25 Positive / 26 eligible Negative / 4 Unknown boundary
```

P2-CAL-04A only prepares Cases and the Reviewer Pack. Seed Labels are not
production review results; real Reviewers must be recruited and must blind
review independently before adjudication. The acceptance bar stays at least 20
reviewed Positive plus 20 reviewed Negative/Near-miss samples per Gate. All
three Gate Candidates remain `more_data_required`, enforcement remains
`report_only`, and `hard_gate=true`, CI blocking, and `--fail-on` remain
disabled. P2-CAL-04A produces no Hard Gate qualification conclusion and does
not unblock P2-15A.


## 13.6 P2-17 CVSS Base Input Adapter completion

P2-17 is complete for source development as of 2026-08-24:

```text
standalone agentsec.risk.cvss adapter 0.1.0
strict Mapping / CvssBaseInput / JSON object input
CVSS v3.1 Base vector parsing and local Base Score verification
CVSS v4.0 Base vector parsing with explicit upstream-score provenance
independent CvssBaseAssessment output
stable non-sensitive adapter error codes
ADR-0040 and docs/cvss-adapter.md
14 targeted CVSS tests; full suite remains green
```

CVSS Base remains separate from the AgentSec NIST-style `RiskAssessment`. It is
not averaged into the AgentSec score, does not change the Capability Risk Model,
and cannot enable a Hard Gate or CI block. CVSS v4.0 is structurally validated
and carries `score_verification=provided`; local v4.0 formula recalculation and
attachment to Domain Findings are deferred follow-up work.


## 13.7 P2-18 CVSS Base Finding and Assessment integration

P2-18 is complete for source development as of 2026-08-24:

```text
optional Finding.cvss nested Domain value object
CvssBaseAssessment.to_domain_cvss() and attach_to_finding() seam
Assessment Text Report CVSS Base / Vector / Verification display
Assessment JSON Report nested CVSS serialization and strict validation
Domain Schema 0.3.0 → 0.4.0
Assessment Output 0.2.0 → 0.3.0
ADR-0041 and docs/cvss-finding-integration.md
```

The AgentSec Finding score and CVSS Base score remain independent. CVSS does
not change Risk Model semantics, activate Hard Gates, block CI, or prove runtime
exploitability. Existing Findings without CVSS remain valid.


## 13.8 P2-19 Vulnerability Identity and Finding Association

P2-19 is complete for source development as of 2026-08-24:

```text
VulnerabilityReference Domain value object
strict vulnerability_id / CVE / CWE validation
explicit Finding.attach_vulnerability() association seam
Text / JSON Assessment Report vulnerability display
Domain Schema 0.4.0 → 0.5.0
Assessment Output 0.3.0 → 0.4.0
vulnerability-reference.schema.json
ADR-0042 and docs/vulnerability-association.md
```

P2-19 only accepts caller-provided explicit associations. It does not query a
vulnerability database, infer CVE/CWE from scanned text, prove a vulnerability
at runtime, trigger a Hard Gate, or block CI. These remain separate follow-up
work.


## 13.9 P2-20 CVSS v4.0 Local Base Score Calculator

P2-20 is complete for source development as of 2026-08-24:

```text
CVSS v4.0 Base MacroVector calculator
official lookup/interpolation data and maximum-severity vectors
local Score calculation with supplied-score consistency checking
score_verification=calculated
CVSS Adapter 0.1.0 → 0.2.0
deterministic v3.1/v4.0 regression coverage
ADR-0043 and docs/cvss-v4-calculator.md
```

P2-20 still accepts Base Metrics only. Temporal, Environmental, Threat, and
Supplemental metrics, runtime exploitability, CVSS Hard Gates, and CI Blocking
remain separate tasks.


## 13.10 P2-21 Extended CVSS Metrics

P2-21 is complete for source development as of 2026-08-24:

```text
CVSS v3.1 Temporal and Environmental metric parsing/calculation
CVSS v4.0 Threat and Environmental metric parsing/calculation
CVSS v4.0 Supplemental metric validation and retention
Base Score / effective Score / score_type separation
CVSS Adapter 0.2.0 → 0.3.0
Domain Schema 0.5.0 → 0.6.0
Assessment Output 0.4.0 → 0.5.0
ADR-0044 and docs/cvss-extended-metrics.md
```

Supplemental Metrics are retained as validated report data and do not alter
the numeric score in this task. CVSS database lookup, runtime verification,
CVSS Hard Gates, and CI Blocking remain separate follow-up work.


## 13.11 P2-22 Vulnerability Input CLI

P2-22 is complete for source development as of 2026-08-24:

```text
agentsec scan --vulnerability-input PATH
agentsec-vulnerability-input 0.1.0 strict JSON contract
bounded UTF-8 no-follow reader
exact Finding ID association
VulnerabilityReference and CVSS enrichment
configuration-error exit 3 on unsafe/invalid input
vulnerability-input.schema.json
ADR-0045 and docs/vulnerability-input-cli.md
```

The option is offline and report-only. It does not query a vulnerability
database, infer CVE/CWE from source text, run the Agent, enable Hard Gates, or
block CI.

## 13.12 P2-23 CVE/CWE Source Adapters and Deterministic Auto-Association

P2-23 is complete for source development as of 2026-08-24:

```text
agentsec-vulnerability-catalog 0.1.0 normalized source contract
NVD CVE JSON 2.0 adapter
strict local CVE/CWE/CVSS normalization
bounded no-follow source reader with 64 MiB limit
per-record NVD skip counters and duplicate-CVE rejection
exact single-CVE Finding text association
automatic CWE/CVSS enrichment
agentsec scan --vulnerability-source PATH
explicit --vulnerability-input remains authoritative
vulnerability-catalog.schema.json
ADR-0046 and docs/vulnerability-source-adapters.md
```

Automatic association is report-only evidence. It does not infer CVE from CWE,
does not use LLM semantic similarity, does not query remote databases, does not
execute the Agent, does not prove exploitability, and does not enable CVSS Hard
Gates or CI Blocking.

The public association method enum changed, so the source versions are:

```text
DOMAIN_SCHEMA_VERSION:     0.6.0 → 0.7.0
ASSESSMENT_OUTPUT_VERSION: 0.5.0 → 0.6.0
```

## 13.13 P2-24 CVSS Report-only Hard Gate

P2-24 is complete for source development as of 2026-08-24:

```text
CVSS effective-score threshold evaluation
High threshold >= 7.0
Critical threshold >= 9.0
CvssHardGateMatch / CvssHardGateAssessment
Finding.cvss_hard_gate
Assessment summary cvss_hard_gate_matches
Text / JSON report visibility
agentsec scan integration after CVSS enrichment
report_only mode with blocks=false
AgentSec score / Severity / generic hard_gate separation
ADR-0047 and docs/cvss-hard-gate.md
```

P2-24 does not enable CVSS CI Blocking, `--fail-on`, production enforcement,
waivers, runtime verification, or actual exploitability proof. CVSS Gate uses
`effective_score`; it does not overwrite AgentSec score or Severity.

The source versions are now:

```text
DOMAIN_SCHEMA_VERSION:     0.7.0 → 0.8.0
ASSESSMENT_OUTPUT_VERSION: 0.6.0 → 0.7.0
CVSS_HARD_GATE_VERSION:    0.1.0
```
