# AgentSec Capability Calibration, Hard Gate, and CI Enforcement Plan

- Status: P2-CAL-01～04 complete; P2-15A complete for HG-CAPCHAIN-001;
  P2-15B complete (Policy-controlled enforcement); scope closed by P2-EXIT-04
- Date: 2026-08-20 (scope amendment 2026-08-25, ADR-0064)
- Applies after: P2-14 Capability Rule Pack `0.2.0`
- Current Capability Risk Model: `0.1.0`
- Current enforcement: one qualified Gate (`HG-CAPCHAIN-001`) under the trusted
  Policy/Qualified Gate Registry chain; all other Gates remain shadow
  candidates. ADR-0064 formally rescopes the historical “3–5 Gates”
  acceptance to this one-Gate MVP plus candidate framework.

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

## 10. P2-CAL-04A preparation status

As of 2026-08-24, P2-CAL-04A completed the engineering preparation only:

```text
216-Case expanded draft Corpus (431 Rule Expectations)
blinded Reviewer Pack 0.3.0 for two independent human Reviewers
ADR-0038 import provenance with explicit seed/human evidence modes
report-only Gate Calibration Coverage Check CLI
docs/calibration-adjudication-reviewer-pack.md human review guide
```

Each candidate Gate now holds at least 20 draft Positive and 20 draft
Negative/Near-miss unique scenarios (25/21, 25/21, and 25/26 with 4 Unknown
boundary Cases each). These are machine-generated `seeded` labels, not reviewed
samples, so the Section 4 acceptance criteria are not met and all three Gate
Candidates stay `more_data_required`. P2-CAL-04A produces no Hard Gate
qualification conclusion: `hard_gate=true` remains disabled, CI blocking
remains disabled, and `--fail-on` remains unimplemented. P2-15A stays blocked
until real Reviewers complete blind review, a real Adjudicator resolves
disagreements, and the human-evidence report satisfies every threshold.
