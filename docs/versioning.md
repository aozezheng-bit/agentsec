# AgentSec Versioning Strategy

- Task: `P0-05`
- Status: Complete
- Decision date: 2026-08-18

## 1. Goals

AgentSec output must be reproducible and independently interpretable. Every
assessment must identify the exact scanner, schemas, rules, and risk model that
produced it. A consumer must never silently guess whether an unknown schema is
compatible.

## 2. Version vector

AgentSec maintains independent versions for:

| Identifier | Purpose | Initial value |
|---|---|---:|
| Package version | Installed CLI and Python package | `0.1.0.dev0` |
| Config schema | `.agentsec` project configuration | `0.1.0` |
| Domain schema | JSON representation of public domain models | `0.1.0` |
| Agent Manifest schema | Framework-neutral Agent declaration inventory | `0.3.0` |
| Capability Diff schema | Versioned normalized capability comparison | `0.1.0` |
| Capability Rule Pack | Structured Manifest combination-rule meanings | `0.1.0` |
| Capability Risk Model | Correlation, likelihood, impact, score, Confidence, and report-only semantics | `0.1.0` |
| Agentic Factor Model | Ten-factor Manifest capability vector | `0.1.0` |
| Threat/Mitigation Model | Static Threat Signal and bounded Mitigation vector | `0.1.0` |
| Technical Score Model | Weighted Agentic Technical Score and CVSS high-water mark | `0.1.0` |
| Drift Score Model | Capability change, source, approval, deployment, and baseline context score | `0.1.0` |
| Governance Score Model | Control maturity, Coverage, ownership, review, and waiver governance score | `0.1.0` |
| Overall Score Model | Technical/Drift/Governance high-water score and qualified Hard Gate floor | `0.1.0` |
| Scoring Replay Model | Full Agentic scoring-chain replay and component fingerprints | `0.1.0` |
| Rule/Score Calibration Report | Pilot-driven per-Rule FP/FN, profile binding, scoring replay, and version decision | `0.1.0` |
| SARIF Reporter | AgentSec mapping and strict subset for SARIF 2.1.0 delivery | `0.1.0` |
| Fail-On Policy | Explicit local High/Critical Severity exit decision | `0.1.0` |
| Fail-On Report Output | Strict wrapper around canonical Assessment plus fail-on decision | `0.1.0` |
| Organization Policy Schema | Shared Scan Rule scope and Capability Gate YAML policy | `0.1.0` |
| Organization Policy Assessment Output | Policy provenance, decision, and canonical Assessment wrapper | `0.1.0` |
| Capability CI Enforcement Output | Qualified Gate decision report | `0.1.0` |
| Capability Assessment output | Strict Manifest + Capability Finding report wrapper | `0.1.0` |
| Capability Change Impact output | Semantic Capability Change Impact and Finding Delta wrapper | `0.1.0` |
| Calibration Case schema | Versioned P2-CAL labels, normalized facts, evidence locations, and fixture index | `0.1.0` |
| CVSS Adapter | CVSS Base vector validation and deterministic Base Score adapters | `0.2.0` |
| Calibration Report output | Deterministic P2-CAL confusion-matrix and calibration metrics report | `0.1.0` |
| Confidence Review Set schema | Bounded reviewer labels for categorical Evidence Confidence agreement | `0.1.0` |
| Confidence Calibration Report output | Reviewer agreement, Cohen's Kappa, grade matrices, and Expected-vs-Emitted metrics | `0.1.0` |
| Adjudication Review Set schema | Independent reviewer classifications, categories, dispositions, and bounded Case/Rule coverage | `0.1.0` |
| Adjudication Report output | FP/FN calibration, Rule tuning recommendations, and report-only Gate Candidate assessment | `0.2.0` |
| Baseline schema | Trusted snapshot file format | `0.1.0` |
| Diff output | Text/JSON `agentsec diff` delivery contract | `0.1.0` |
| Assessment output | General machine-readable Assessment report | `0.1.0` |
| Rule pack | Rule identifiers, behavior, and default metadata | `0.1.0` |
| Risk model | Score factors, mappings, thresholds, and hard gates | `0.1.0` |

The current source of truth is `src/agentsec/versioning.py`.

## 2.1 Package version history

| Version | Task | Meaning |
|---|---|---|
| `0.1.0.dev0` | P0-02 to P1-30 | Unreleased Phase 1 development builds |
| `0.1.0` | P1-31 | First Phase 1 Markdown static-scanning PoC release |
| `0.2.0` | Phase 2 Integration Hardening | Add structured Manifest/Capability analysis, CLI, restricted Artifact I/O, bilingual Demo, and local Phase 2 release artifacts |
| `0.3.0` | P2-32 | Internal MVP with SARIF, Policy, Waivers, CI enforcement, Agentic scoring, Pilot, and Rule/Score calibration |

P2-13 and P2-14 are unreleased additive source-tree capabilities. Package
`0.2.0` remains unchanged during development; P2-13 adds Capability Change
Impact Output `0.1.0`, and P2-14 expands Capability Rule Pack `0.1.0` → `0.2.0`.
A future release review must choose the next Package version and rebuild
distribution artifacts.

## 2.2 Domain Schema history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P0-04 | Initial Phase 1 domain models |
| `0.2.0` | P1-08 | Add `asset_limit_exceeded` coverage issue for deterministic total-asset limits |
| `0.3.0` | P1-24 | Add required Config Schema and Risk Model provenance to Assessment Metadata |
| `0.4.0` | P2-18 | Add optional schema-backed CVSS Base data to Domain Findings |
| `0.5.0` | P2-19 | Add explicit VulnerabilityReference with CVE/CWE association to Domain Findings |
| `0.6.0` | P2-21 | Add extended CVSS score views and Temporal/Environmental/Threat/Supplemental metrics to Findings |
| `0.7.0` | P2-23 | Add deterministic_match vulnerability associations and normalized CVE/CWE source contracts |
| `0.8.0` | P2-24 | Add report-only CVSS Hard Gate assessment to Findings |

The `0.2.0` change is recorded in
`docs/decisions/0003-resource-limit-coverage.md`. The `0.3.0` change is recorded
in `docs/decisions/0013-assessment-text-report-and-version-metadata.md`. Because
these are pre-1.0 minor changes, consumers must explicitly support the produced
minor version rather than assume compatibility.

## 2.2.1 Agent Manifest Schema history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P2-05 | Initial strict Agent subject identity, portable sources, resolution states, instructions, tools, permissions, controls, runtime identities, relationships, Unknowns, Coverage, deterministic JSON, safe validation, and JSON Schema export |
| `0.2.0` | P2-06 | Add instruction effective order, overridden-source provenance, and deterministic resolution trace |
| `0.3.0` | P2-07 | Add source-level configuration candidates, effective precedence order, and configuration resolution trace |

Agent Manifest Schema evolves independently from the Phase 1 Domain Schema.
ADR-0022 and ADR-0023 record why raw Parser values stay outside the Manifest and why later
Resolver/Extractor tasks populate the existing typed dimensions rather than
changing current Assessment/Baseline/Diff output.


## 2.2.2 Capability Diff Schema history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P2-11 | Initial Tool, Permission, Control, Runtime Identity, Relationship, Unknown, profile-status, and Coverage comparison with value-minimizing fingerprints, source provenance, deterministic JSON, safe validation, and JSON Schema export |

Capability Diff evolves independently from the existing Phase 1 Diff Output.
P2-11 does not change the `agentsec diff` CLI delivery contract.


## 2.2.3 Capability Rule and Risk history

| Interface | Version | Task | Change |
|---|---|---|---|
| Capability Rule Pack | `0.1.0` | P2I-02 | Initial six framework-neutral Manifest combination Rules with stable IDs and bilingual trusted metadata |
| Capability Rule Pack | `0.2.0` | P2-14 | Expand to 29 stable deterministic Rules covering production/external permissions, approval/control gaps, runtime-identity declarations, memory/delegation combinations, and Unknown relationships |
| Capability Risk Model | `0.1.0` | P2I-02 | Correlation-to-Confidence and static-likelihood mappings, high-water-mark impact, NIST matrix scoring, value-free evidence, atomic isolation, and report-only policy |

These versions evolve independently from the Phase 1 Markdown Rule Pack and Risk
Model. ADR-0029 records the separation and ADR-0034 records the P2-14 Rule Pack
expansion. A change to Capability Rule conditions, IDs, correlation semantics,
likelihood, impact, Confidence, score, gate behavior, or enforcement requires
the corresponding independent version review.


### 2.2.3.1 Agentic Risk Track history

| Interface | Version | Task | Change |
|---|---|---|---|
| Agentic Factor Model | `0.1.0` | P2-18 | Ten deterministic Manifest factors with value-free evidence |
| Threat/Mitigation Model | `0.1.0` | P2-19 | Static Threat signals and bounded control multipliers |
| Technical Score Model | `0.1.0` | P2-20 | Weighted Agentic Score with optional CVSS Base high-water mark |
| Drift Score Model | `0.1.0` | P2-21 | Capability Diff change score with bounded source/approval/deployment context |
| Governance Score Model | `0.1.0` | P2-22 | Control maturity and explicit governance context risk score |
| Overall Score Model | `0.1.0` | P2-23 | Component high-water aggregation and non-dilutable qualified report-only floor |
| Scoring Replay Model | `0.1.0` | P2-24 | Frozen full-chain replay, component hashes, and suite fingerprint |

These interfaces are independent from the historical CVSS Adapter P2-20 task and
from the existing Capability Risk Model `0.1.0`. Changes require a separate version
review and replay validation.

### 2.2.3.2 SARIF Reporter history

| Interface | Version | Task | Change |
|---|---|---|---|
| SARIF Reporter | `0.1.0` | P2-25 | Add strict deterministic SARIF 2.1.0 delivery for Assessment Findings, Capability Findings, and Overall Score |
| SARIF Reporter | `0.2.0` | P2-26 | Add explicit fail-on run/invocation/Result policy properties without using SARIF level as authority |

The AgentSec SARIF Reporter version identifies the AgentSec mapping, strict subset,
properties, fingerprint keys, and security boundaries. It is independent from the
OASIS SARIF standard version `2.1.0`, Package version, Assessment Output, Capability
Assessment Output, Rule Packs, and Risk Models. ADR-0055 records the initial mapping;
ADR-0056 records the P2-26 policy-context extension.

### 2.2.3.3 Fail-On history

| Interface | Version | Task | Change |
|---|---|---|---|
| Fail-On Policy | `0.1.0` | P2-26 | Add explicit local `high|critical` AgentSec Severity threshold with Coverage precedence and exit `0/1/2` |
| Fail-On Report Output | `0.1.0` | P2-26 | Add strict JSON wrapper embedding canonical Assessment Output plus recomputable decision |

Fail-On is independently versioned from Finding Severity mappings and Assessment
Output. P2-26 does not change Risk Model `0.4.0`; it consumes the existing final
Severity only when explicitly enabled. ADR-0056 records the contract.

### 2.2.3.4 Organization Policy history

| Interface | Version | Task | Change |
|---|---|---|---|
| Organization Policy Schema | `0.1.0` | P2-27 | Add strict explicit YAML for Scan thresholds/Rule scope and Capability qualified Gates |
| Organization Policy Assessment Output | `0.1.0` | P2-27 | Add Policy SHA-256, recomputable decision, and canonical Assessment wrapper |
| Capability CI Enforcement Output | `0.2.0` | P2-27 | Add Policy source format/schema/SHA-256 provenance |
| SARIF Reporter | `0.3.0` | P2-27 | Add organization Policy/run/Result context |

ADR-0057 records the contract. P2-27 changes no Rule or risk meaning and adds no waiver semantics.



### 2.2.3.5 Rule/Score Calibration history

| Interface | Version | Task | Change |
|---|---|---|---|
| Rule/Score Calibration Report | `0.1.0` | P2-31 | Add Pilot-driven per-Rule TP/FP/FN, reviewed risk-profile hashes, frozen scoring-suite verification, calibration generation `v1`, and explicit retain/review/more-data decision |

P2-31 retains Rule Pack `0.3.0` and Risk Model `0.4.0`; report versioning does
not imply Rule or score semantics changed. ADR-0060 records this decision.

## 2.2.4 Capability Assessment Output history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P2I-03 | Initial strict `agentsec-capability-assessment` wrapper with canonical Manifest, deterministic Capability Findings, management summary, report-only policy, Stage Trace, Rule failures, safe validation, and JSON Schema export |

Capability Assessment Output evolves independently from Agent Manifest Schema,
Capability Diff Schema, and the Phase 1 Assessment Output. ADR-0030 records the
artifact boundaries and compatibility policy.

## 2.2.5 Capability Change Impact Output history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P2-13 | Initial semantic Tool/Permission/Control Change Impact and logical Capability Finding Delta wrapper |

P2-13 embeds Capability Diff `0.1.0` and keeps Package `0.2.0` during source
development. It does not change the Capability Rule Pack or Capability Risk
Model. A future release review must rebuild distribution artifacts before this
output is treated as released.


## 2.2.6 Calibration Case Schema history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P2-CAL-01 | Initial bounded Calibration Case and Corpus Index contracts with positive/negative/near-miss/Unknown labels, normalized fact states, value-free evidence locations, reviewer disposition, and safe fixture containment |

Calibration Case Schema is a source-development calibration contract. It does
not change the Agent Manifest, Capability Rule Pack, Capability Risk Model, or
CI enforcement semantics.

## 2.2.7 Confidence Calibration history

| Interface | Version | Task | Change |
|---|---|---|---|
| Confidence Review Set schema | `0.1.0` | P2-CAL-03 | Add bounded reviewer labels with reviewer/case/rule identity, categorical A/B/C/D grade, correlation, status, and safe loading contract |
| Confidence Calibration Report output | `0.1.0` | P2-CAL-03 | Add reviewer pair agreement, Cohen's Kappa, Expected-vs-Emitted agreement, grade matrices, per Rule/Correlation metrics, limitations, and report-only policy |

These are independent source-development contracts. They do not redefine
Evidence Confidence, change Severity, enable Hard Gates, or enable CI blocking.
ADR-0036 records the decision to keep reviewer observations separate from
P2-CAL-01 Case ground truth.

## 2.2.8 Adjudication and Gate Candidate history

| Interface | Version | Task | Change |
|---|---|---|---|
| Adjudication Review Set schema | `0.1.0` | P2-CAL-04 | Add bounded independent reviewer classification/category/disposition labels for every Case/Rule expectation |
| Adjudication Report output | `0.1.0` | P2-CAL-04 | Add FP/FN category separation, consensus/unresolved state, deterministic Rule tuning recommendation, and report-only Gate Candidate qualification |
| Adjudication Report output | `0.2.0` | P2-CAL-04A repair | Count candidate-scoped eligible positive/negative samples and exclude incomplete or relevant-Unknown Cases from confirmed-negative thresholds |
| Adjudication Resolution Set schema | `0.1.0` | P2-CAL-04A Agent 2 hardening | Preserve final human resolutions separately from the two original Reviewer labels |
| Adjudication Report output | `0.3.0` | P2-CAL-04A Agent 2 hardening | Add adjudication-required/completed provenance and explicit seed/human evidence modes |

These contracts do not mutate or publish Rules and do not enable Hard Gates or
CI. ADR-0037 records the fail-closed sample and independent-review decision.


## 2.3 Baseline Schema history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P1-12 | Initial strict baseline model, provenance, exact UTF-8 content, asset hashes, deterministic JSON codec, and compatibility gate |

The initial format is recorded in
`docs/decisions/0004-baseline-schema.md`. Baseline Schema evolves independently
from Domain Schema. A reader validates the top-level baseline version before
interpreting asset content or other security-significant fields.


## 2.4 Diff Output history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P1-16 | Initial redacted and escaped Text/JSON Diff CLI contract with structured errors |

The delivery decision is recorded in
`docs/decisions/0005-diff-cli-output.md`. Diff Output evolves independently from
Domain and Baseline schemas. JSON documents emit the version as
`format_version`.

## 2.5 Assessment Output history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P1-25 | Initial strict `agentsec-assessment` JSON wrapper, complete sanitized Assessment, explicit report-only policy, deterministic summary and arrays, and schema export |
| `0.2.0` | P1-27 | Add required discovered, scanned, and skipped Coverage counts to the strict Assessment summary |
| `0.3.0` | P2-18 | Add optional CVSS Base data to Finding records and regenerate the embedded Domain schema |
| `0.4.0` | P2-19 | Add optional vulnerability identity and CVE/CWE association to Finding records |
| `0.5.0` | P2-21 | Add optional effective CVSS score, score type, and extended metrics to Finding records |
| `0.6.0` | P2-23 | Add automatic CVE/CWE source association and deterministic_match provenance to Finding records |
| `0.7.0` | P2-24 | Add optional CVSS Hard Gate assessment and effective-score gate summary to Assessment output |

The initial contract is recorded in
`docs/decisions/0014-versioned-assessment-json-report.md`. Assessment Output
evolves independently from Domain Schema and Diff Output. JSON documents emit
its version as top-level `format_version`. P1-27 changes the format to `0.2.0`;
pre-1.0 `0.1.x` consumers must explicitly add support before reading it.


## 2.5.1 CVSS Adapter history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P2-17 | Strict CVSS v3.1/v4.0 Base input adaptation; v4.0 upstream Score provenance |
| `0.2.0` | P2-20 | Local CVSS v4.0 Base MacroVector calculation and supplied-score consistency checking |
| `0.3.0` | P2-21 | Add v3.1 Temporal/Environmental and v4.0 Threat/Environmental/Supplemental input and scoring |

The CVSS Adapter version is independent from Domain Schema, Assessment Output,
and the AgentSec Risk Model.

## 2.6 Rule Pack history

| Version | Task | Change |
|---|---|---|
| `0.1.0` | P0-05 to P1-19 | Versioned Rule interfaces and execution infrastructure with no production Rule IDs |
| `0.2.0` | P1-20 | Initial 15-rule Markdown pack with stable IDs, metadata, positive/negative tests, obfuscation indicators, and executable-reference detection |
| `0.3.0` | M1-01 | Expand the same 15 stable Rule meanings with reviewed Chinese triggers, Chinese positive/negative tests, localized inventory display, and a Chinese Demo |

The initial production pack is documented in `docs/rule-pack.md` and ADR-0009.
Because this is a pre-1.0 minor change, consumers supporting only `0.1.x` must
not treat results from Rule Pack `0.2.0` as semantically equivalent.


## 3. Package version

The Python package uses PEP 440-compatible versions. Releases follow semantic
intent:

- major: incompatible public CLI or Python-interface changes;
- minor: backward-compatible feature additions;
- patch: backward-compatible fixes;
- `.devN`: unreleased development builds.

Setuptools reads the package version from
`agentsec.versioning.PACKAGE_VERSION`; `pyproject.toml` does not contain a
second hard-coded package version.

## 4. Serialized interface versions

Configuration, domain schemas, baselines, Diff, Assessment, and Capability
Assessment output formats, rule packs, and risk models use exact
`MAJOR.MINOR.PATCH` identifiers.

### 4.1 Before 1.0

While `MAJOR` is zero:

- minor changes may be incompatible;
- a consumer accepts only the same major and minor version;
- patch changes must not alter required fields or meaning.

Examples:

```text
0.1.1 consumer reads 0.1.0 producer: compatible
0.2.0 consumer reads 0.1.9 producer: incompatible
```

### 4.2 At and after 1.0

After version 1.0:

- major changes are incompatible;
- minor changes may add optional fields or backward-compatible behavior;
- patch changes do not alter the serialized structure or meaning;
- a newer consumer may read an older minor version within the same major;
- an older consumer must reject a newer unsupported minor version.

## 5. Change rules

### Major increment

Required for:

- removing or renaming a public field;
- changing a field type incompatibly;
- changing the meaning of an existing enum value;
- changing a score so that identical evidence has incompatible semantics;
- changing baseline trust or verification semantics.

### Minor increment

Allowed for:

- adding optional fields;
- adding enum values when consumers explicitly support unknown-value handling;
- adding rules without changing existing rule meaning;
- adding risk factors while preserving existing factor interpretation;
- adding backward-compatible CLI behavior.

Before 1.0, these changes still increment the minor version and are treated as
potentially incompatible.

### Patch increment

Allowed for:

- documentation corrections;
- implementation fixes that preserve serialized structure and meaning;
- false-positive fixes that do not redefine a Rule ID;
- performance improvements;
- additional tests.

## 6. Rule identity policy

A Rule ID has stable meaning.

- Fixing implementation without changing meaning increments the rule-pack
  patch version.
- Materially changing trigger meaning requires a new Rule ID or a rule-pack
  major/minor increment with migration notes.
- Reusing an old Rule ID for a different risk is prohibited.
- Reports include both `rule_id` and `rule_pack_version`.
- Phase 1 Rule IDs use the validated `FAMILY-TOPIC-NNN` form.
- `RuleMetadata`, applicability, input context, and candidate Evidence/Finding
  structures are the Python Rule interface defined by ADR-0006.
- This Python seam is not a serialized Domain Schema. A breaking change requires
  an ADR and package release notes; a changed rule trigger still follows the
  Rule ID and rule-pack rules above.
- P1-18 generic Keyword/Regex/Context adapters do not define production Rule IDs,
  so they do not increment `RULE_PACK_VERSION`; their bounded matching semantics
  are recorded in ADR-0007.
- P1-19 unscored Finding fingerprints use `finding-sha256:<digest>` over Rule ID
  and authoritative Evidence locators. This internal Python identity and runner
  do not change Domain Schema, Rule Pack, or Risk Model versions; ADR-0008 records
  the contract.
- P1-20 publishes the first 15 production Rule IDs and increments Rule Pack from
  `0.1.0` to `0.2.0`; the inventory and compatibility decision are recorded in
  ADR-0009.
- P1-21 introduces the first executable likelihood, high-water-mark impact,
  NIST matrix, numeric, and Severity mappings. It increments Risk Model from
  `0.1.0` to `0.2.0`; ADR-0010 records the semantics and compatibility boundary.
- P1-22 introduces explicit A/B/C/D Evidence Confidence methods, profiles,
  rationale, limitations, and failure behavior. It increments Risk Model from
  `0.2.0` to `0.3.0`; ADR-0011 records the separation from Severity.
- P1-23 introduces report-only Hard Gate matches, High/Critical score floors,
  `max(base, floor)` aggregation, and final Finding assembly. It increments Risk
  Model from `0.3.0` to `0.4.0`; ADR-0012 records the non-enforcement boundary.
- P1-24 adds required `config_schema_version` and `risk_model_version` fields
  to Assessment Metadata and increments Domain Schema from `0.2.0` to `0.3.0`;
  ADR-0013 records why reports retain provenance instead of guessing current
  process versions.
- P1-25 introduces independent Assessment Output `0.1.0`, a strict report
  wrapper, explicit report-only policy, deterministic arrays and summary, and
  schema export; ADR-0014 records why this format is not coupled to Domain or
  Diff Output versions.
- P1-26 hardens the shared redaction implementation while preserving every
  serialized structure and existing “never output full secrets” meaning. No
  interface, Rule Pack, or Risk Model version changes; ADR-0015 records the
  detection-view and fail-closed policy.
- P1-27 adds required discovered/scanned/skipped Coverage counts to the
  Assessment JSON summary and increments Assessment Output from `0.1.0` to
  `0.2.0`; ADR-0016 records Text limits, complete JSON Issues, and the separation
  between Coverage and Findings.
- P1-28 expands and validates the inert test corpus to 40 Cases. Fixtures and
  test expectations are not production serialized interfaces, so Package,
  Schema, Output, Rule Pack, and Risk Model versions remain unchanged unless a
  fixture update reflects an actual production-semantic change.
- M1-01 expands existing Rule triggers with reviewed Chinese phrases while
  preserving all 15 Rule identities and risk meanings. It increments Rule Pack
  from `0.2.0` to `0.3.0`, adds Chinese inventory display and 45-Case replay,
  and is recorded in ADR-0017. No Schema, Output, or Risk Model changes occur.
- P2-01 adds a Python-only `StructuredParser` interface and internal JSON, YAML,
  and TOML node model. It does not add serialized Asset types or report fields,
  so no Schema, Output, Rule Pack, or Risk Model identifier changes. ADR-0018
  records the integration boundary and requires a new review when structured
  data becomes serialized or enters Baseline/Diff output.
- P2-02 adds Python-only `.rules` and MCP specialized declaration Parsers.
  Codex `.rules` values are scanned input rather than AgentSec detector Rules,
  and no declaration is serialized into production outputs yet. No interface or
  risk version changes; ADR-0019 records the non-execution and secret-omission
  boundary.
- P2-03 adds a Python-only Framework Adapter interface and neutral inspection
  models. They are not serialized in current Assessment, Baseline, or Diff
  output and do not enter Rule/Risk processing. No production version changes;
  ADR-0020 records the seam and future Manifest review requirement.
- P2-04 adds the Python-only `CodexAdapter` and an optional working-directory
  field to the Framework inspection request. Adapter results still do not enter
  current serialized output, Rule, or Risk processing, so no production version
  changes occur. ADR-0021 records explicit-root discovery, non-execution,
  precedence-hint, Coverage, and future Manifest review requirements.
- P2-05 adds independent Agent Manifest Schema `0.1.0`, deterministic JSON and
  JSON Schema interfaces, compatibility-first validation, and a source-only
  Builder. Existing Domain, Baseline, Diff, Assessment, Rule Pack, and Risk Model
  versions remain unchanged. ADR-0022 records the declaration-vs-effective
  capability boundary and source-value omission policy.
- P2-06 extends Agent Manifest Schema `0.1.0` to `0.2.0` with deterministic
  instruction inheritance, Override replacement, effective application order,
  superseded-source provenance, and resolution trace. Existing Phase 1 versions
  remain unchanged. ADR-0023 records the resolver boundary and no-content-read
  guarantee.
- P2-07 extends Agent Manifest Schema `0.2.0` to `0.3.0` with source-level
  configuration candidates, Framework/MCP/Rules roles, effective precedence
  order, and configuration resolution trace. Field-level configuration merging
  remains deferred to later capability extraction; ADR-0024 records this
  declaration-vs-value boundary.
- P2I-03 introduces independent Capability Assessment Output `0.1.0` while
  retaining canonical Agent Manifest `0.3.0` and Capability Diff `0.1.0` codecs.
  The wrapper adds policy, derived summary, Findings, Stage Trace, Rule failures,
  compatibility-first validation, and Schema export; ADR-0030 records why it is
  separate from Phase 1 Assessment Output `0.2.0`.
- P2I-04 exposes existing Manifest, Capability Assessment, Capability Diff, and
  Capability Rule contracts through new CLI commands and restricted local
  Artifact I/O. It changes no serialized or risk meaning, so interface versions
  remain unchanged; ADR-0031 records the command/exit/output boundary.
- Phase 2 Integration Hardening publishes Package `0.2.0` because the installed
  CLI/Python surface has expanded substantially while every serialized and risk
  interface retains its independent version. It also freezes Phase 2 Schemas and
  local wheel/sdist evidence; ADR-0032 records the release decision.
- P2-13 adds Capability Change Impact Output `0.1.0` as an unreleased additive
  source-tree interface. ADR-0033 records its value-minimizing semantic state,
  logical Finding matching, completeness, and report-only policy.

## 7. Risk-model policy

The risk-model version changes whenever any of these change:

- likelihood or impact mappings;
- score formulas;
- factor weights;
- severity thresholds;
- threat or mitigation multipliers;
- hard-gate conditions;
- aggregation behavior;
- Evidence Confidence definitions, method mappings, profiles, downgrade or
  upgrade behavior, and limitations.

Risk scores from different risk-model versions must not be compared as if they
were calculated by the same scale. Trend systems must retain the version and
may need to replay historical evidence using the new model.

The Phase 1 Risk Model remains independent from the Capability Risk Model.

Risk Model `0.2.0` was the first executable base-score model. Risk Model
`0.3.0` added independent A/B/C/D Evidence Confidence. Risk Model `0.4.0` adds
report-only Hard Gate floors and final effective score/Severity selection while
preserving earlier mappings. `0.1.x` was only a reserved version identifier.

## 8. Compatibility behavior

Readers must:

1. parse the version before parsing the payload;
2. reject malformed versions;
3. reject unsupported major versions;
4. apply the pre-1.0 minor compatibility restriction;
5. report a structured compatibility error;
6. never silently discard unknown security-significant fields.

The helper `can_read_interface_version` implements the initial compatibility
policy.

## 9. Report requirements

Machine-readable reports must include at least:

```text
package version
config schema version
domain schema version
rule-pack version
risk-model version
```

Serialized Agent Manifests must include `schema_version` and retain scanner,
Framework, and Adapter provenance. Their schema version is independent from the
Assessment report version vector.

The same version vector must remain visible in human-readable Assessment
reports. Assessment Metadata retains these values at creation time; renderers
must not substitute current process constants. Baseline-aware reports must also
include the baseline schema version. Diff JSON must include the independent
Diff Output version. General Assessment JSON must include the independent
Assessment Output version before policy, summary, or Domain content.
Capability Assessment reports must additionally retain the independent
Capability Assessment Output, Capability Rule Pack, and Capability Risk Model
versions rather than substituting the Phase 1 Assessment or Markdown Rule/Risk
identifiers.

## 10. Release procedure

Before changing any version identifier:

1. classify the change as package, config, domain, Agent Manifest, Capability
   Diff, Capability Assessment output, Capability Rule/Risk, baseline, Diff
   output, Assessment output, Phase 1
   rule, or Phase 1 risk;
2. decide major/minor/patch impact;
3. update the source-of-truth constant;
4. update migration or release notes;
5. regenerate affected JSON Schemas;
6. run historical fixture replay when rules or risk semantics change;
7. run the complete quality gate.


### 2.2.10 Vulnerability Source and Association history

| Interface | Version | Task | Change |
|---|---|---|---|
| Vulnerability catalog | `0.1.0` | P2-23 | Add normalized AgentSec catalog and NVD CVE JSON 2.0 adapter contract |

The catalog is an offline source-development contract. It does not enable
network access, runtime verification, exploitability proof, Hard Gates, or CI
blocking. ADR-0046 records the deterministic exact-CVE association boundary.


### 2.2.11 CVSS Hard Gate history

| Interface | Version | Task | Change |
|---|---|---|---|
| CVSS Hard Gate | `0.1.0` | P2-24 | Add deterministic High/Critical effective-score evaluation in report-only mode |

CVSS Hard Gate is separate from the generic AgentSec Hard Gate and does not
change AgentSec score, Severity, CI exit behavior, or runtime verification.
ADR-0047 records the separation.

### 2.2.12 Capability Shadow Gate history

| Interface | Version | Task | Change |
|---|---|---|---|
| Capability Shadow Gate | `0.1.0` | P2-15A-PILOT-02 | Add pilot-only `HG-CAPCHAIN-001` Shadow metadata and deterministic same-target/parent-child evaluation |

Capability Shadow Gate metadata is separate from the Capability Risk Model. The
Shadow evaluator never sets the generic `hard_gate`, never changes score,
Severity, Evidence Confidence, or CLI exit behavior, and never enables CI
blocking. ADR-0048 records the contract and the requirement for independent
human evidence before any formal P2-15A qualification.

### 2.2.13 Shadow Gate Demo Report history

| Interface | Version | Task | Change |
|---|---|---|---|
| Shadow Gate Demo Report | `0.1.0` | P2-15A-PILOT-03 | Add deterministic live Match/No-match scenarios and validated seeded Coverage metadata |

The Demo Report is a presentation and calibration-observability artifact. Its
Matrix labels are not human review evidence and its exit code `2` only denotes
incomplete sample coverage; it is not a risk or CI-blocking decision. ADR-0049
records the boundary.


## P2-EXIT-06-05A Rule Pack patch

Independent external Human Evidence identified four false negatives that
preserved existing Rule meanings. The bounded implementation correction advances
`RULE_PACK_VERSION` from `0.3.0` to `0.3.1`; Domain Schema and Risk Model remain
unchanged. Frozen 0.3.0 release artifacts retain their historical 0.3.0 vector.
