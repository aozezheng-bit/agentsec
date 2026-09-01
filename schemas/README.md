# AgentSec JSON Schemas

These files are generated from the current source of truth:

```bash
PYTHONPATH=src python3.12 scripts/export_release_schemas.py
```

## Layout and ownership

Every frozen schema file belongs to exactly one versioned source-of-truth
interface. The central ownership map is
`agentsec.provenance.schema_file_ownership()`
(P2-EXIT-05); `tests/test_provenance_registry.py` enforces that the map stays
byte-complete with the files below.

```text
schemas/agentic-assessment/        Agentic Assessment Output 0.1.0
schemas/assessment/                Assessment Output 0.7.0 + Fail-On Report 0.1.0
schemas/attack-graph/              Capability Attack Graph (Nodes/Edges/Paths)
                                   0.1.0 + Attack Path Report 0.1.0
schemas/baseline/                  Baseline Schema 0.1.0
schemas/calibration/               Calibration Case/Corpus/Report 0.1.0,
                                   Confidence Review/Report 0.1.0,
                                   Adjudication Review 0.1.0 / Resolution 0.1.0 /
                                   Report Output 0.3.0,
                                   Rule-Score Calibration Output 0.1.0,
                                   Joint Expert Evidence 0.1.0,
                                   Shadow Gate Demo 0.1.0
schemas/capability-assessment/     Capability Assessment Output 0.2.0
schemas/capability-change-impact/  Capability Change Impact Output 0.1.0
schemas/capability-diff/           Capability Diff Schema 0.1.0
schemas/domain/                    Phase 1 Domain Schema 0.8.0 (including
                                   CvssBase, CvssHardGate*, and
                                   VulnerabilityReference)
schemas/manifest/                  Agent Manifest Schema 0.3.0
schemas/pilot/                     Pilot Plan/Report/Human Labels 0.1.0,
                                   External Review Submission 0.1.0
schemas/policy/                    Organization Policy 0.3.0, Organization
                                   Assessment Output 0.3.0, Qualified Gate
                                   Registry 0.1.0
schemas/score-context/             Agentic Score Context Schema 0.1.0; Attack Path Score Context 0.1.0
schemas/semantic-analysis/         Semantic Analysis Input 0.1.0,
                                   constrained Model Output 0.1.0,
                                   Shadow-only Analysis Result 0.1.0,
                                   Finding Integration and Rule Candidate Reports 0.1.0,
                                   Candidate Calibration, Finding Promotion Review,
                                   and Rule Implementation Replay Reports 0.1.0,
                                   End-to-end Shadow Pipeline Report 0.1.0,
                                   Controlled Rule Promotion / Rule Pack Staging Report 0.1.0,
                                   Prompt Envelope 0.1.0,
                                   Provider Request/Response 0.1.0,
                                   Shadow Invocation Result 0.1.0,
                                   Evaluation/Parity Reports 0.1.0,
                                   Trial Config/Case/Response Sets 0.1.0,
                                   P3-14 Scenario Detection Metrics Report 0.1.0,
                                   P3-15 Scenario Replay Suite 0.1.0,
                                   P3-16 Shadow Mode Report 0.1.0,
                                   P3-17 Feedback Set + Loop Report 0.1.0
schemas/vulnerability-catalog/     Offline normalized CVE/CWE Catalog 0.1.0
schemas/vulnerability-input/       Vulnerability Input Schema 0.1.0
```


`assessment-fail-on-report.schema.json` is the P2-26 explicit local Policy Gate
wrapper. It embeds the canonical sanitized Assessment Output `0.7.0` and adds a
strict deterministic `high|critical` Severity decision. It is emitted only when
`agentsec scan --fail-on` is explicitly selected; default Assessment JSON stays
unchanged.

The current source-tree Domain and Assessment schemas are versioned source-of-truth
contracts. They are newer than the historical accepted 0.1.0/0.2.0 release
artifacts because P2-18 and P2-19 add optional CVSS and vulnerability-reference
data to Findings. AgentSec 0.2.0 release artifacts remain historical.

The Capability Change Impact Schema is the P2-13 source-development contract. It
is not included in the accepted `dist/0.2.0/` artifacts until a separate release
review rebuilds and accepts a new distribution.

The Phase 1 `agentsec diff` CLI JSON contract remains Diff Output `0.1.0` and
does not have a separate JSON Schema exporter. Capability Diff and Capability
Change Impact are separate, strict Schema-backed artifacts.

Consumers must validate the appropriate Schema or Output version before reading
security-significant fields. Package version compatibility must not be used as a
substitute for interface-version validation.

The P3-01 semantic-analysis Schemas define a contract-only Shadow seam. The
input contains bounded sanitized Evidence, the model-output Schema forbids
Severity/Confidence/Allow/Block/Rule/Waiver authority fields, and the final
result is fixed to `report_only=true`, `runtime_verified=false`, and
`blocks=false`. No Provider, Model, Prompt, credential, or model invocation is
configured by these Schemas.

P3-02 adds the Prompt, Provider request/response, and Shadow Invocation Schemas.
They approve only the non-billable in-memory fixture Provider/Model identity,
separate trusted instructions from untrusted data, bind timeout/token/zero-cost
limits, retain no raw payloads in the final artifact, and preserve
`report_only=true`, `runtime_verified=false`, `blocks=false`, and
`policy_authority=false`. They do not configure a live Provider or network
transport.


The calibration schemas are source-development contracts for P2-CAL-01 through
P2-CAL-04A. They contain only bounded labels, normalized fact keys, categorical
reviewer grades, value-free evidence locations, and portable fixture paths.
They do not contain runtime credentials, raw source excerpts, commands, URLs, or
authorization decisions. `confidence-review-set.schema.json`, `confidence-calibration-report.schema.json`,
`calibration-adjudication-set.schema.json`,
`calibration-adjudication-resolution-set.schema.json`, and
`calibration-adjudication-report.schema.json` are generated by
`scripts/export_release_schemas.py`.

P2-CAL-04A adds the Adjudication Resolution Set Schema `0.1.0` and advances the
Calibration Adjudication Report Schema to Output `0.3.0` (candidate-scoped
eligible samples, separate Reviewer-agreement and adjudication state, and
explicit `seed`/`human` evidence modes per ADR-0038). These remain report-only
calibration contracts: they carry no Hard Gate authorization, enable no CI
blocking, and Seed Labels remain excluded from production review evidence.
schemas/vulnerability-catalog/  Offline normalized CVE/CWE Catalog Schema 0.1.0
schemas/domain/                    includes CvssHardGateMatch and CvssHardGateAssessment

`joint-expert-review-evidence.schema.json` is a source-development schema for
P2-15A-PILOT-01. It describes consensus labels produced by experts reviewing
together. The artifact is content-addressed and explicitly pilot-only; it is
not independent Reviewer A/B evidence, formal P2-CAL-04 Human Evidence, or a
Hard Gate qualification record.

`capability-shadow-gate-demo.schema.json` is the P2-15A-PILOT-03 report-only
Demo contract `0.1.0`. It combines deterministic live Shadow scenarios with
validated, seeded Gate Coverage metadata. It does not qualify a Gate, enable
`hard_gate=true`, or enable CI blocking.


The P2-EXIT-06 Pilot contracts add `pilot-human-labels.schema.json` and
`external-pilot-review-submission.schema.json`. They store only independently
reviewed expected exit, Coverage, deterministic Rule IDs, a bounded rationale,
and manifest binding. They do not store scanner observations, source excerpts,
secrets, runtime exploit claims, or CI authority.


P3-03 adds `semantic-evaluation-report.schema.json`. It stores only bounded case
IDs, expected/predicted counts, Precision/Recall/F1, Evidence binding accuracy,
Coverage, and safe Provider error codes. It is a Shadow trial quality report:
`report_only=true`, `policy_authority=false`, `release_authority=false`, and
`runtime_verified=false`. It contains no raw model response, credential,
source excerpt, endpoint, or enforcement decision.


P3-04 adds protected trial Config/Case/Response Set Schemas and a
Offline/Live Parity Report Schema. The trial config stores only endpoint and
credential environment-variable names, never credential values. The case and
response fixtures are bounded strict contract objects; the parity report stores
only value-free status, prediction parity, and Evidence parity.


P3-06 adds `semantic-finding-integration-report.schema.json` and `semantic-rule-candidate-report.schema.json`. They are report-only contracts: links are based on trusted static Evidence overlap, and Rule proposals remain review-required. Neither schema permits Finding mutation, Severity/Confidence authority, automatic Rule publication, Policy changes, or CI blocking.

P3-07 adds `semantic-candidate-calibration-case.schema.json`, `semantic-candidate-calibration-report.schema.json`, `semantic-finding-promotion-report.schema.json`, and `semantic-rule-implementation-replay-report.schema.json`. These contracts contain human calibration and deterministic replay evidence only; they cannot create or modify Findings, publish Rules, or authorize Policy/CI/Hard Gates.

P3-08 adds `semantic-shadow-pipeline-report.schema.json`, an aggregate report for one Shadow invocation, report-only Finding integration, and Rule Candidate generation. It has no Finding, Rule Pack, Policy, CI, Hard Gate, or runtime authority.

P3-09 adds the trusted Adapter/Manifest-derived input construction path and the `agentsec semantic analyze` CLI. Its output uses `semantic-shadow-pipeline-report.schema.json`; offline mode is the default and live mode is explicit opt-in.


P3-AG-05 adds `attack-path-evidence-association-report.schema.json`. It is a
report-only correlation artifact: static graph source locators can be joined
to existing file/diff Finding Evidence and trusted Semantic Evidence chunks by
normalized path, content digest, and line overlap. It contains no source
excerpts, credentials, endpoints, or secrets and cannot create or mutate
Findings, affect Severity/Confidence, or authorize Policy/CI/Hard Gates.


P3-AG-08 adds `attack-path-calibration-report.schema.json`. It compares
independent human labels with a frozen association report using exact, partial,
and unmatched relation classes. The report exposes accuracy and one-vs-rest
metrics plus unreviewed-association count; it remains report-only and cannot
change the associator, Findings, Severity, Confidence, Policy, CI, or Hard Gates.


P3-AG-09 adds `score-context/attack-path-score-context.schema.json`. It is a
report-only projection of a validated Attack Path Evidence Association Report
and optional bound calibration report. It is context-only: its literal
`numeric_score_effect=0.0` and `calibration_qualified=false` prevent static path
counts or fixture calibration from changing the Agentic Score or granting any
Hard Gate/CI authority.

P3-19 Semantic Gate evidence Schemas:

- `semantic-analysis/semantic-gate-human-corpus.schema.json`
- `semantic-analysis/semantic-gate-review-submission.schema.json`
- `semantic-analysis/semantic-gate-pilot-config.schema.json`
- `semantic-analysis/semantic-gate-pilot-report.schema.json`

P3-20 Semantic Gate Evaluation Schemas:

- `semantic-analysis/semantic-gate-evaluation-import.schema.json`
- `semantic-analysis/semantic-gate-report-only-promotion.schema.json`
