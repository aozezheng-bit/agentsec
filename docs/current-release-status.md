# AgentSec Current Release Status

- Authority: this is the single authoritative release/status page
  (P2-EXIT-05). When other documents disagree, this page wins.
- Date: 2026-09-04
- Companion architecture page: `docs/current-architecture.md`

## 1. Package status

```text
PACKAGE_VERSION        0.4.0       (local Phase 3 candidate)
Release target         AgentSec 0.4.0 Phase 3 Ready Candidate (P2-EXIT-08)
Latest preserved candidate AgentSec 0.4.0 (candidate_go, dist/0.4.0/)
Source-reconciled candidate AgentSec 0.4.0 (P3-REL-01, dist/candidates/0.4.0-p3-rel-01/)
Workspace              local Git working tree; no remote publication
```

Frozen release artifacts:

```text
agentsec-0.1.0  Phase 1 PoC            dist/ root
agentsec-0.2.0  Phase 2 integration    dist/0.2.0/
agentsec-0.3.0  internal MVP           dist/0.3.0/
agentsec-0.4.0  Phase 3 candidate      dist/0.4.0/
```

See `docs/releases/0.1.0.md`, `docs/releases/0.2.0.md`,
`docs/releases/0.3.0.md`, `docs/releases/0.4.0.md`, and each release's acceptance records.

## 2. Phase completion status

```text
Phase 0  foundation                       complete (P0-01～P0-07)
Phase 1  Markdown static scanning PoC     complete (P1-01～P1-31, 0.1.0)
Phase 2  structured capability profile    complete; P2-EXIT accepted
Phase 3  LLM and composite risk           Shadow-only started;
                                          P3-01～P3-10 complete; P3-11A/P3-11B/P3-11C complete; P3-12～P3-17 metrics, replay, Shadow Mode, and FP/FN feedback loop complete; P3-18～P3-20 semantic Gate definition/qualification, Gate-specific human Corpus, live-Pilot seam, and Evaluation Import complete (report-only; live Pilot pending organizational approval); RISK-06 Runtime Attestation / Evidence Reconciliation complete as an external-evidence import/reconciliation seam; semantic candidates, Finding links, Rule proposals, calibration, replay, and pipeline aggregation remain non-authoritative
```

## 3. P2-EXIT remediation progress (source: P2-AUDIT-01)

```text
P2-EXIT-01 Trusted Gate Qualification Registry        Complete 2026-08-25
P2-EXIT-02 Trusted CI Control Plane                   Complete 2026-08-25
P2-EXIT-03 Integrated Agentic Score CLI/Report        Complete 2026-08-25
P2-EXIT-04 Hard Gate Scope Closure                    Complete 2026-08-25
P2-EXIT-05 Documentation/Schema/Version Consolidation Complete 2026-08-25
P2-EXIT-06 External Real-project Report-only Pilot    Complete 2026-08-26
P2-EXIT-06-02 External Homi Baseline Evidence          Complete 2026-08-26
P2-EXIT-06-03 Homi PR/Change Drift Evidence            Complete 2026-08-26
P2-EXIT-06-03A Heartbeat Template/Active Calibration  Complete 2026-08-26
P2-EXIT-06-04 Final 20-State Scope/Drill Closure       Complete 2026-08-26
P2-EXIT-06-05 Independent Review/Final Acceptance      Complete 2026-08-26
P2-EXIT-06-05A Human-review FN Calibration              Complete 2026-08-26
P2-EXIT-07 Package API / Supply-chain Hardening       Complete 2026-08-25
P2-EXIT-08 Phase 3 Entry Review / 0.4.0 Candidate     Complete; candidate_go 2026-08-31
P2-EXIT-08A Two-stage Entry/Candidate State Machine   Complete 2026-08-26
P2-HOMI-01 Homi Workspace Adapter                    Complete 2026-08-25
P2-HOMI-02 Homi File Role/Precedence/Conflict Model    Complete 2026-08-25
P2-HOMI-03～05 Homi profile/combination/simulation      Complete
P2-HOMI-06 Homi real-project report-only pilot           Complete 2026-08-25
P2-HOMI-07 Homi CLI Packaging                         Complete 2026-08-25
RISK-06 Runtime Attestation / Evidence Reconciliation Complete 2026-09-04; external evidence import only
RISK-07 Runtime Attestation Trust / Replay Hardening       Complete locally 2026-09-04; report-only; Homi publish pending
```

Latest P2-EXIT-08A review artifacts:

```text
docs/reviews/phase3-entry-readiness-2026-08-26.json  (agentsec-phase3-entry-review 0.2.0)
docs/reviews/phase3-entry-readiness-2026-08-26.md    (Chinese reader-friendly rendering)
```

ADR-0077 separates `entry_readiness` from `candidate_acceptance`, removing the
old requirement to build/promote 0.4.0 before entry could become Go. The current entry decision is `ready_for_candidate`. The independently reviewed
20-State external Pilot completed with 20/20 passing Cases, FP=0, FN=0,
Precision=1.0, Recall=1.0, and `acceptance_ready=true`. Version promotion, candidate artifacts, and package
verification are evaluated later in `candidate_acceptance`. The package was explicitly promoted to `0.4.0` by the release owner on 2026-08-31 for local candidate acceptance. This does not claim remote publication or production deployment. No LLM invocation or runtime-authority path is enabled.

The historical 2026-08-25 `0.1.0` review remains an audit record but cannot
authorize candidate promotion under the `0.2.0` state machine.

P2-EXIT-08A final verification: 10 state-machine tests, 21 focused regression
tests, and 1269 full-suite tests passed; Ruff, formatting, strict Mypy, package
hardening, and fixed-epoch byte-reproducible build checks also passed.

P2-EXIT-06-03A upgraded the Homi Adapter/Profile/Pilot/Simulation provenance to
`0.2.0`, classified the documentation Heartbeat as `example_only`, removed the
baseline `HOMI-COMB-002` false positive, and made PR-03 activation drift visible.
The final calibration verification passed 71 focused tests and 1289 full-suite
tests at calibration time. After P2-EXIT-06-04/05, the current repository check
passes 1298 tests, Ruff, formatting, strict configured Mypy, package hardening,
and fixed-epoch byte-reproducible builds.


P2-EXIT-06-04 closed the complete machine scope on 2026-08-26: 20/20
engineering contracts passed across 10 Baseline and 10 PR states, with risky,
incomplete-Coverage, and active/expired Waiver lifecycle drills. P2-EXIT-06-05
adds a blinded 20-case Reviewer Pack, strict import, final replay, and automatic
P2-EXIT-08A handoff. A deleted automation-only smoke fixture reached
`ready_for_candidate`; it is not human evidence and grants no authority.

Completion records: `docs/tasks/P2-EXIT-01…05-*.md`; plan:
`docs/phase2-exit-hardening-plan.md`; audit:
`docs/reviews/phase2-completion-audit-2026-08-25.md`.

## 4. Gate and enforcement posture

```text
Qualified enforcement Gate   HG-CAPCHAIN-001 only (ADR-0064; P2-15A/P2-CAL-04A
                             human evidence; registry pinned per ADR-0062)
Shadow candidates            HG-PRODAUTO-001, HG-EXTERNALPROD-001
                             (no allow-list entry until externally qualified)
Default scan behavior        report-only (exit 0)
Deterministic blocking       explicit fail-on thresholds, organization Policy,
                             or qualified capability enforce only
Historical artifacts         qualification report v1 is superseded by v2 and
                             grants no authority
```

## 5. Key version vectors (interface provenance)

The machine-readable single source is
`agentsec.provenance.interface_provenance_registry()`; markdown rendering via
`agentsec.provenance.render_interface_provenance_markdown()`. Highlights:

```text
RULE_PACK_VERSION                     0.3.1
RISK_MODEL_VERSION                    0.4.0
DOMAIN_SCHEMA_VERSION                 0.8.0
AGENT_MANIFEST_SCHEMA_VERSION         0.3.0
ASSESSMENT_OUTPUT_VERSION             0.7.0
CAPABILITY_RULE_PACK_VERSION          0.2.0
CAPABILITY_ASSESSMENT_OUTPUT_VERSION  0.2.0
CAPABILITY_CI_POLICY_SCHEMA_VERSION   0.2.0
QUALIFICATION_REGISTRY_SCHEMA_VERSION 0.1.0
ORGANIZATION_POLICY_SCHEMA_VERSION    0.3.0
ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION 0.3.0
CAPABILITY_CI_REPORT_OUTPUT_VERSION   0.5.0
AGENTIC_ASSESSMENT_OUTPUT_VERSION     0.1.0
SCORE_CONTEXT_SCHEMA_VERSION          0.1.0
SARIF_REPORTER_VERSION                0.4.0
HOMI_ADAPTER_VERSION                  0.2.0
HOMI_PROFILE_MODEL_VERSION            0.2.0
HOMI_PILOT_FORMAT_VERSION             0.2.0
HOMI_SAFE_SIMULATION_MODEL_VERSION    0.2.0
EXTERNAL_HOMI_REVIEW_SCHEMA_VERSION   0.1.0
HOMI_BUILD_PROVENANCE_VERSION         0.1.0
HOMI_OPERATIONALITY_OUTPUT_VERSION    0.1.0
HOMI_POSTURE_OUTPUT_VERSION           0.1.0
HOMI_CALIBRATION_OUTPUT_VERSION       0.1.0
RUNTIME_ATTESTATION_REPORT_VERSION    0.1.0
EVIDENCE_RECONCILIATION_REPORT_VERSION 0.1.0
SEMANTIC_ANALYZER_VERSION             0.1.0
SEMANTIC_INPUT_SCHEMA_VERSION         0.1.0
SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION  0.1.0
SEMANTIC_OUTPUT_SCHEMA_VERSION        0.1.0
SEMANTIC_MODEL_PROVIDER_ID             offline-fixture
SEMANTIC_MODEL_ID                      agentsec-semantic-fixture-v1
SEMANTIC_PROVIDER_CONTRACT_VERSION     0.1.0
SEMANTIC_PROMPT_VERSION                0.1.0
SEMANTIC_PROMPT_SCHEMA_VERSION         0.1.0
SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION  0.1.0
SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION 0.1.0
SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION 0.1.0
SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION  0.1.0
SEMANTIC_RULE_PROMOTION_VERSION             0.1.0
SEMANTIC_RULE_PACK_STAGING_VERSION          0.1.0
```

Frozen published schemas are owned centrally
(`agentsec.provenance.schema_file_ownership()`, `schemas/README.md`).

## 6. Phase 3 entry posture

```text
P2-EXIT-06  complete: 20 States, 10 PR scans, three Drills, independent
            Human Evidence, FP/FN calibration, and final Replay accepted
P2-EXIT-07  complete: package API, lockfiles, SBOM/license evidence,
            reproducible build, and Reviewer/Human Evidence sdist exclusion
P2-EXIT-08A entry_readiness = ready_for_candidate; all five required checks pass
P2-EXIT-08 Stage 2 candidate_acceptance = candidate_go; all required checks pass
Phase 3     P3-01～P3-10 complete; P3-11A/P3-11B/P3-11C complete; P3-12～P3-17 metrics, replay, Shadow Mode, and FP/FN feedback loop complete; P3-18～P3-20 semantic Gate definition/qualification, Gate-specific human Corpus, live-Pilot seam, and Evaluation Import complete (report-only); RISK-06 Runtime Attestation / Evidence Reconciliation complete as an external-evidence import/reconciliation seam; semantic candidates, Finding links, Rule proposals, calibration, replay, pipeline aggregation, and Rule Pack staging remain non-authoritative
Phase 3 B   P3-12～P3-17 metrics, replay, Shadow Mode, and FP/FN feedback loop complete (report-only; confirmed 54-row feedback set signed); P3-18 Gate definition/qualification, P3-19 human Corpus and live-Pilot seam, and P3-20 Evaluation Import complete; RISK-06 external Runtime Attestation import/reconciliation seam complete; next step is the organization-approved P3-19 live Pilot
Phase 3 AG  P3-AG-01～P3-AG-08 complete (see sections 20, 23, 25, 26, 28);
            association API/CLI, story Demo, and calibration are report-only; next AG task is human corpus expansion
Release     local candidate accepted; remote publication and production deployment not performed
```

P2-EXIT-08 now approves Phase 3 Shadow-only entry. LLM output remains candidate
evidence only and cannot control Allow/Block, Waivers, Severity downgrade,
automatic Rule publication, or release authorization.

## 7. P3-01 semantic contract status

```text
Task                                 P3-01 Complete
Operating mode                       shadow_only
Semantic Analyzer                    0.1.0
Semantic Analysis Input Schema       0.1.0
Semantic Model Output Schema         0.1.0
Semantic Analysis Result Schema      0.1.0
Provider/Model/Prompt                 P3-02 offline fixture; P3-03 live opt-in seam
Actual model invocation              offline replay; live invocation opt-in only
Candidate authority                  none; report-only Evidence only
CI/Policy/Hard Gate influence         none
Runtime verification                 false
```

P3-01 establishes the trusted sanitized input envelope, strict untrusted model
output Schema, opaque Evidence binding, deterministic candidate identity,
Coverage/Unknown preservation, fixed Confidence `C` post-processing, and the
immutable no-tool/no-write/no-network Authority Boundary. It adds no LLM SDK,
credential, network transport, Provider selection, Prompt, or CLI command.
Semantic output is candidate evidence only. Deterministic Rules and reviewed
Policy remain the only decision authority. See
`docs/semantic-analysis-contract.md` and ADR-0082.

## 8. P3-02 offline Shadow invocation status

```text
Task                                 P3-02 Complete
Provider ID                          offline-fixture
Model ID                             agentsec-semantic-fixture-v1
Prompt version                       0.1.0
Provider transport                   in_memory_fixture
Live Provider/SDK/credential         none
Network or billable invocation       disabled
Attempts/fallback                    1 / disabled
Raw request/response retention       false
Result authority                     none; candidate Evidence only
CI/Policy/Hard Gate influence        none
```

P3-02 adds trusted Prompt construction, separate instruction/data/Schema
channels, approved Provider capability metadata, bounded request/response
contracts, timeout/token/output/zero-cost enforcement, stable safe failures,
deterministic offline fixture replay, and a content-addressed Shadow Invocation
result. It invokes no live model and adds no semantic CLI command. See
`docs/semantic-shadow-invocation.md` and ADR-0083.

## 9. P3-03 live Shadow trial and evaluation status

```text
Task                                 P3-03 Complete
Live Provider                        HTTPS JSON, explicit opt-in only
Credential                           environment-variable reference only
Default endpoint                     none configured
Default network                     disabled
Evaluation report                    report-only; no Policy/release authority
Metrics                              TP/FP/FN, Precision/Recall/F1, Evidence Binding, Coverage
Runtime verification                 false
```

P3-03 adds `LiveSemanticProvider`, explicit HTTPS and credential-reference
validation, injected transport support, bounded response handling, and the
`SemanticEvaluationHarness`. It does not configure a live endpoint or credential,
and no default CLI path performs network I/O. See `docs/semantic-evaluation.md`
and ADR-0084.

## 10. P3-04 provider-specific trial status

```text
Task                    P3-04 Complete
CLI                     agentsec semantic trial
Default provider        offline_fixture
Live provider           explicit opt-in + exact binding
Parity                  value-free Offline/Live comparison
Policy/release authority none
```

See `docs/provider-specific-semantic-trial.md` and ADR-0085.

## 11. P3-05 Provider quality and controlled promotion

```text
Quality metrics                 Precision/Recall/F1/Evidence/coverage
Human review                    independent A/B submissions + adjudication
Promotion states                review_pending → adjudication_pending → eligible_shadow → approved_shadow
Production/CI/Policy authority  false
Runtime verification             false
```

P3-05 can approve only an `approved_shadow` state after explicit owner action;
it does not promote a Provider to production or grant CI/Policy authority. See
`docs/tasks/P3-05-provider-quality-human-review-controlled-promotion.md` and
ADR-0086.

## 12. P3-06 semantic integration and Rule Candidate status

```text
Task                                 P3-06 Complete
Finding integration                  trusted path/hash/line/category only
Relationship output                  supports / duplicates / contradicts / unmatched
Rule Candidate default               review_required
Automatic Rule publication           false
Finding/Severity/Confidence mutation false
Policy/CI/Hard Gate authority        false
```

P3-06 links semantic candidates only to pre-existing deterministic Findings and
only when trusted Evidence has the same normalized path, asset SHA-256,
overlapping line range, and category. Missing or mismatched Evidence fails
closed to `unmatched`. Rule proposals use a finite trusted family mapping and
require explicit human review before an engineering implementation queue
transition; accepting a proposal does not publish or activate a Rule. See
`docs/semantic-finding-integration.md`, ADR-0087, and
`docs/tasks/P3-06-semantic-finding-integration-rule-candidate-workflow.md`.

## 13. P3-07 calibration, Finding promotion, and Rule replay status

```text
Task                                 P3-07 Complete
Candidate calibration                human labels + TP/FP/FN/TN + agreement
Finding promotion review             positive-link review only; report-only
Rule implementation replay            trusted Rule + inert RuleContext fixtures
Rule Pack mutation                   false
Finding creation/mutation             false
Policy/CI/Hard Gate authority         false
```

P3-07 adds a controlled engineering loop from semantic candidates to human
calibration, read-only Finding promotion review, and deterministic Rule replay.
Replay uses the existing `DeterministicRuleRunner` over trusted in-memory
contexts; it does not import or execute target-project code. A replay pass is
implementation evidence only and does not publish a Rule or activate CI. See
`docs/semantic-candidate-calibration.md`, ADR-0088, and
`docs/tasks/P3-07-semantic-candidate-calibration-finding-promotion-rule-replay.md`.

## 14. P3-08 Semantic Shadow Pipeline status

```text
Task                                 P3-08 Complete
Pipeline composition                 invocation + Finding links + Rule proposals
Aggregate report                    deterministic SHA-256 bound
Finding/Rule/Policy/CI authority     false
Runtime verification                 false
```

P3-08 provides a reusable application-layer `SemanticShadowPipeline` that
composes the validated Shadow invocation, P3-06 Finding integration, and Rule
Candidate workflow into one strict aggregate report. It does not load or
execute target-project code, create or mutate Findings, publish Rules, or
affect Policy/CI/Hard Gates. See `docs/semantic-shadow-pipeline.md`, ADR-0089,
and `docs/tasks/P3-08-semantic-shadow-pipeline-integration.md`.

## 15. P3-09 Trusted Input Builder and Semantic Analyze CLI status

```text
Task                                 P3-09 Complete
Trusted Semantic Input Builder       Adapter/Manifest-derived sanitized Evidence
CLI                                  agentsec semantic analyze
Default Provider                    offline_fixture; no network
Live Provider                       explicit opt-in only
Output                              Text/JSON Shadow Pipeline report
Finding/Rule/Policy/CI authority     false
Runtime verification                 false
```

P3-09 builds semantic input only from trusted Adapter records and the
deterministic Agent Manifest pipeline. It adds `agentsec semantic analyze`,
which runs the end-to-end Shadow Pipeline and writes through the hardened
ReportArtifactWriter. Offline mode emits no candidates unless an explicitly
bounded response fixture is supplied; Live mode requires explicit endpoint,
credential environment name, Provider/Model binding, and `--allow-live`. The
command never changes deterministic Finding, Rule, Policy, CI, Hard Gate, or
runtime state. See `docs/semantic-shadow-pipeline.md`,
`docs/tasks/P3-09-trusted-input-builder-semantic-analyze-cli.md`, and ADR-0090.

## 16. P3-10 Controlled Rule promotion and staging status

```text
Task                              P3-10 Complete
Assessment                        deterministic replay and proposal checks
Owner transition                  eligible_for_staging → staged
Rule Pack mutation                false
Automatic publication             false
Finding/Severity/Confidence       false
Policy/CI/Hard Gate/Release       false
Runtime verification              false
```

P3-10 adds `SemanticRulePromotionController` and the strict
`semantic-rule-promotion-report` Schema. A candidate must be explicitly
accepted for implementation, have a matching deterministic replay with zero FP,
FN, failures, and perfect replay metrics, and bind to a new trusted Rule ID
before it can be eligible for staging. An Owner approval ID and rationale are
required for `staged`. The report is immutable staging evidence only; it does
not modify the installed Rule Pack or activate any enforcement path. See
`docs/semantic-rule-promotion.md`, ADR-0091, and
`docs/tasks/P3-10-controlled-semantic-rule-promotion-rule-pack-staging.md`.

## 17. Latest verification snapshot

Executed on 2026-08-31 after P3-10 and candidate promotion:

```text
Focused P3-09 regression          5 passed
Focused P3-10 regression          7 passed
Focused P3-08 regression          4 passed
Focused P3-07 regression          5 passed
Focused P3-06 regression          9 passed
Ruff check                         pass
Ruff format                        pass; 1077 files
Strict configured Mypy            pass; 322 source files
Full Pytest                        1375 passed
Package hardening                  pass
Reproducible Wheel/sdist           byte_identical=true
Candidate Wheel SHA-256            ae0f4a07a0245df3c100fcceee477a8c6eec7548841960afda8fe880034bf14b
Candidate sdist SHA-256            6a147051cad806e1c3bc5d50bbf170722f0826098dab1ac948c630c69ce703b9b
Reproducible-build Wheel SHA-256   36de412244b1c5c466cb7145cea6e43ef1b7b9398c264a98ae4f28f8f1ca7f17
Reproducible-build sdist SHA-256   fa60642ea60348aec2e45b300ba6d43b2240406c67cef70fa55b8a3de853b78e
Artifact signature                 not_claimed
SLSA provenance                    not_claimed
```

## 18. P2-EXIT-08 Stage 2 candidate acceptance

On 2026-08-31 the release owner explicitly approved local 0.4.0 candidate
promotion. The deterministic `candidate_acceptance` state machine returned:

```text
review_stage        candidate_acceptance
state               candidate_go
status              go
acceptance_ready    true
ready_for_release   true
blocking_checks     []
```

Evidence:

```text
docs/reviews/candidate-verification-2026-08-31.json
docs/reviews/phase3-candidate-acceptance-2026-08-31.json
docs/reviews/phase3-candidate-acceptance-2026-08-31.md
dist/0.4.0/SHA256SUMS
```

`ready_for_release=true` means the local candidate passed the configured release
checks. It does not claim a Git tag, remote publication, production deployment,
artifact signature, SLSA provenance, Runtime Attestation, or LLM authority.

## 19. P3-11A human-labeled semantic evaluation corpus

```text
Task                              P3-11A Complete
Cases / judgments                 45 / 108 (supported 101, not_supported 7)
Label provenance                  ai_draft_human_confirmed (AI draft plus per-case human confirmation)
Reviewer                          internal-reviewer (45/45 confirmed, zero edits; REVIEW-WORKSHEET.zh.md)
Artifacts                         pilots/semantic-quality-p3-11/gold-labels/semantic-gold-labels.json
Authority                         report_only=true; blocks=false
```

P3-11A delivers the blinded reviewer pack, sanitized bounded corpus excerpts,
the strict fail-closed import validator, and the human-confirmed gold-label
case set that P3-11B consumes. It grants no Provider, Finding, Rule, Policy,
CI, Hard Gate, release, or runtime authority. P3-11B has since delivered the
offline semantic quality qualification gate (see the P3-11B entry in
`CHANGELOG.md` and ADR-0092). See
`docs/tasks/P3-11-real-provider-semantic-shadow-pilot-semantic-quality-qualification.md`.

## 20. P3-AG-01 attack graph node and edge schema

```text
Task                              P3-AG-01 Complete
Deliverable                       agentsec-capability-attack-graph 0.1.0
Node kinds / Edge kinds           11 / 14 with a validated endpoint matrix
Identifiers                       attack-node/edge/path-sha256 content addresses
Evidence                          value-free (asset path, digest, line range)
Authority                         report_only=true; blocks=false; all false
Path marks                        static_declared_path; runtime_verified=false;
                                  reachability=not_proven; exploitability=not_proven
Tests                             tests/test_attack_graph_p3_ag_01.py (20 passed)
```

P3-AG-01 supplies the strict Attack Graph data contract for the renumbered
P3-AG track: node, edge, graph, and static declared-path schemas, content
addressing, deterministic ordering, size bounds, a frozen JSON Schema under
`schemas/attack-graph/`, and `ATTACK_GRAPH_SCHEMA_VERSION` provenance
ownership. It contains no Manifest-to-graph builder, no path matcher, no
attack-path report, and no runtime reachability or exploitability claim.
Per the 2026-08-31 roadmap erratum, this Track is separate from the completed
Semantic P3-01～P3-10 work. See
`docs/tasks/P3-AG-01-attack-graph-node-edge-schema.md`, ADR-0093, and
`docs/threat-model.md` (TM-36). The next task on this track is P3-AG-02.

## 21. P3-12 AgentDojo-style paired injection scenario corpus

```text
Task                              P3-12 Complete
Deliverable                       agentsec-p3-12-agent-dojo-scenario-set 0.1.0
Scenarios / cases                 9 / 18 (9 normal tasks, 9 attack tasks)
Injection families                instruction_override, scanner_control,
                                  finding_suppression, hidden_instruction,
                                  command_execution, auto_approval
Languages                         zh + en (one fully Chinese scenario pair)
Label provenance                  p3-11a_gold_derived (verbatim inheritance
                                  from the human-confirmed gold set; source
                                  gold file SHA-256 bound)
Harness wiring                    build_scenario_evaluation_cases → P3-03
                                  SemanticEvaluationCase with recomputed
                                  content-addressed Evidence binding
Authority                         report_only=true; blocks=false; all false
Tests                             tests/test_semantic_p3_12.py (16 passed)
```

P3-12 records the paired normal-task and attack-task corpus for the B-line
evaluation scenario set: every scenario lists one benign task and one
injected counterpart from real repository corpus, the attack tasks must
expect a supported `instruction_integrity` judgment while normal tasks
must expect none, and the whole pack loads fail-closed. Attack success
semantics are detection-based only and belong to P3-14; no dynamic attack,
runtime reachability, or exploitability is claimed. See
`docs/tasks/P3-12-agentdojo-style-injection-scenario-corpus.md`, ADR-0094,
and `pilots/agentdojo-style-p3-12/README.md`. The B-line code chain is
complete through P3-20; the next step is the organization-approved P3-19
live Pilot.

## 22. P3-13 InjecAgent-style tool-injection scenario corpus

```text
Task                              P3-13 Complete
Deliverable                       agentsec-p3-13-injecagent-scenario-set 0.1.0
Scenarios / cases                 7 / 14 (7 benign tasks, 7 tool-injection tasks)
Injection intents                 secret_disclosure, data_forwarding,
                                  tool_commandeering (x2), external_tool_binding,
                                  destructive_action, multi_capability_chain
Languages                         zh + en (one fully Chinese scenario pair)
Label provenance                  p3-11a_gold_derived (verbatim inheritance
                                  from the human-confirmed gold set; source
                                  gold file SHA-256 recorded and test-verified)
Harness wiring                    build_injecagent_evaluation_cases → P3-03
                                  SemanticEvaluationCase via the shared
                                  Evidence-rebinding fail-closed path
Authority                         report_only=true; blocks=false; all false
Tests                             tests/test_semantic_p3_13.py (19 passed)
```

P3-13 records the tool-integration channel counterpart to P3-12: paired
scenarios whose attack tasks expect a supported tool-integration judgment
(code execution, network access, external tooling, secret access, or
destructive action) while normal tasks expect none. Attack success
semantics are detection-based only and belong to P3-14; no dynamic
tool-call observation, runtime reachability, or exploitability is claimed.
See `docs/tasks/P3-13-injecagent-style-tool-injection-scenario-corpus.md`,
ADR-0095, and `pilots/injecagent-style-p3-13/README.md`. The B-line code
chain is complete through P3-20; the next step is the organization-approved
P3-19 live Pilot.

## 23. P3-AG-02 Manifest Capability Graph Builder

```text
Task                              P3-AG-02 Complete
Deliverable                       ManifestCapabilityGraphBuilder 0.1.0 (ADR-0097)
Input                             one validated AgentManifest (no file access)
Reproducibility                   identical Manifest → byte-identical graph JSON
Manifest binding                  canonical_manifest_sha256 (== P3-09 digest)
Mapping                           identity/tools/relations/permissions/MCP/override
Authority                         report_only=true; blocks=false; all false
Paths                             () (matching reserved for P3-AG-03)
Tests                             tests/test_attack_graph_p3_ag_02.py (8 passed)
```

P3-AG-02 turns one validated Agent Manifest into a reproducible
Capability Attack Graph: identity and child agents, skill / MCP-server /
tool nodes, memory stores, secret and production targets, canonical
network/memory sinks, and one untrusted-input node per OVERRIDE
instruction candidate. Evidence stays value-free
(asset path, digest, line range) with deterministic node/edge merging and
16-Evidence fail-closed bounds; disabled tools, deny permissions, and
unmapped relation kinds emit nothing, and self-delegation fails closed.
The builder records the ADR-0097 amendment to the ADR-0093 endpoint matrix
(Manifest tool families may source `sends_to`, `writes_to`, `installs`)
and resolves the duplicate 0093 ADR by renumbering the P3-11C decision to
ADR-0096. No path matching, path report, runtime verification, or
authority claim exists yet. See
`docs/tasks/P3-AG-02-manifest-capability-graph-builder.md` and ADR-0097.
The next task on this track is P3-AG-03.

## 24. P3-14 paired-scenario detection metrics

```text
Task                              P3-14 Complete
Deliverable                       agentsec-p3-14-scenario-evaluation-metrics 0.1.0
Inputs                            one or both of the P3-12/P3-13 packs
Channels                          instruction_channel + tool_channel (sorted)
ASR semantics                     detection_based_proxy (task-level FNR on
                                  attack tasks; dynamic success never claimed)
Utility semantics                 task-level TNR on normal tasks
Other metrics                     judgment-level P/R/F1 (P3-03 semantics)
                                  plus task-level FPR/FNR
Invocations                       classified per task kind; visible
                                  invocation_failed outcome and
                                  metrics_complete=false
Coherence                         outcome counts, ASR==FNR, utility+FPR==1,
                                  rate/value fraction match all validated
Authority                         report_only=true; blocks=false; all false
Tests                             tests/test_semantic_p3_14.py (18 passed)
```

P3-14 computes the plan's evaluation metrics as detection-based
statistics over the paired scenario corpora: ASR is the share of attack
tasks with at least one missed expected judgment, Utility is the share
of normal tasks kept free of false alarms, and FPR/FNR are the matching
task-level rates. Invocation failures stay visible per task kind and
never silently dilute rates. The report freezes
`asr_semantics=detection_based_proxy` and
`runtime_attack_success_claimed=false`; no dynamic attack success, tool
reachability, or exploitability is claimed, and offline-fixture numbers
are not quality claims. See
`docs/tasks/P3-14-scenario-detection-metrics.md`, ADR-0098, and the
frozen `schemas/semantic-analysis/semantic-scenario-metrics-report.schema.json`.
The B-line code chain is complete through P3-20; the next step is the
organization-approved P3-19 live Pilot.

## 25. P3-AG-03 attack path pattern library and matcher

```text
Task                              P3-AG-03 Complete
Deliverable                       Attack Path Pattern Library 0.1.0 (ADR-0099)
Patterns                          7 builtin (five roadmap families plus the
                                  optional supply-chain family and an egress
                                  variant)
Matching                          deterministic DFS: pattern ID → node order →
                                  edge ID; attack-path-sha256 path IDs
Bounds                            per-pattern 64 / graph 256 fail-closed
Authority                         report_only=true; blocks=false; all false
Path marks                        static_declared_path; runtime_verified=false;
                                  reachability=not_proven; exploitability=
                                  not_proven
Tests                             tests/test_attack_graph_p3_ag_03.py (15 passed)
```

P3-AG-03 adds `agentsec.attack_graph.patterns` with the strict pattern
contracts and the reviewed builtin library, plus `AttackPathMatcher` whose
`match()` walks declared edges only and whose `match_into_graph()` re-emits
a fully re-validated report-only graph with matched paths. Preconditions
bind to the start node (secret exfiltration requires a `reads_secret`
edge). Bounds fail closed with `AttackPathMatchError`. The real Codex
pipeline yields delegation 1, injection 4, memory-poisoning 2, and
secret-exfiltration 1 path deterministically. `mcp-production-write` and
`tool-dependency-install` match zero paths while the builder emits no
`writes_to`/`installs` edges — the vocabulary and matcher are ready and
the boundary is disclosed in ADR-0099. No path report, evidence
association, Demo, calibration, runtime reachability, or authority claim
exists yet. See `docs/tasks/P3-AG-03-attack-path-pattern-library-matcher.md`
and ADR-0099. The next task on this track is P3-AG-04.

## 26. P3-AG-04 attack path report

```text
Task                              P3-AG-04 Complete
Deliverable                       agentsec-attack-path-report 0.1.0 (ADR-0101)
Producer                          build_attack_path_report (validated graph only)
Bindings                          manifest schema/digest + graph digest +
                                  pattern library version
Entries                           value-free per path; ≤256; sorted unique
Authority                         report_only=true; blocks=false; all false;
                                  exploitability_claimed=false
Limitations                       fixed six disclosed boundary notes
Renderer                          bounded text; boundary-first; value-free
Tests                             tests/test_attack_graph_p3_ag_04.py (12 passed)
```

P3-AG-04 adds the report surface for the Attack Graph chain: a
value-free `AttackPathReport` whose entries summarize matched static
paths without node labels, Manifest references, asset digests, or
excerpts, bound end-to-end through the Manifest and graph digests plus
the pattern library version. `build_attack_path_report` is the only
producer and fails closed outside one validated graph; the text renderer
prints the boundary first and one bounded line per path; the JSON
encoder is canonical and round-trips validation. A matched path is
explicitly not a Finding: no severity, confidence, or recommendation is
rendered and every authority boolean stays false. P3-AG-05 supplies the
separate value-minimized association report, P3-AG-06 supplies its CLI, and
P3-AG-07 supplies the presenter Demo; none claims runtime reachability or
exploitability. See section 28, ADR-0103, and ADR-0105. See
`docs/tasks/P3-AG-04-attack-path-report.md` and ADR-0101. P3-AG-04B adds
the deterministic application service and `agentsec attack-graph PROJECT`
CLI with Text/JSON output, explicit roots, stable exit codes, and hardened
same-kind artifact writing. It does not create Findings or affect Policy/CI/
Hard Gates. See `docs/tasks/P3-AG-04B-attack-graph-cli-wiring.md` and
ADR-0102. P3-AG-05, P3-AG-06, and P3-AG-07 are complete; the next task
on this track is Attack Path Evidence calibration.

P3-AG-04B CLI verification on 2026-08-31:

```text
Attack Graph CLI regression       5 passed
Attack Graph + docs/provenance    75 passed (focused)
Full Pytest                       1516 passed
Ruff / Mypy                       pass
Package hardening                 pass
Reproducible build                byte_identical=true
```

## 27. P3-15 historical sample replay suite

```text
Task                              P3-15 Complete
Deliverable                       agentsec-p3-15-scenario-replay-suite 0.1.0
Inputs                            the frozen P3-12/P3-13 packs plus 2..8
                                  ReplayRunSpec runs (adapter + semver
                                  prompt_version + run_id)
Run identity                      approved provider/model metadata
                                  cross-checked against the P3-14 metrics
                                  report; configurations must be unique
Comparisons                       adjacent run pairs per channel with
                                  before/after + deltas for ASR, utility,
                                  precision, recall, FPR, FNR
Transitions                       17-value closed vocabulary per task;
                                  failed-side transitions keep
                                  comparison_complete=false
Determinism                       byte-identical suite JSON for identical
                                  inputs (no timestamps)
Authority                         report_only=true; blocks=false; all false
Tests                             tests/test_semantic_p3_15.py (19 passed)
```

P3-15 makes model and Prompt upgrades comparable over the frozen
scenario corpora: every replay run records its configuration identity
and full P3-14 metrics report, and adjacent runs are compared per
injection channel with metric deltas and per-task outcome transitions.
Offline chains vary the Prompt version because the offline Shadow
adapter only accepts the approved fixture identity; approved live
bindings plug in without API change. A comparison is human-review
evidence only — never a promotion, rollback, qualification, or quality
claim. See `docs/tasks/P3-15-scenario-replay-suite.md`, ADR-0100, and
the frozen `schemas/semantic-analysis/semantic-scenario-replay-suite.schema.json`.
The B-line code chain is complete through P3-20; the next step is the
organization-approved P3-19 live Pilot.

## 28. P3-16 batch Shadow Mode pipeline

```text
Task                              P3-16 Complete
Deliverable                       agentsec-p3-16-semantic-shadow-mode-report 0.1.0
Batch scope                       one call runs up to 256 ShadowModeCase
                                  entries through the P3-08 pipeline
Non-blocking semantics             P3-02 stable invocation failures become
                                  failed rows (error_code, no child digest)
                                  and the batch continues; contract defects
                                  fail closed with stable codes
Rows                              value-free (analysis id, status, child
                                  pipeline_sha256, error code, candidate/
                                  link/proposal counts), sorted unique
Aggregate binding                 shadow_mode_sha256 over canonical row
                                  payloads; counts cross-checked
Authority                         operating_mode=shadow_only;
                                  blocks=false;
                                  deterministic_decisions_affected=false;
                                  all semantic authority booleans false
Tests                             tests/test_semantic_p3_16.py (14 passed)
```

P3-16 delivers the plan's Shadow Mode ("LLM 不阻断，只记录"): a batch
runner that composes the P3-05 Shadow adapter and the P3-08 single-input
pipeline case by case, records every case in a digest-bound aggregate,
and never blocks or mutates anything. A stable Provider failure is
recorded evidence, not a batch interruption; deterministic decisions,
Findings, Rules, Policies, CI gates, and releases are untouched. See
`docs/tasks/P3-16-batch-shadow-mode-pipeline.md`, ADR-0103, and the
frozen `schemas/semantic-analysis/semantic-shadow-mode-report.schema.json`.
The B-line code chain is complete through P3-20; the next step is the
organization-approved P3-19 live Pilot.

## P3-AG-05 status — Evidence association

P3-AG-05 is complete in the source tree. `AttackPathEvidenceAssociator` now
correlates static path source locators with existing deterministic Finding
Evidence and trusted Semantic Evidence chunks using normalized path, content
SHA-256, and overlapping lines. Exact, full-range, partial, and unmatched
relations are explicit and deterministically ordered. The report binds graph,
path report, Finding input, and optional Semantic result digests, retains no
source excerpts or secrets, and keeps all authority and runtime flags disabled.

The new report is source-development contract
`agentsec-attack-path-evidence-association-report` `0.1.0`; it is not a CLI
blocking surface and does not change the frozen 0.4.0 distribution. A future
CLI task may validate graph/Finding/Semantic artifacts and invoke this API.
Focused Attack Graph/provenance tests pass; full release acceptance still
requires the standard full-suite and candidate rebuild checks.


## P3-AG-06 status — Association CLI / E2E

P3-AG-06 is complete. `agentsec attack-graph-associate` accepts either a
validated Capability Attack Graph artifact or an explicit project root, reads
bounded strict Finding/Semantic inputs, invokes the P3-AG-05 associator, and
emits Text/JSON report-only output with safe atomic Artifact writing. Existing
`agentsec attack-graph PROJECT` behavior is unchanged. Valid unmatched results
remain non-blocking; malformed inputs fail safely. See
`docs/tasks/P3-AG-06-attack-path-evidence-association-cli-e2e.md` and
ADR-0104.


## P3-AG-07 status — Attack Path Story Demo

P3-AG-07 is complete. `scripts/run-attack-path-demo.sh` builds an inert
Homi-like fixture through the production Manifest/Graph pipeline, selects a
bounded story path, prepares one deterministic Finding and two Shadow Semantic
Candidates, invokes `agentsec attack-graph-associate`, and validates Text/JSON
outputs. The story visibly demonstrates `partially_supports`, `duplicates`,
and `unmatched` without executing target content or making an enforcement
decision. See `docs/tasks/P3-AG-07-attack-path-story-demo.md`,
`docs/decisions/0105-attack-path-story-demo.md`, and
`tests/test_attack_path_story_demo.py`.

## 29. P3-17 human FP/FN feedback and closed resolution loop

```text
Task                              P3-17 Complete (human review done)
Deliverables                      agentsec-p3-17-semantic-feedback-set 0.1.0,
                                  agentsec-p3-17-semantic-feedback-loop-report 0.1.0
Row contract                      one case judgment + issue type
                                  (false_positive/false_negative) + aligned
                                  rationale + Evidence IDs + draft/confirmed/
                                  rejected status; scan_coverage forbidden
Drafting                          deterministic expected-vs-predicted
                                  signature diffing over the frozen
                                  P3-12/P3-13 packs; stable invocation
                                  failures recorded as unevaluated cases
Human confirmation                reviewer_id + independence statement
                                  (>=20 chars); ai_assisted rejected;
                                  per-row confirm/reject resolved
Closed loop                       per-row resolved/unresolved/unevaluated
                                  (FP resolved ⇔ no longer predicted;
                                  FN resolved ⇔ detected again),
                                  resolution_rate over evaluated rows
Pilot draft                       pilots/semantic-feedback-p3-17/draft/:
                                  54 FN rows (honest offline fixture),
                                  submission template, Chinese worksheet
                                  (motivation: P3-11C trial P=0.394/R=0.378,
                                  FP=57/FN=61)
Confirmed set                     pilots/semantic-feedback-p3-17/confirmed/
                                  semantic-feedback-set.json — 54 rows
                                  (FN 54/FP 0), reviewer internal-reviewer, provenance
                                  ai_draft_human_confirmed (54/54 confirmed
                                  on 2026-08-31 via REVIEW-GUIDE workflow;
                                  feedback_sha256 a51af6750a63…f2c02)
Authority                         report_only=true; blocks=false; all false
Tests                             tests/test_semantic_p3_17.py (15 passed)
```

P3-17 delivers the plan's 人工反馈与标签: FP rows (over-flagged judgments)
and FN rows (missed judgments) that persist beyond a single run, a
`ai_draft_human_confirmed` confirmation workflow (the same discipline as
P3-11A gold labels), and a resolution evaluator that re-replays the same
packs and reports whether each labeled issue is now resolved after a
Provider/Prompt change. Feedback and resolution rates are human-review
evidence only; no calibration, publication, Policy, CI, gate, release, or
runtime authority is granted. The reviewer completed the worksheet on
2026-08-31 (all 54 rows confirmed, zero edits of draft judgments). See
`docs/tasks/P3-17-human-fp-fn-feedback-loop.md`, ADR-0106, and the frozen
`schemas/semantic-analysis/semantic-feedback-set.schema.json` /
`semantic-feedback-loop-report.schema.json`. The B-line code chain is
complete through P3-20; the next step is the organization-approved P3-19
live Pilot.


## P3-AG-08 status — Attack Path Evidence Calibration

P3-AG-08 is complete. `AttackPathEvidenceCalibrationRunner` compares
independent labels bound to a frozen association-report digest, distinguishes
`duplicates`, `supports`, `partially_supports`, `unmatched`, and missing rows,
and reports accuracy plus per-relation Precision/Recall/F1. A three-case seed
pilot and runnable script are checked in under `calibration/attack-path/`; the
seed is explicitly not a production qualification claim. Calibration remains
report-only and cannot mutate associations, Findings, Rules, Policy, CI, Hard
Gates, or runtime state. See
`docs/tasks/P3-AG-08-attack-path-evidence-calibration.md` and ADR-0106.

## P3-AG-09 status — Attack Path Score Integration

P3-AG-09 is complete as a report-only integration. `agentsec score` now accepts
`--attack-path-report` and optional digest-bound `--attack-path-calibration`.
The validated `AttackPathScoreContext` is emitted in Agentic Assessment JSON,
with summary metadata in Text and SARIF. The context preserves association and
calibration provenance, while literal contract constraints keep
`scoring_mode=context_only`, `numeric_score_effect=0.0`, and
`calibration_qualified=false`. Consequently Attack Path data cannot alter
Technical/Drift/Governance/Overall scores, Severity, Hard Gates, CI exit codes,
or release authority. See `docs/tasks/P3-AG-09-attack-path-score-integration.md`,
`schemas/score-context/attack-path-score-context.schema.json`, and
`tests/test_attack_path_score_integration.py`.


## P3-REL-01 status — Current Source / Candidate Artifact Reconciliation

P3-REL-01 is complete. The current source tree was rebuilt into
`dist/candidates/0.4.0-p3-rel-01/` without overwriting the preserved
`dist/0.4.0/` candidate. The reconciliation report confirms all current
`src/agentsec` modules and JSON Schemas are packaged, including P3-AG and
P3-AG-09, and the installed Wheel passes offline CLI smoke tests for
`attack-graph` and `score --attack-path-report`. Two fixed-epoch builds are
byte-identical after sdist normalization. This is a local reconciled candidate,
not remote publication, signature, SLSA provenance, runtime attestation, or
production deployment. See
`docs/tasks/P3-REL-01-current-source-candidate-artifact-reconciliation.md`,
ADR-0107, and
`dist/candidates/0.4.0-p3-rel-01/reconciliation-report.json`.

## P3-REL-02 status — Reconciled Candidate Acceptance Wiring

P3-REL-02 is complete. The existing Candidate Acceptance State Machine now
accepts `--reconciled-candidate-report` and validates the P3-REL-03 byte-level report,
current source inventory digest, root-contained Candidate directory, Wheel/sdist
SHA256SUMS, report artifact digests and sizes, fixed-epoch reproducibility, and
installed CLI smoke evidence. The current source-reconciled Candidate reached
`candidate_go` with `acceptance_ready=true`, `ready_for_release=true`, and no
blocking checks. Legacy `--candidate-verification-report` fixtures remain
supported; the preserved `dist/0.4.0/` artifacts remain unchanged. See
`docs/tasks/P3-REL-02-reconciled-candidate-acceptance-wiring.md`, ADR-0108, and
`docs/reviews/phase3-reconciled-candidate-acceptance-2026-08-31.json`.

## P3-REL-03 status — Byte-level Content Reconciliation

P3-REL-03 is complete. The source-reconciled Candidate now performs per-file
byte comparisons for every `src/agentsec/**/*.py` Wheel/sdist member, every
sdist `schemas/**/*.json` member, and the sdist copies of `pyproject.toml` and
`MANIFEST.in`. The report records Boolean content checks and bounded relative
mismatch paths without exposing source content. Duplicate archive members fail
closed. Candidate Acceptance requires the byte-level contract in addition to
the existing inventory digest, artifact hashes, reproducibility, and offline
CLI smoke evidence. The regenerated report is at
`dist/candidates/0.4.0-p3-rel-01/reconciliation-report.json` and the historical
`dist/0.4.0/` artifacts remain unchanged. See
`docs/tasks/P3-REL-03-byte-level-content-reconciliation.md` and ADR-0109.

## P3-REL-04 status — Release Manifest / Provenance Bundle Hardening

P3-REL-04 is complete. The source-reconciled Candidate now has deterministic
`release-manifest.json`, `provenance-bundle.json`, and
`PROVENANCE-SHA256SUMS` evidence. The bundle binds the Wheel/sdist, artifact
checksums, P3-REL-03 byte-level reconciliation report, current source
inventory, lockfiles, SBOM, license inventory, and explicit non-claims. The
Candidate Acceptance State Machine consumes
`--release-provenance-bundle` and validates paths, sizes, digests, the
self-excluded bundle checksum contract, build boundary, and evidence-only
authority. The historical `dist/0.4.0/` Candidate remains unchanged. See
`docs/tasks/P3-REL-04-release-manifest-provenance-bundle-hardening.md`,
ADR-0110, and
`dist/candidates/0.4.0-p3-rel-01/provenance-bundle.json`.

## P3-18 status — Semantic Gate Definition / Controlled Qualification

P3-18 is complete as a report-only qualification contract. A digest-bound
`SemanticGateCandidate` declares Gate identity, signal, minimum Positive and
Eligible Negative/Near-miss coverage, quality thresholds, Evidence Confidence
requirements, and immutable authority boundaries. The deterministic
`SemanticGateQualificationRunner` consumes P3-05 Provider Promotion, P3-07
calibration/Finding-promotion, P3-10 Rule-staging, and human confidence
evidence when supplied, and returns `qualified`, `conditionally_qualified`,
or `not_qualified`. Missing required evidence is pending; it is never treated
as a pass. The output cannot block CI, publish Rules, approve Waivers, alter
Severity/Score, grant runtime authority, or authorize release. The Gate
authority contract explicitly fixes `can_block_ci=false` and
`can_publish_rule=false`.
`docs/tasks/P3-18-semantic-gate-definition-controlled-qualification.md`,
ADR-0111, and
`schemas/semantic-analysis/semantic-gate-qualification-report.schema.json`.

## P3-19 status — Human Corpus / Real Provider Pilot

```text
Task                              P3-19 Complete (code chain; live run pending approval)
Subtasks                          P3-19-01～P3-19-05 all Complete
Corpus                            41-case Gate-specific Human Corpus (reviewed,
                                  adjudicated, digest-bound)
Pilot preflight                   fail-closed; current status preflight_blocked
Live authority                   none; organizational approvals pending
```

The new path is still Shadow-only and report-only. No real endpoint or credential is
configured in the repository. A live result cannot be claimed until the organization
provides the endpoint, credential environment, cost approval, data-residency approval,
retention-policy approval, and a current Gate-specific human Corpus.

P3-19 Pilot execution on 2026-09-01 used the 41-case Gate-specific Human Corpus and
human-corpus-bound Candidate. Fail-closed preflight passed Corpus integrity, Gate binding,
Human Review completeness, and call budget checks, but returned `preflight_blocked` because
no approved HTTPS endpoint, credential environment, live opt-in, or organizational approval
was present. No network was accessed and no Provider quality claim was made.

## P3-20 status — Provider Evaluation Import / Semantic Gate Qualification

P3-20 is complete (offline chain, 2026-09-01). `SemanticGateEvaluationImport`
binds the current Gate Candidate, the Gate-specific Human Corpus, the
Provider/Model/Prompt contract, and a Provider Evaluation or completed
live-Pilot report digest into one fail-closed import; a `preflight_blocked`
or failed Pilot cannot be imported as Provider Evaluation.
`qualify_semantic_gate_evaluation()` runs the P3-18 deterministic
qualification without a second Provider call, and `promote_report_only()`
emits report-only promotion evidence that fixes `can_block_ci=false` and
`can_publish_rule=false`. The equivalent CLI is `agentsec semantic gate-qualify`.
The current P3-19 live Pilot remains `preflight_blocked` because no approved
endpoint or credential is configured; therefore no real Provider quality
claim is made yet. See
`docs/tasks/P3-20-provider-evaluation-import-semantic-gate-qualification.md`,
ADR-0113, and
`schemas/semantic-analysis/semantic-gate-evaluation-import.schema.json`.

Latest verification snapshot (2026-09-01, after P3-18/P3-19/P3-20):

```text
Full Pytest (serial)               1604 passed
Ruff / Ruff format                 pass
Mypy (strict, configured)          pass
Candidate artifacts                rebuilt current; release-bundle tests pass
```

Serial full-suite runs pass consistently; concurrent full-suite runs can
produce one-off subprocess contention failures unrelated to this change.

## 32. Homi recalibration status (2026-09-03)

```text
P3-HOMI-RECAL-02  local complete: build fingerprint, package digest, Heartbeat regression
P3-HOMI-RECAL-03  local complete: template/latent/active/runtime_attested sidecar
P3-HOMI-RECAL-04  local complete: raw/calibrated potential impact and current posture split
P3-HOMI-RECAL-05  local complete: deterministic HOMI-COMB-003/004 calibration sidecar
P3-HOMI-RECAL-06  local verification complete; Homi remote publication paused
```

The current-turn implementation produces `homi-build-fingerprint.json`,
`homi-operationality.json`, `homi-posture.json`, and `homi-calibration.json`.
`homi bundle` consumes same-directory Sidecars only when their
`source_report_sha256` binds them to the Pilot JSON. Static Homi reports remain
report-only: `runtime_verified=false`, `ci_blocked=false`, and no Sidecar grants
runtime or release authority. GitHub/Homi synchronization remains pending a
clean candidate isolation, package fingerprint comparison, and explicit release
approval.


## RISK-07 implementation status

RISK-07 is complete in the local source candidate. Runtime Attestation 0.2
requires `key_id`, `signature_algorithm`, `issued_at`, `expires_at`, `nonce`,
and detached signature. `TrustedRuntimeIssuer` and `RuntimeTrustRegistry`
provide explicit trust roots without storing secrets.

`agentsec homi reconcile-runtime` now emits:

```text
homi-runtime-trust-verification.json
homi-runtime-reconciliation.json
homi-runtime-replay-store.json
```

Trust failure, missing registry, stale/future evidence, revoked/unknown key,
invalid signature, replay, or replay-store failure keeps
`runtime_verified=false` and Evidence Confidence D. Trust plus partial/conflict
reconciliation is B; trust plus complete reconciliation is A. The entire path
remains `report_only=true`, `policy_authority=false`, and `ci_blocked=false`.

External Endpoint, credential, KMS, data-retention, and Homi publication
approvals remain organizational prerequisites for a real runtime pilot.
