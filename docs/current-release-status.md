# AgentSec Current Release Status

- Authority: this is the single authoritative release/status page
  (P2-EXIT-05). When other documents disagree, this page wins.
- Date: 2026-08-31
- Companion architecture page: `docs/current-architecture.md`

## 1. Package status

```text
PACKAGE_VERSION        0.4.0       (local Phase 3 candidate)
Release target         AgentSec 0.4.0 Phase 3 Ready Candidate (P2-EXIT-08)
Latest local candidate AgentSec 0.4.0 (candidate_go, dist/0.4.0/)
Workspace              local; not a Git repository; no remote publication
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
                                          P3-01～P3-10 complete; P3-11A/P3-11B/P3-11C complete; P3-12/P3-13/P3-14 scenario metrics track complete; semantic candidates, Finding links, Rule proposals, calibration, replay, and pipeline aggregation remain non-authoritative
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
Phase 3     P3-01～P3-10 complete; P3-11A/P3-11B/P3-11C complete; P3-12/P3-13/P3-14 scenario metrics track complete; semantic candidates, Finding links, Rule proposals, calibration, replay, pipeline aggregation, and Rule Pack staging remain non-authoritative
Phase 3 B   P3-12/P3-13 corpora plus P3-14 detection metrics complete (report-only); P3-15 replay next
Phase 3 AG  P3-AG-01 complete (see section 20); P3-AG-02 next
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
Reviewer                          呈屿 (45/45 confirmed, zero edits; REVIEW-WORKSHEET.zh.md)
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
and `pilots/agentdojo-style-p3-12/README.md`. The next task on this track
is P3-15.

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
ADR-0095, and `pilots/injecagent-style-p3-13/README.md`. The next task on
this track is P3-15.

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
The next task on this track is P3-15.
