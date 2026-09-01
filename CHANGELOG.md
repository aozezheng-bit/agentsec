# Changelog

## P3-20 — Provider Evaluation Import / Semantic Gate Qualification (2026-09-01)

- Added Candidate/Corpus/Provider/Model/Prompt/Evaluation Digest binding.
- Added fail-closed Evaluation Import for the current Gate-specific Human
  Corpus.
- Added deterministic Semantic Gate Qualification without a second Provider
  call.
- Added explicit report-only Promotion Evidence and
  `agentsec semantic gate-qualify`.
- Real Provider quality remains pending the approved P3-19 live Pilot.

## P3-19 — Semantic Gate Human Corpus / Real Provider Pilot (2026-09-01)

- Added digest-bound Gate-specific Human Corpus and reviewer/adjudication
  import contracts.
- Added Positive / Eligible Negative / Near-miss / Unknown coverage accounting
  and P3-18 integration.
- Added fail-closed Real Provider Pilot approval preflight, bounded
  report-only runner, and CLI.
- Added frozen JSON Schemas and tests; no live endpoint or credential is
  configured.

## P3-18 — Semantic Gate Definition / Controlled Qualification (2026-09-01)

- Added digest-bound Semantic Gate candidates with explicit sample, quality,
  coverage, human-confidence, and authority contracts.
- Added deterministic report-only qualification with pass/pending/fail checks
  and integration points for P3-05, P3-07, and P3-10 evidence.
- Added Candidate creation and qualification CLIs plus strict schemas and
  report-only regression coverage.

## P3-REL-04 — Release Manifest / Provenance Bundle Hardening (2026-08-31)

- Added deterministic `release-manifest.json`, `provenance-bundle.json`, and
  `PROVENANCE-SHA256SUMS` generation for the source-reconciled Candidate.
- Bound artifact, P3-REL-03 reconciliation, source inventory, supply-chain,
  build-boundary, and explicit non-claim evidence into one fail-closed bundle.
- Wired the bundle into Candidate Acceptance without granting signatures,
  SLSA, Runtime Attestation, publication, CI, or production authority.

## P3-REL-03 — Byte-level Content Reconciliation (2026-08-31)

- Added per-file byte comparisons between the current source and Candidate
  Wheel/sdist members for Python modules, Schemas, `pyproject.toml`, and
  `MANIFEST.in`.
- Added bounded content-match and mismatch-path evidence to the reconciliation
  report and required it in Candidate Acceptance; duplicate archive members
  fail closed.
- Added tamper regression coverage while preserving the historical
  `dist/0.4.0/` Candidate and report-only security boundary.

## P3-REL-01 — Current Source / Candidate Artifact Reconciliation (2026-08-31)

- Added `scripts/reconcile-candidate-artifacts.py` to build and verify a new
  source-reconciled candidate without overwriting the preserved `dist/0.4.0/`.
- Added fixed-epoch Wheel/sdist reproducibility, source-module/Schema inclusion
  checks, offline installed-CLI smoke tests, and P3-AG/P3-AG-09 package checks.
- Published the local candidate under
  `dist/candidates/0.4.0-p3-rel-01/`; signatures and SLSA provenance remain
  unclaimed.


## Unreleased — 2026-08-31 — P3-17 Human FP/FN Feedback and Closed Resolution Loop (ADR-0106)

- add `agentsec.semantic.feedback` with the versioned
  `agentsec-p3-17-semantic-feedback-set` and
  `agentsec-p3-17-semantic-feedback-loop-report` families: digest-bound
  false-positive/false-negative rows, a deterministic AI draft builder,
  a human confirmation builder, and a closed-loop resolution evaluator;
- implement the row contract: one case judgment (kind, category,
  disposition) plus issue type (`false_positive`/`false_negative`) with
  an aligned closed rationale vocabulary (`missed_judgment`/
  `overflagged_judgment`), the case Evidence IDs, and draft/confirmed/
  rejected status; rows cannot target `scan_coverage`;
- draft deterministically from expected-versus-predicted signature
  diffing over the frozen P3-12/P3-13 packs (shared normal cases
  deduplicate; divergent duplicates fail closed); stable invocation
  failures become unevaluated cases, never fabricated rows;
- require human confirmation: `ai_assisted` provenance is rejected,
  reviewer identity and a >=20-character independence statement are
  enforced, and confirmed sets reject leftover draft rows;
- evaluate the closed loop per row with issue-type-specific semantics
  (an FP row is resolved when the judgment is no longer predicted; an FN
  row is resolved when the expected judgment is detected again), a
  `resolution_rate` over evaluated rows, invocation failures kept
  unevaluated with `evaluation_complete=false`, and a loop digest
  binding the feedback digest plus run identity;
- ship the pilot draft pack at
  `pilots/semantic-feedback-p3-17/draft/`: 54 false-negative rows from
  the honest offline fixture (predicts nothing), a submission template,
  and a Chinese review worksheet referencing the P3-11C real-provider
  trial (precision 0.394 / recall 0.378, FP=57 / FN=61) as motivation;
- add the fail-closed `scripts/import-p3-17-feedback.py` importer and
  the idempotent `scripts/build-p3-17-feedback-pack.py` generator;
  register both version vectors and their frozen Schemas
  (`semantic-feedback-set.schema.json`,
  `semantic-feedback-loop-report.schema.json`) with provenance ownership
  and export-script wiring;
- add ADR-0106, the task record, and 15 tests covering FP/FN drafting
  precision, confirmation, tampering, loop resolution in four regimes,
  determinism, round-trips, frozen-schema byte identity, and corpus
  non-disclosure; keep every authority boolean false — the confirmed set
  itself awaits the human reviewer;
- add the interactive expert workflow for the remaining human step:
  `scripts/review-p3-17-feedback.py` walks the reviewer through every
  draft row with the case's sanitized evidence text, per-row
  confirm/reject decisions with bounded notes, resumable progress
  (`draft/review-progress.json`), bulk-confirm of remaining rows with
  explicit consent, automatic submission finalization (reviewer id plus
  an editable independence statement), optional fail-closed import plus
  set verification, and the `REVIEW-GUIDE.zh.md` runbook (keys,
  recovery, exit codes, authority boundary);
- complete the human review: all 54 draft rows were reviewed and
  confirmed by 呈屿 on 2026-08-31 through the REVIEW-GUIDE workflow
  (provenance ai_draft_human_confirmed, zero draft-judgment edits);
  the confirmed set landed at
  `pilots/semantic-feedback-p3-17/confirmed/semantic-feedback-set.json`
  (feedback_sha256 a51af6750a636ab8466f91d3feab6c8ed0eaf5ab92aff6c2a145
  dfc148fb6c02) and closed-loop spot checks resolved 54/54 for a
  gold-echoing provider and 0/54 for the zero-output fixture.

## Unreleased — 2026-08-31 — P3-16 Batch Shadow Mode Pipeline (ADR-0103)

- add `agentsec.semantic.shadow_mode` with the versioned
  `agentsec-p3-16-semantic-shadow-mode-report` family: a batch Shadow
  Mode runner over up to 256 cases that records every case and never
  blocks, composing the P3-05 Shadow adapter and the P3-08
  single-input pipeline instead of duplicating Shadow logic;
- implement the plan's non-blocking semantics: a case whose invocation
  raises a P3-02 stable `SemanticShadowInvocationError` becomes a
  `failed` row with `error_code` and zero child digest while the batch
  continues; contract defects (wrong types, duplicate analysis IDs,
  bound violations, missing pipeline, invalid adapter) fail closed with
  stable `ShadowModeError` codes;
- record value-free per-case rows (status, child `pipeline_sha256`,
  error code, candidate/link/proposal counts) sorted and unique, with
  an aggregate `shadow_mode_sha256` digest over the canonical row
  payloads and counts cross-checked against the rows;
- freeze the non-blocking authority: `operating_mode=shadow_only`,
  `blocks=false`, `deterministic_decisions_affected=false`, plus the
  semantic finding/rule/severity/policy/ci/runtime false literals — a
  batch run only adds recorded evidence and never changes
  deterministic decisions, Findings, Rules, Policies, CI, or releases;
- register `SEMANTIC_SHADOW_MODE_SCHEMA_VERSION` and
  `SEMANTIC_SHADOW_MODE_OUTPUT_VERSION` (report family `0.1.0`), central
  schema file ownership, the frozen
  `schemas/semantic-analysis/semantic-shadow-mode-report.schema.json`
  export, and export-script wiring;
- add ADR-0103, the task completion record, and 14 P3-16 tests covering
  batch counting, non-blocking failure rows, determinism, round-trip
  encoding, frozen-schema byte identity, fail-closed inputs, and corpus
  non-disclosure.

## Unreleased — 2026-08-31 — P3-AG-04B Attack Graph CLI Wiring

- add `DeterministicAttackGraphAnalysisEngine` to compose Manifest analysis,
  graph building, path matching, and the P3-AG-04 report;
- add `agentsec attack-graph PROJECT` with Text/JSON output, explicit roots,
  stable exit codes, and hardened same-kind artifact writing;
- add `ATTACK_PATH_REPORT` artifact validation, public API exports, CLI tests,
  and P3-AG-04B task/ADR documentation;
- preserve static-declared-path, report-only, no-runtime, no-Finding, no-Policy,
  no-CI, no-Hard-Gate, and no-release authority boundaries.

## Unreleased — 2026-08-31 — P3-AG-04 Attack Path Report (ADR-0101)

- add the frozen `agentsec-attack-path-report` `0.1.0` contract in
  `agentsec.attack_graph.report`: value-free entries (pattern ID, node kind
  sequence, content-addressed node IDs, node/edge counts) with per-entry
  cross-field coherence validation and the fixed boundary marks
  (`static_declared_path`, `runtime_verified=false`,
  `reachability=not_proven`, `exploitability=not_proven`);
- bind every report to its source of truth via
  `manifest_schema_version`, `manifest_sha256`,
  `canonical_attack_graph_sha256(graph)`, the exact pattern library
  version, `path_count == len(entries)`, and entries sorted by unique
  `path_id`; non-empty reports must carry disclosed limitations and the
  report fixes every authority boolean false plus
  `exploitability_claimed=false`;
- add `build_attack_path_report` as the only producer: it derives every
  field from one validated graph with matched paths and fails closed on
  anything else;
- add `render_attack_path_report_text` (bounded per-path lines plus
  boundary-first footer, no node labels or Manifest references) and
  `encode_attack_path_report_json` (canonical deterministic JSON that
  round-trips through validation);
- export the frozen JSON Schema under `schemas/attack-graph/` and register
  `ATTACK_PATH_REPORT_VERSION` in the provenance registry with schema-file
  ownership; export the report surface through the public API;
- add 12 regression tests: empty report, digest bindings, coherence
  validation, tamper rejection, determinism, value-free text/JSON, schema
  export, and the real Codex pipeline report;
- ADR numbering: the concurrent P3-15 replay-suite ADR landed first and
  kept ADR-0100, so the attack-path report is recorded as ADR-0101; three
  pending Ruff format passes (two Python files from this task plus the
  concurrent session's replay-suite task document) were applied to keep
  `check.sh` green; no behavior change.

## Unreleased — 2026-08-31 — P3-AG-03 Attack Path Pattern Library / Matcher (ADR-0099)

- add the strict `AttackPathPatternSpec` / `AttackPathStepSpec` contracts
  and the reviewed builtin library
  `ATTACK_PATH_PATTERN_LIBRARY_VERSION 0.1.0` of seven static patterns:
  `secret-exfiltration`, `injection-tool-execution`, `memory-poisoning`,
  `delegation-escalation`, `mcp-external-egress`, `mcp-production-write`,
  and `tool-dependency-install` (roadmap families plus the optional
  supply-chain family and an egress variant);
- patterns bind preconditions to the start node (exfiltration requires a
  `reads_secret` outgoing edge), keep kind sets sorted/unique/non-empty,
  and pass `validate_pattern_library` when injected as a custom tuple;
- add the deterministic `AttackPathMatcher`: DFS over declared edges only
  with fixed pattern-ID → node-order → edge-ID traversal, producing
  content-addressed `attack-path-sha256` paths that all carry
  `path_kind=static_declared_path`, `runtime_verified=false`,
  `reachability=not_proven`, and `exploitability=not_proven`;
- fail closed on bounds: 64 matches per pattern and the graph-level 256
  path bound raise `AttackPathMatchError` instead of truncating;
- add `match_into_graph()` re-emitting a fully re-validated report-only
  graph (same Manifest binding, nodes, edges) with matched paths and all
  authority booleans false;
- register the library version in the interface provenance registry,
  export the matcher/specs/library through the public API, and add 15
  regression tests including the real Codex pipeline (delegation 1,
  injection 4, memory-poisoning 2, secret-exfiltration 1; the
  production-write and dependency-install patterns match zero paths while
  the builder emits no `writes_to`/`installs` edges — vocabulary-ready
  boundary, disclosed in ADR-0099);

## Unreleased — 2026-08-31 — P3-14 Paired-Scenario Detection Metrics (ADR-0098)

- add `agentsec.semantic.scenario_metrics` with the versioned
  `agentsec-p3-14-scenario-evaluation-metrics` report family: per-channel
  detection metrics over the P3-12/P3-13 paired scenario packs plus
  value-free per-task outcome rows;
- define the static metric semantics: the ASR detection proxy is the
  task-level false-negative rate on attack tasks (share of attack tasks
  with at least one missed expected judgment), the Utility proxy is the
  task-level true-negative rate on normal tasks (share kept free of
  false alarms), and FPR/FNR are the matching task-level rates while
  judgment-level Precision/Recall/F1 keep the P3-03 semantics;
- freeze `asr_semantics=detection_based_proxy` and
  `runtime_attack_success_claimed=false`: dynamic benchmark dimensions
  (observed tool calls, task completion under injection) are never
  computed or claimed;
- classify invocation failures per task kind, keep them visible
  (`invocation_failed` outcome, `metrics_complete=false`), and compute
  task-level rates over completed tasks only; channels without completed
  attack or normal tasks fail closed with stable error codes;
- enforce coherence under validation: detected + undetected + per-kind
  failures equal task counts, ASR equals FNR, utility plus FPR equals 1,
  and both rates match their raw-count fractions;
- fail closed on empty packs, duplicate channels, non-tuple pack input,
  wrong adapter/pack types, and Provider/Model identity drift across
  channels;
- register `SEMANTIC_SCENARIO_METRICS_SCHEMA_VERSION` and
  `SEMANTIC_SCENARIO_METRICS_OUTPUT_VERSION` (report family `0.1.0`),
  central schema file ownership, the frozen
  `schemas/semantic-analysis/semantic-scenario-metrics-report.schema.json`
  export, and export-script wiring;
- add ADR-0098, the task completion record, and 18 P3-14 tests covering
  perfect/undetected/false-alarm/per-kind-failure providers,
  determinism, round-trip encoding, frozen-schema byte identity, and
  corpus non-disclosure;
- keep the report report-only with no Provider, Rule, Policy, CI, Hard
  Gate, or release authority, and no real-quality claim from offline
  fixtures.

## Unreleased — 2026-08-31 — P3-11C Real Provider Shadow Trial (ADR-0096)

- execute the first real-provider Shadow trial over the 45-case human-confirmed
  gold set with theta-public|Kimi-K3-256K via the Theta OpenAI-compatible
  endpoint (two budgeted 45-invocation runs, QPS-paced, credential read only
  from THETA_API_KEY at the transport boundary and never persisted);
- add value-neutral contract canonicalization in the ADR-0083 OpenAI-compatible
  adapter: sort and deduplicate model-supplied limitation arrays and order
  candidates by candidate_key before P3-01 validation; unparsable payloads
  still fail closed through the strict contract unchanged;
- add SemanticQualityGate.qualify_evaluation_report() so one invocation run
  can back evaluation and qualification without re-billing, with 2 new tests
  (parity with qualify() and type fail-closed) plus a canonicalization unit
  test;
- record the first real-provider quality baseline: 42/45 complete,
  precision 0.394 / recall 0.378 / f1 0.385, evidence binding accuracy 1.000,
  coverage 0.933; qualification not_qualified (valid first-shot baseline
  documenting the judgment-granularity gap); attempt-1 artifacts kept as the
  pre-canonicalization control;
- keep qualification report-only: no provider promotion, Policy, CI, Gate,
  Rule, Finding, or release authority (ADR-0086 promotion flow unchanged).

## Unreleased — 2026-08-31 — P3-AG-02 Manifest Capability Graph Builder (ADR-0097)

- add the deterministic `ManifestCapabilityGraphBuilder` (`0.1.0`) that
  turns one validated `AgentManifest` into a reproducible
  `CapabilityAttackGraph` with `paths=()` and no authority change;
- map identity, tool families (skill / mcp_server / tool), relation-derived
  child agents and memory stores, permission-derived secret, production,
  network, and memory facts, MCP server→tool pairs, and one
  `untrusted_input` node per OVERRIDE instruction candidate;
- keep Evidence value-free: each Manifest source reference resolves to
  `(asset_path, content_sha256, start_line, end_line)` with a whole-file
  fallback; nodes and edges merge deterministically with the 16-Evidence
  fail-closed bound; disabled tools, deny permissions, and unmapped
  relation kinds emit nothing; self-delegation fails closed;
- bind graphs to the Manifest through `canonical_manifest_sha256` (equal
  to the P3-09 canonical digest) and register
  `ATTACK_GRAPH_BUILDER_VERSION` in the provenance registry; export the
  builder through the public API;
- amend the ADR-0093 endpoint matrix per ADR-0097: `sends_to` accepts
  `agent|tool|skill|mcp_server` sources and `writes_to` / `installs`
  accept `tool|skill|mcp_server` sources (validator rule only; the JSON
  Schema stays `0.1.0`);
- resolve the 0093 ADR numbering collision by renumbering the P3-11C
  decision record to ADR-0096;
- add ADR-0097, task documentation, threat-model TM-36/builder controls,
  and 8 regression tests (real Codex project plus a synthetic Manifest
  mapping matrix);
- gate hygiene: exclude the transient `build/` artifact directory from Ruff
  (it mirrors `src/` during wheel builds and made `check.sh` results depend
  on build activity) and apply one pending Ruff format pass to
  `semantic/provider_specific.py`; no behavior change.

## Unreleased — 2026-08-31 — P3-13 InjecAgent-Style Tool-Injection Scenario Corpus (ADR-0095)

- add the versioned `agentsec-p3-13-injecagent-scenario-set` data family to
  `agentsec.semantic.scenarios`: paired benign and attack tool-injection
  task contracts, the `InjecAgentIntent` taxonomy
  (secret_disclosure, data_forwarding, tool_commandeering,
  external_tool_binding, destructive_action, multi_capability_chain),
  counts, and a fail-closed loader/encoder;
- record the static tool-integration signature complementary to P3-12:
  attack tasks must expect a supported judgment in {code_execution,
  network_access, external_tooling, secret_access, destructive_action}
  and normal tasks must expect none; unpaired scenarios, wrong slot
  kinds, duplicate case IDs, and demoted dispositions fail closed;
- ship the deterministic bilingual scenario pack at
  `pilots/injecagent-style-p3-13/scenarios.json` (7 scenarios / 14 cases)
  built from real corpus (risky testdata, safe testdata, release-agent
  Chinese demo, Homi pilot snapshots) with every expected judgment
  inherited verbatim from the P3-11A human-confirmed gold set and the
  source gold file SHA-256 recorded and test-verified;
- add `build_injecagent_evaluation_cases` converting paired tasks into
  P3-03 `SemanticEvaluationCase` through the shared Evidence-rebinding
  path, so tampered text or Evidence IDs fail closed;
- generalize the shared `ScenarioError` message across both pack
  families (stable failure codes unchanged) and reuse the P3-12
  `ScenarioTaskCase`/`ScenarioTaskKind` paradigm;
- add ADR-0095, the task completion record, the pilot README, the
  idempotent builder, and 19 P3-13 tests including harness replay and
  false-negative visibility for undetected tool injections;
- keep the pack report-only with no Finding, Rule, Policy, CI, Hard
  Gate, release, runtime, or Provider-promotion authority, and never
  claim dynamic tool-call observation, attack success, or exploitability.

## Unreleased — 2026-08-31 — P3-12 AgentDojo-Style Paired Injection Scenario Corpus (ADR-0094)

- add `agentsec.semantic.scenarios` with the versioned
  `agentsec-p3-12-agent-dojo-scenario-set` data family: paired
  one-normal and one-attack task contracts, six recorded injection
  families, sorted unique IDs, counts, and a fail-closed loader/encoder;
- record the static injection signature: attack tasks must expect a
  supported `instruction_integrity` judgment and normal tasks must expect
  none; unpaired scenarios, wrong slot kinds, and duplicate case IDs fail
  closed;
- ship the deterministic bilingual scenario pack at
  `pilots/agentdojo-style-p3-12/scenarios.json` (9 scenarios / 18 cases)
  built from real corpus (prompt-injection testdata, safe testdata,
  release-agent demos, Homi pilot snapshots) with every expected judgment
  inherited verbatim from the P3-11A human-confirmed gold set and the
  source gold file SHA-256 bound (`p3-11a_gold_derived`);
- add `build_scenario_evaluation_cases` converting paired tasks into the
  P3-03 `SemanticEvaluationCase` with recomputed content-addressed
  Evidence binding, so tampered text or Evidence IDs fail closed;
- add ADR-0094, the task completion record, the pilot README, the
  idempotent builder, and 16 P3-12 tests including harness replay and
  false-negative visibility for dropped attack candidates;
- keep the pack report-only with no Finding, Rule, Policy, CI, Hard Gate,
  release, runtime, or Provider-promotion authority, and never claim
  dynamic attack success or runtime exploitability.

## Unreleased — 2026-08-31 — P3-AG-01 Attack Graph Node / Edge Schema (ADR-0093)

- add the strict `agentsec-capability-attack-graph` `0.1.0` contract with
  eleven constrained node kinds, fourteen directed edge kinds, and a validated
  endpoint-kind matrix covering the five planned attack-path families;
- derive node, edge, and static declared-path identities from canonical
  content hashes (`attack-node/edge/path-sha256:`) and recheck them during
  validation so tampered or duplicated identifiers fail closed;
- preserve Evidence as value-free source references
  (asset path, digest, line range) plus Manifest component references and
  node provenance, with bounded control-character-free labels;
- fix report-only, non-blocking boundaries with `runtime_verified=false` and
  `reachability=not_proven` / `exploitability=not_proven` on every path;
- add canonical JSON encoding, a bilingual-neutral Text renderer, the frozen
  JSON Schema export under `schemas/attack-graph/`,
  `ATTACK_GRAPH_SCHEMA_VERSION` provenance ownership, ADR-0093,
  threat-model TM-36, and 20 regression tests.

## Unreleased — 2026-08-31 — P3-11B Semantic Quality Qualification Gate (ADR-0092)

- add `agentsec.semantic.quality_gate` with strict `GoldLabelCase`/`GoldLabelSet`
  models binding the P3-11A human-confirmed gold labels to content-addressed
  sanitized evidence; `ai_assisted` labels are rejected as gate input;
- add fail-closed `load_gold_labels` (symlink/JSON/case-binding checks) and
  `SemanticQualityGate.qualify()` evaluating one Shadow Adapter over the gold
  set through the P3-03 harness against `ProviderQualityThresholds`;
- add report-only `QualityGateReport` `0.1.0` with qualified /
  not_qualified status, failed checks, reasons, metrics, and frozen
  no-authority booleans; frozen Schema export and provenance ownership
  (`SEMANTIC_QUALIFICATION_VERSION `0.1.0``);
- record the first offline qualification artifact over the 45-case gold set
  (qualified, P/R/F1 = 1.0 on fixture replay) under
  `pilots/semantic-quality-p3-11/qualification/`;
- expose label-corpus corrections enforced by validation: 13 `scan_coverage`
  judgments remapped to `instruction_integrity` (P3-01 forbids model-authored
  Coverage) and 8 duplicate judgments merged (108 -> 97);
- keep qualification report-only; no provider promotion, Policy, CI, Gate,
  Rule, Finding, or release authority.


## 0.4.0 — 2026-08-31 — Phase 3 Ready Candidate Acceptance

- promote the package from `0.4.0.dev0` to the explicitly approved local `0.4.0` candidate;
- build and checksum the local Wheel and sdist under `dist/0.4.0/`;
- verify package hardening, clean non-editable installation, public API imports,
  checksums, full quality gates, and byte-reproducible builds;
- complete P2-EXIT-08 Stage 2 with `candidate_acceptance=candidate_go` and no blocking checks;
- retain Shadow/report-only semantic boundaries and make no remote publication,
  production deployment, signature, SLSA, Runtime Attestation, or LLM authority claim.

## Unreleased — 2026-08-31 — P3-11A Human-labeled Semantic Evaluation Corpus

- add the blinded P3-11 semantic reviewer pack: 45 sanitized bilingual corpus
  cases (Homi snapshots, prompt-injection testdata, demo workspaces) with
  content-addressed `semantic-evidence-sha256` Evidence IDs;
- ship the Chinese labeling guide, annotation workflow, submission template,
  AI draft, and the human-confirmed review worksheet (45/45 cases confirmed
  with zero edits, reviewer 呈屿, `label_provenance=ai_draft_human_confirmed`);
- add the fail-closed import validator that emits 108 gold judgments
  (supported 101 / not_supported 7) as a machine-readable case set at
  `pilots/semantic-quality-p3-11/gold-labels/semantic-gold-labels.json`;
- keep the corpus report-only with `blocks=false` and no Provider, Finding,
  Rule, Policy, CI, Hard Gate, release, or runtime authority.

## Unreleased — 2026-08-31 — P3-10 Controlled Semantic Rule Promotion / Rule Pack Staging

- add deterministic `SemanticRulePromotionController` with explicit `rejected`,
  `eligible_for_staging`, and Owner-approved `staged` states;
- require accepted Rule Candidate provenance, exact replay binding, zero FP/FN/
  failures, perfect replay metrics, Evidence/Finding bounds, trusted Rule family,
  and a new deterministic Rule ID;
- add value-free Rule Pack ID diffs, strict promotion report Schema, JSON encoder,
  public API and provenance ownership;
- require explicit Owner approval ID and rationale while keeping staging immutable,
  report-only, and outside Finding, Policy, CI, Hard Gate, release, and runtime authority;
- add P3-10 ADR, task/architecture/threat-model documentation, and regression tests.

## Unreleased — 2026-08-31 — P3-09 Trusted Semantic Input Builder / Semantic Analyze CLI

- add `TrustedSemanticInputBuilder` to derive bounded sanitized semantic Evidence from trusted Framework Adapter records and deterministic Manifest state;
- add `agentsec semantic analyze PROJECT` with offline fixture default, bounded response fixture support, explicit live HTTPS opt-in, bilingual Text, JSON output, and hardened report artifact writing;
- add `semantic-shadow-pipeline` artifact validation, P3-09 tests, documentation, and provenance updates;
- keep semantic output Shadow-only with no Finding, Rule Pack, Policy, CI, Hard Gate, or runtime authority.

## Unreleased — 2026-08-31 — P3-08 Semantic Shadow Pipeline Integration

- add `SemanticShadowPipeline` to compose validated Shadow invocation, trusted Finding integration, and Rule Candidate proposal generation;
- add a deterministic aggregate report with child-result hash binding and fixed non-authority fields;
- add P3-08 Schema, public API/provenance ownership, ADR-0089, threat-model documentation, task documentation, and security regression tests;
- keep the aggregate report Shadow-only with no Finding, Rule Pack, Policy, CI, Hard Gate, or runtime authority.

## Unreleased — 2026-08-31 — P3-07 Semantic Calibration / Finding Promotion / Rule Replay

- add human-labeled Semantic Candidate calibration with TP/FP/FN/TN, Precision/Recall/F1, field agreement, and Evidence agreement;
- add report-only Finding Promotion Review that accepts only trusted positive deterministic links and never creates or mutates a Finding;
- add deterministic Rule Implementation Replay through the existing Rule Runner, with proposal-family binding, Finding count bounds, Evidence binding, and failure metrics;
- add strict P3-07 Schemas, public API/provenance ownership, ADR-0088, threat-model controls, task documentation, and security regression tests;
- keep replay, calibration, and promotion evidence outside Rule Pack, Policy, CI, Hard Gate, and release authority.

## Unreleased — 2026-08-31 — P3-06 Semantic Finding Integration / Rule Candidate Workflow

- add deterministic, read-only links from semantic candidates to existing Findings using trusted normalized path, asset SHA-256, line overlap, category, and static Evidence source checks;
- distinguish `duplicates`, `supports`, `contradicts`, and fail-closed `unmatched` relationships without mutating Finding, Severity, Confidence, Policy, CI, or Hard Gate state;
- add content-addressed review-required Rule Candidate proposals with a finite trusted category-to-family mapping and explicit accept/reject reviewer transitions;
- add strict integration/proposal Schemas, public API exports, provenance ownership, ADR-0087, threat-model controls, and P3-06 security regression tests;
- keep automatic Rule publication, runtime proof, and all enforcement authority disabled.

## Unreleased — 2026-08-31 — P3-04 Provider-Specific Adapter / Parity / Trial CLI

- add provider-specific structured JSON mapping, protected trial inputs, Offline/Live parity, and `agentsec semantic trial`;
- preserve Shadow-only, no-Policy, no-release, no-runtime authority.

## Unreleased — 2026-08-31 — P3-03 Live Provider Shadow Trial / Semantic Evaluation Harness

- add explicit `LiveSemanticProviderConfig` and `LiveSemanticProvider` with
  HTTPS-only endpoint validation, environment-variable credential references,
  explicit live opt-in, bounded response bytes, no redirects, no inherited
  proxy use, and no raw credential/payload retention in final artifacts;
- extend Provider metadata to distinguish transport network access from model
  Tool/network authority while preserving the P3-01/P3-02 Shadow boundary;
- add `SemanticEvaluationCase`, `SemanticEvaluationHarness`, and a frozen
  report-only evaluation output with TP/FP/FN, Precision/Recall/F1, Evidence
  Binding Accuracy, Coverage Rate, and safe failure metrics;
- add injected-transport tests for Live trials without network I/O, Chinese/
  English/mixed case labels, credential non-disclosure, live opt-in, and
  evaluation replay; add ADR-0084, TM-30, public API, provenance, and schema
  ownership updates;
- keep live endpoint/credential configuration absent, no model SDK or Provider
  promotion, no semantic CLI, no Rule/Policy/CI/Hard Gate/Release authority,
  and no runtime verification.

## Unreleased — 2026-08-26 — P3-02 Provider / Prompt / Shadow Invocation Adapter

- add the fixed `SemanticPromptEnvelope` with trusted system instructions,
  canonical untrusted `SemanticAnalysisInput` data, exact Model Output Schema,
  and recomputable Input/System/Schema/Prompt hashes;
- activate only the `offline-fixture` Provider and
  `agentsec-semantic-fixture-v1` Model identity with in-memory transport,
  structured output, timeout enforcement, and fixed no-tool/no-write/no-network/
  no-billing/no-retention capabilities;
- add bounded Provider Request/Response contracts, one-attempt/no-fallback
  invocation limits, pre-call input budgeting, response identity/completion/
  output/token/zero-cost/elapsed-time validation, and stable non-echoing errors;
- add `SemanticShadowInvocationAdapter` and content-addressed final result around
  the unchanged P3-01 validator; final output remains candidate Evidence only,
  report-only, runtime-unverified, non-blocking, and without Policy authority;
- add deterministic offline replay, four frozen Schemas, public API/provenance/
  package-hardening integration, ADR-0083, TM-29, and security regression tests;
- add no live Provider, SDK, credential, endpoint, network transport, billable
  invocation, retry, fallback, CLI command, or model-quality claim.

## Unreleased — 2026-08-26 — P3-01 LLM Semantic Analysis Contract / Authority Boundary

- add the versioned `SemanticAnalysisContract` seam and strict trusted Input,
  constrained untrusted Model Output, and trusted Shadow Result contracts at
  `0.1.0` before any Provider, Model, Prompt, SDK, credential, or transport is
  selected;
- bind bounded sanitized Agent Evidence through project-relative locations,
  Asset/text SHA-256 values, line ranges, and opaque recomputable Evidence IDs;
  redact secrets and minimize URLs, email addresses, network addresses, and
  unsafe controls without retaining raw request/response payloads;
- reject unknown model fields and forged/unanalyzed Evidence references; models
  cannot emit Severity, Confidence, Allow/Block, Waiver, Rule publication,
  source locations, Hard Gate authority, or runtime proof;
- deterministically assign candidate IDs, Coverage, fixed Confidence `C`,
  `report_only=true`, `runtime_verified=false`, `blocks=false`, and
  `authority_effect=none` in trusted post-processing;
- add immutable `shadow_only` no-tool/no-write/no-network Authority Boundary,
  ADR-0082, TM-28, frozen Semantic Schemas, public package exports, provenance
  ownership, package-hardening coverage, and semantic/documentation regression
  tests;
- keep Provider/Model/Prompt and actual model invocation unconfigured.
  Deterministic Rules and reviewed Policy remain the only CI authority.

## Unreleased — 2026-08-25 — P2-EXIT-05 Documentation/Schema/Version Provenance Consolidation

- add the two authoritative current-state pages
  `docs/current-architecture.md` and `docs/current-release-status.md`;
  historical task logs and phase plans are explicitly marked as history;
- add the complete interface provenance registry
  (`agentsec.provenance.interface_provenance_registry()`): every public
  interface version classified exactly once (product vector, report-family
  vector, historical-immutable, fixture-internal, reserved Phase 3), eight
  Phase 3 reserved interfaces, and an explicit no-authorization guarantee;
- add central schema ownership (`agentsec.provenance.schema_file_ownership()`,
  `schemas/README.md` layout) covering all 39 frozen schemas with a
  byte-completeness test;
- complete `scripts/export_release_schemas.py` with the qualified-gate-
  registry, agentic-assessment, and score-context exporters; regeneration is
  byte-identical to the frozen schemas;
- consolidate README current status, command surface, release artifacts, and
  documentation map to the 0.4.0.dev0 development line, replacing stale
  0.2.0 claims; add a Superseded banner linking qualification report v1 to v2;
- add documentation consistency tests; no code behavior change and no version
  bump in this task.

## Unreleased — 2026-08-25 — P2-EXIT-04 Hard Gate Scope Closure

- formally rescope the Phase 2 MVP Hard Gate acceptance from “3–5 Gates” to
  one qualified Gate plus the governed candidate framework (Path A per the
  P2-EXIT plan), closing audit finding F04; ADR-0064 records the decision;
- HG-CAPCHAIN-001 remains the only enforcement-allow-listed Gate;
  HG-PRODAUTO-001 and HG-EXTERNALPROD-001 are documented as Shadow
  candidates whose promotion still requires the full reviewed evidence chain
  plus external pilot evidence;
- update the P2-15A acceptance blocks in the Phase 2 scope, integration
  plan, and Hard Gate enforcement plan documents with the ADR-0064
  reference, and add a documentation consistency test pinning the rescoped
  wording; no code, schema, or risk-model change (no version impact).

## Unreleased — 2026-08-25 — P2-EXIT-03 Integrated Agentic Score CLI/Report

- add the additive `agentsec score PROJECT --before MANIFEST.json
  [--context CONTEXT.json]` command exposing the complete deterministic
  Agentic Factor → Threat/Mitigation → Technical → Drift → Governance →
  Overall scoring chain with qualified Hard Gate floors; keep `capability
  assess` and all existing command semantics unchanged;
- add the bounded `agentsec-score-context` `0.1.0` contract supplying
  reviewed Drift, Governance, CVSS, and accepted Gate-match context;
  unknown values stay conservative unknowns and are never fabricated;
  strict JSON loading fails closed on unknown fields, duplicate keys,
  invalid digests/enums, D-confidence Gate evidence, and malformed CVSS;
- add `agentsec-agentic-assessment` Output `0.1.0` with Text (en/zh),
  JSON, and SARIF 2.1.0 renderers, context provenance, Coverage/Unknown
  state, an explicit report-only policy block, and the full version vector;
- advance the package to the `0.4.0.dev0` development line, re-baseline the
  frozen scoring replay suite for the package-version provenance change
  (P2-32 precedent), and register the new artifact kind in the restricted
  writer; also fix the frozen capability CI enforcement artifact check to
  track the live report schema version;
- the score remains report-only: it never blocks CI, grants no Gate
  authority, and uses no LLM output.

## Unreleased — 2026-08-25 — P2-EXIT-02 Trusted CI Control Plane

- close the P0 audit finding that Policy, Waiver, and Qualification lived in
  the PR checkout under evaluation: trust artifacts are now loaded from an
  explicit trust root or verified against protected digest pins;
- add `--trust-root` to `scan` and `capability enforce` (Mode A: separate
  protected policy checkout; relative `--policy` paths must stay inside the
  trust root, escaping paths/symlinked roots fail closed with exit 3);
- add `--expect-policy-sha256` (scan and enforce) and
  `--expect-registry-sha256` (enforce) digest pins (Mode B); mismatches fail
  closed with exit 3 before analysis;
- upgrade Organization Policy Schema `0.2.0 → 0.3.0` with a
  `capability.qualification` registry binding; organization Capability Gate
  authority returns through the verified P2-EXIT-01 registry chain and
  unbound Gate lists fail closed at load;
- advance Organization Assessment Report Output `0.2.0 → 0.3.0` and Capability
  CI Report Output `0.4.0 → 0.5.0` with trust provenance blocks
  (`trust_mode`, digest pin and verification state, expected digests);
- add `docs/examples/ci/github-actions-trusted.yml` (two-checkout Mode A plus
  protected digest Mode B), runner support for AGENTSEC_TRUST_ROOT and
  AGENTSEC_EXPECT_POLICY_SHA256, replay cases (trusted-pin-block,
  trusted-pin-mismatch, trusted-root-block), and `docs/trusted-ci.md` with
  CODEOWNERS/branch-protection prerequisites;
- keep deterministic rules as the only blocking authority; LLM output and
  runtime-unverified evidence remain excluded from Policy, Waiver, and Gate
  authority.

## Unreleased — 2026-08-25 — P2-EXIT-01 Trusted Gate Qualification Registry

- add the strict `agentsec-qualified-gate-registry` Schema `0.1.0` with a
  bounded no-follow YAML loader rejecting aliases, anchors, tags, duplicate
  keys, unknown fields, symlinks, and oversized input, plus a frozen JSON
  Schema export;
- upgrade Capability CI Policy Schema `0.1.0 → 0.2.0`: policies listing
  qualified Gates must pin `qualification.registry_path` and an approved
  `registry_sha256`, and missing trust binding fails closed with exit `3`;
- verify Gate authority through the full evidence-binding chain: registry
  digest pin, qualification report digest pin, duplicate-key rejection,
  Gate/Rule binding, completion, accepted status, empty blocking reasons,
  passing checks, safe policy flags, and recomputed `artifact_id`;
- advance Capability CI Report Output `0.3.0 → 0.4.0` with a
  `qualification_registry` provenance block;
- bind the repository-approved HG-CAPCHAIN-001 qualification evidence through
  `calibration/p2-15a-capchain-40/human-evidence/qualified-gate-registry.yaml`
  and update the enforce example policy;
- suspend Capability Gate authority from organization YAML policies (no
  registry binding field yet) with fail-closed exit `3` until P2-EXIT-02;
- record the decision in ADR-0062 and keep LLM, runtime-unverified, and
  D-confidence evidence excluded from Gate authority.

## 0.3.0 — 2026-08-25 — Internal MVP

- release SARIF, fail-on, Organization Policy, Waivers, qualified Capability CI
  enforcement, CVSS/Agentic scoring, scoring replay, CI examples, Pilot, and
  Rule/Score calibration as Package `0.3.0`;
- retain calibrated Markdown Rule Pack `0.3.0` and Risk Model `0.4.0`;
- add 0.3.0 release notes, known limitations, acceptance record, ADR-0061, and
  dedicated Wheel/sdist acceptance tests;
- include Policies, CI workflows, Pilot and Calibration evidence, Schemas,
  scripts, demos, and tests in the source distribution;
- verify deterministic Policy blocking, active Waiver allowance, SARIF, Manifest,
  Capability analysis, and clean non-editable offline Wheel installation;
- preserve historical 0.1.0 and 0.2.0 artifacts and make no Git, remote
  publication, remote CI, production deployment, or runtime exploit claim.

## Unreleased — 2026-08-25 — P2-30 Pilot Project Integration

- add strict versioned Pilot Plan and Pilot Report contracts at `0.1.0`;
- integrate an eight-scenario internal Release Agent pilot through the real
  P2-29 Organization Policy CI Runner;
- collect decision, Coverage, scenario-level unique-Rule FP/FN, JSON/SARIF
  artifact size, and local wall-clock performance evidence;
- add JSON/Markdown pilot reports, frozen Schemas, ADR-0059, acceptance tests,
  and an active GitHub Actions pilot replay workflow;
- label the evidence `internal_integration` and avoid production accuracy,
  remote-CI, or runtime exploitability claims.

## Unreleased — 2026-08-25 — P2-29 CI Examples

- add an executable GitHub Actions pull-request workflow with separate decision
  capture, always-run JSON/SARIF upload, and final fail-closed enforcement;
- add a shared CI Runner that verifies JSON/SARIF exit-code agreement and
  preserves the canonical `0/1/2/3/4/5/64` process outcome;
- add a GitLab CI example plus deterministic active/expired Waiver fixtures;
- add local static validation and replay for safe, blocked, incomplete, invalid
  Policy, active-Waiver, and expired-Waiver scenarios;
- keep deterministic Organization Policy as the only blocking authority and
  defer real pilot-repository rollout evidence to P2-30.

## Unreleased — 2026-08-25 — P2-28 Risk Waivers

- add required Owner/Reason/Expiry Waivers scoped to Finding, Rule, or Gate;
- keep waived Findings/Gates visible while removing only blocking authority;
- automatically expire Waivers and record evaluation date plus applied/expired IDs;
- advance Organization Policy/Report to `0.2.0`, SARIF Reporter to `0.4.0`, and Capability CI Output to `0.3.0`;
- add ADR-0058, waiver example, schemas, tests, and documentation.

## Unreleased — 2026-08-25 — P2-27 Organization Policy

### Added

- add strict explicit `agentsec-organization-policy` YAML `0.1.0`;
- configure Scan High/Critical thresholds and blocking Rule IDs without disabling Findings;
- configure qualified Capability Gate IDs through the existing enforcement engine;
- add Policy SHA-256 provenance, Text/JSON/SARIF Scan reporting, frozen Schemas, and examples;
- add ADR-0057 and organization Policy tests.

### Changed

- advance SARIF Reporter `0.2.0` → `0.3.0`;
- advance Capability CI Enforcement Output `0.1.0` → `0.2.0` with source provenance;
- keep `--policy` explicit and mutually exclusive with `--fail-on`;
- defer waivers to P2-28.

## Unreleased — 2026-08-25 — P2-26 Explicit `--fail-on`

### Added

- add `agentsec scan --fail-on high|critical` with explicit CLI-only policy;
- add deterministic `FailOnDecision` `0.1.0` with Coverage precedence, stable
  matched Finding IDs, trusted rationale, and exit `0/1/2`;
- add `agentsec-assessment-fail-on` JSON Output `0.1.0`, strict decoder, frozen
  Schema, and schema exporter integration;
- add Text decision summary and explicit Assessment Policy header;
- extend SARIF with fail-on run/invocation/Result properties and advance SARIF
  Reporter `0.1.0` → `0.2.0`;
- add ADR-0056, task/usage documentation, CLI/unit/schema/tamper tests.

### Security and policy boundaries

- default scan behavior remains report-only;
- only AgentSec Finding Severity `high|critical` is accepted;
- incomplete Coverage returns `2` and cannot be overridden by a threshold match;
- Confidence, SARIF level, CVSS, LLM output, and runtime state have no fail-on
  authority;
- `capability assess` does not expose severity fail-on and cannot bypass the
  existing qualified `capability enforce --policy` path;
- organization Policy and waivers remain P2-27/P2-28.

## Unreleased — 2026-08-25 — P2-25 SARIF Reporter

### Added

- add strict deterministic SARIF 2.1.0 subset models and safe JSON codec;
- add Phase 1 Assessment, Capability Assessment, and Overall Score SARIF
  renderers;
- add `agentsec scan --format sarif` and
  `agentsec capability assess --format sarif`;
- add restricted `.sarif` Capability Assessment artifact output;
- add stable Rule indexes, URI/line locations, versioned partial fingerprints,
  AgentSec score/Confidence/Correlation/CVSS/CVE/CWE/Gate/Coverage properties;
- add `SARIF_REPORTER_VERSION = 0.1.0`, ADR-0055, usage documentation, and
  focused regression tests.

### Security and policy boundaries

- SARIF excludes Evidence excerpts, Commands, URL values, Headers, environment
  values, credentials, tokens, memory content, and raw source values;
- SARIF selection does not change exit codes, enable `--fail-on`, or block CI;
- incomplete analysis still emits visible partial SARIF and returns `2`;
- Config Schema remains `output.format=text|json`; SARIF is an explicit CLI-only
  override in P2-25.

## Unreleased — 2026-08-24 — P2-CAL-04A-HUMAN-SUBSET-01 HG-CAPCHAIN-001 Review Package

### Added

- add `scripts/build-capchain-review-subset.py`;
- add `calibration/p2-15a-capchain-40/` with 40 opaque independent-review
  questions, two pending Reviewer templates, selection binding, package
  manifest, label schema, and reviewer instructions;
- add a deterministic 20 Positive + 20 Eligible Negative/Near-miss selection
  without distributing expected labels, Ground Truth, Seed labels, or Joint
  Expert Evidence;
- add `tests/test_capchain_review_subset.py` for packet count, binding,
  determinism, non-clobbering, and secret/label boundary checks.

### Boundaries

- this package is prepared for independent human review but is not yet formal
  Human Evidence; a scoped Import, Confidence report, Comparison, and
  Adjudication are still required;
- no Gate qualification, `hard_gate=true`, `--fail-on`, or CI blocking is
  enabled.

## Unreleased — 2026-08-24 — P2-15A-PILOT-03 Shadow Gate Demo and Coverage Report

### Added

- add `scripts/run-shadow-gate-demo.py` and the presenter-friendly
  `scripts/run-shadow-gate-demo.sh` wrapper;
- add five deterministic Shadow Gate scenarios covering same-target,
  parent-child, Agent-wide, relevant Unknown, and incomplete-Coverage behavior;
- add `agentsec-capability-shadow-gate-demo` report Schema `0.1.0` with
  Coverage statistics and seeded Matrix Match/No-match metadata;
- add ADR-0049, the P2-15A-PILOT-03 task document, and focused Demo tests.

### Boundaries

- the Demo runs only inert deterministic static analysis and never executes
  scanned code, Skills, Hooks, commands, MCP servers, or network requests;
- Matrix Match/No-match labels are seeded expected calibration metadata, not
  Human Evidence, Agreement, Adjudication, or P2-15A qualification;
- the Demo remains Shadow-only, report-only, non-clobbering, and non-blocking.

## Unreleased — 2026-08-24 — P2-15A-PILOT-02 Capability Shadow Gate

### Added

- add deterministic `HG-CAPCHAIN-001` Shadow Gate evaluation after the
  Capability Rule runner;
- require `same_target` or `parent_child` correlation, complete Coverage, and
  zero relevant Unknowns for a Shadow match;
- add strict Gate version, correlation, related-ID, Finding binding, and
  non-enforcement contract validation;
- add ADR-0048 and the P2-15A-PILOT-02 task document.

### Changed

- keep Shadow metadata at `CAPABILITY_SHADOW_GATE_VERSION = 0.1.0` and keep the
  Capability Risk Model at `0.1.0`;
- keep the Capability Assessment Output at `0.2.0` with
  `mode=shadow`, `qualification=pilot_only`, and `blocks=false`.

### Boundaries

- Shadow matches do not set `hard_gate=true`, change scores or Severity, alter
  Evidence Confidence, change CLI exit codes, enable `--fail-on`, or block CI;
- Shadow evaluation does not qualify P2-15A and does not replace independent
  Reviewer A/B evidence or Adjudication.

## Unreleased — 2026-08-24 — P2-15A-PILOT-01 Joint Expert Review Evidence

### Added

- add `import-joint-panel` operation to `scripts/pilot-review.py` and
  `import_joint_panel_review` to `agentsec.calibration.pilot_review`;
- add `agentsec-joint-expert-review-evidence` artifact format `0.1.0` with
  mandatory `joint_panel` metadata (`evidence_mode=joint_expert_review`,
  `review_panel_id`, `reviewer_count`, `independent_initial_labels=false`,
  `adjudication_required=false`, `qualification=pilot_only`);
- add content-addressed `evidence_id` and full Pilot binding-chain
  verification (Pack manifest hash, Selection binding, per-row
  corpus/question-set/case-fingerprint/source hashes); any Case, Corpus, or
  Pack change fails the import closed;
- add `calibration/pilot-review-100/joint-panel-pilot-input.json` and the
  formalized 50-row `joint-expert-evidence.json` for `expert-panel-001`;
- add `tests/test_pilot_joint_panel_import.py` and the P2-15A-PILOT-01 task
  document.

### Changed

- reset the 50 joint-panel rows in
  `calibration/pilot-review-100/reviewer-a-labels.template.json` to `pending`
  so joint consensus conclusions can no longer be mistaken for Reviewer A
  independent evidence.

### Boundaries

- Joint Expert Review Evidence is pilot-only: it is not Reviewer A/B
  independent evidence, feeds no agreement/Kappa statistics, is not formal
  P2-CAL-04 Human Evidence, and does not count toward P2-15A Hard Gate
  qualification;
- no `hard_gate=true`, CI blocking, or `--fail-on` is enabled.

## Unreleased — 2026-08-24 — P2-24 CVSS Report-only Hard Gate

### Added

- add deterministic CVSS High/Critical effective-score gate evaluation;
- add `CvssHardGateMatch`, `CvssHardGateAssessment`, and
  `Finding.cvss_hard_gate`;
- add `cvss_hard_gate_matches` to Assessment JSON summaries;
- add Text/JSON report visibility and automatic `agentsec scan` integration;
- add ADR-0047, P2-24 task documentation, and focused CVSS Gate tests.

### Changed

- preserve CVSS Gate as a separate report view from AgentSec score, Severity,
  and generic `hard_gate`;
- bump Domain Schema `0.7.0` → `0.8.0`;
- bump Assessment Output `0.6.0` → `0.7.0`;
- add `CVSS_HARD_GATE_VERSION = 0.1.0` to the version vector.

### Boundaries

- CVSS Gate remains report-only and never changes CLI exit codes;
- no `--fail-on`, CI Blocking, production enforcement, runtime verification,
  or exploitability proof is enabled.

## Unreleased — 2026-08-24 — P2-23 CVE/CWE Source Adapters

### Added

- add an offline `agentsec-vulnerability-catalog` `0.1.0` contract and
  `schemas/vulnerability-catalog/vulnerability-catalog.schema.json`;
- add a bounded no-follow local source reader with AgentSec catalog and NVD
  CVE JSON 2.0 adapters;
- add deterministic exact-CVE auto-association and CWE/CVSS enrichment;
- add `agentsec scan --vulnerability-source PATH`;
- add ADR-0046, P2-23 task documentation, source adapter tests, and CLI tests.

### Changed

- extend `VulnerabilityReference.association_method` with
  `deterministic_match`;
- bump Domain Schema `0.6.0` → `0.7.0`;
- bump Assessment Output `0.5.0` → `0.6.0`.

### Boundaries

- source loading remains offline and report-only;
- no remote database query, LLM semantic match, runtime verification,
  exploitability proof, CVSS Hard Gate, or CI Blocking is enabled.

## Unreleased — 2026-08-24 — P2-CAL-04A Documentation and QA Closure

### Added

- add `tests/test_p2_16_risk_score_contract.py`: cross-layer NIST → High-Water-
  Mark Impact → Base Score → Severity → Text/JSON regression coverage;
- add `docs/tasks/P2-16-02-capability-risk-score-contract-regression-hardening.md`
  with the P2-16-02 completion record and unchanged-version decision;
- add `docs/calibration-adjudication-reviewer-pack.md`: Reviewer recruitment,
  blind A/B review flow, Ground Truth isolation, Label lifecycle
  (`pending → reviewed → adjudicated`), disagreement handling, FP/FN
  vocabulary, Case reuse and Gate statistics rules, post-review CLI usage,
  P2-15A preconditions, and security boundaries;
- add `tests/test_phase2_calibration_docs.py` documentation regression tests
  for the P2-CAL-04A Task ID, the three Gate Candidate IDs, the 20 Positive /
  20 Negative-Near-miss sample requirement, Seed Label restrictions,
  `report_only` enforcement, and the disabled state of `hard_gate=true`;
- add README quick starts for Reviewer Pack validation and the report-only
  Gate Calibration Coverage Check CLI;
- add `docs/tasks/P2-CAL-04A-AGENT-04-completion-report.md` with the final
  documentation handoff, sample statistics, QA results, human-review gap, and
  P2-15A blocking status;
- add `calibration/pilot-review-100/`: a deterministic 100-question Demo-first
  selection, reviewer-facing draft templates, and pilot workflow boundaries;
- add `scripts/pilot-review.py` and the bounded Pilot Review validator/report/
  compare/adjudication-template/merge workflow without changing the formal
  431-question importer.

### Changed

- record P2-CAL-04A completion status in `docs/phase2-scope.md`,
  `docs/phase2-integration-plan.md`,
  `docs/capability-calibration-hard-gate-enforcement-plan.md`, and the
  multi-Agent work plan;
- document the Coverage Check CLI and human review guide in
  `calibration/README.md`;
- document the Adjudication Resolution Set Schema `0.1.0` and Adjudication
  Report Output `0.3.0` in `schemas/README.md`;
- document Pilot progress validation, label-only reporting, and non-clobbering
  merge snapshots in the Pilot Review README and Reviewer Guide.

### Boundaries

- P2-CAL-04A only prepares Cases and the Reviewer Pack; real Reviewers must be
  recruited by humans and must blind review independently;
- Seed Labels are not production review results and all three Gate Candidates
  remain `more_data_required`;
- no Hard Gate qualification conclusion is produced; `hard_gate=true`, CI
  blocking, and `--fail-on` remain disabled;
- no Capability Rule, Risk Model, P2-15A/P2-15B code, Reviewer Label, or
  Adjudication Label content is changed.

## Unreleased — 2026-08-21 — P2-CAL-04A Reviewer Evidence Provenance

### Added

- add ADR-0038 and a versioned `AdjudicationResolutionSet` `0.1.0`;
- add strict Reviewer Pack `0.3.0` file manifests with complete path, SHA-256,
  size, role, scope, and mode validation;
- add separate formal imports for independent Adjudication Reviews, Human
  Confidence Reviews, and final Adjudication Resolutions;
- add explicit `seed` and `human` evidence modes to P2-CAL-04;
- add adversarial extra/missing Pack file, disagreement-preservation, Human
  Confidence, Resolution, and no-seed-fallback tests.
- pass the complete repository gate with 904 tests, Ruff formatting/lint, and
  strict Mypy over 196 source files.

### Changed

- preserve Reviewer A/B labels after adjudication instead of copying the final
  resolution into both Reviewer rows;
- report original Reviewer agreement separately from adjudication-required and
  adjudication-completed state;
- derive Human Gate Candidate Confidence grades and Kappa from the explicitly
  supplied Human Confidence report;
- bump Calibration Adjudication Report Output `0.2.0` → `0.3.0`.

### Boundaries

- all behavior remains report-only with CI blocking disabled;
- real Reviewer recruitment, identity verification, independence, and final
  human sign-off remain operational work;
- no Capability Rule, Risk Model, Hard Gate, runtime verification, LLM, or
  automatic Rule publication is added.

## Unreleased — 2026-08-21 — P2-CAL-04A Gate Coverage CLI Hardening

### Added

- add a report-only Gate Calibration Coverage Check CLI with Text/JSON output
  and explicit `0/2/4/5` exit semantics;
- add 33 focused Corpus/Matrix, threshold, path-safety, source-binding,
  semantic-uniqueness, cross-Gate reuse, and macOS path-alias regression tests;
- add the Agent 3 completion report and handoff state for final documentation
  and QA.

### Changed

- pin the three approved candidate Gate definitions in trusted code and reject
  Gate, component Rule, floor, or threshold injection from the Matrix;
- bind Matrix metadata and Rows to Corpus ID, Rule Pack, Ground Truth, Review
  Status, deterministic Scenario identity, and the expected Case source view;
- recompute value-free semantic fingerprints from validated Corpus Ground Truth
  and count unique eligible samples independently per Gate;
- allow one multi-expectation Case to cover multiple Gates without permitting
  duplicate counting inside the same Gate;
- preserve lexical and resolved Corpus roots so macOS `/tmp` and `/var` aliases
  remain usable without weakening Corpus-internal symlink rejection.

### Boundaries

- the CLI remains `report_only` with `ci_blocking_enabled=false`;
- all labels remain `seeded`; independent human Review and Adjudication are
  still required;
- no Rule, Risk Model, Hard Gate, `--fail-on`, CI enforcement, runtime
  verification, LLM, automatic Rule publication, or vulnerability proof is
  added.

## Unreleased — 2026-08-21 — P2-CAL-04A Corpus Repair

### Changed

- replace duplicated Gate samples with semantically distinct synthetic contexts;
- exclude relevant-Unknown and incomplete Cases from confirmed-negative Gate
  sample counts;
- add 155 inert Markdown/JSON/YAML/TOML/Manifest source views for Reviewer Pack
  preparation while keeping deterministic replay on value-free Fact Bundles;
- add semantic fingerprints, eligible-negative metadata, expanded Corpus identity
  `p2-cal-04a-expanded-corpus`, and Labels Version `0.2.0`;
- update Adjudication Report Output to `0.2.0` for candidate-scoped eligible
  sample-count semantics;
- add the Agent 1 completion report and stronger semantic-uniqueness, source-view,
  and Unknown-boundary tests.

### Boundaries

- all generated review and adjudication labels remain `seeded`;
- actual independent human Review and Adjudication are still pending;
- no Rule, Risk Model, Hard Gate, `--fail-on`, or CI enforcement is enabled.

## Unreleased — 2026-08-21 — P2-CAL-04 Independent Adjudication

### Added

- add independent `AdjudicationReviewSet` Schema `0.1.0` with complete
  Case/Rule reviewer coverage, classification/category/disposition labels, and
  bounded safe loading;
- add `CalibrationAdjudicationReport` Output `0.1.0` with FP/FN category
  separation, consensus/unresolved states, deterministic Rule tuning
  recommendations, and three report-only Gate Candidate assessments;
- add bilingual Text/JSON delivery, adjudication Schema exports, and
  `scripts/run-calibration-adjudication.py`;
- add 122 seeded adjudication labels for the 61-Expectation corpus;
- add ADR-0037, P2-CAL-04 documentation, and regression tests.

### Boundaries

- seeded labels are not independent production adjudications;
- all current Gate Candidates remain `more_data_required` because sample
  thresholds are not met;
- no Rule mutation or publication, Hard Gate activation, `--fail-on`, CI
  enforcement, runtime verification, LLM, or vulnerability proof is added.


## Unreleased — 2026-08-21 — P2-CAL-03 Evidence Confidence Calibration

### Added

- add independent `ConfidenceReviewSet` Schema `0.1.0` with bounded seeded or
  reviewed A/B/C/D labels, reviewer identity, correlation, and safe loading;
- add `ConfidenceCalibrationReport` Output `0.1.0` with reviewer pair
  agreement, Cohen's Kappa, Expected-vs-Emitted agreement, grade matrices, and
  per Rule/Correlation metrics;
- add bilingual Text/JSON rendering, confidence Schema exports, and
  `scripts/run-confidence-calibration.py`;
- add ADR-0036 and P2-CAL-03 documentation and tests.

### Boundaries

- checked-in labels are seeded fixture labels, not independently adjudicated
  human review evidence;
- current static Rules do not produce A-level runtime evidence; D-confidence
  and incomplete evidence remain report-only signals;
- no Hard Gate, `--fail-on`, CI enforcement, runtime verification, LLM, Rule
  publication, or vulnerability proof is added by P2-CAL-03.


## Unreleased — 2026-08-21 — P2-CAL-02 Deterministic Evaluation Runner

### Added

- add deterministic Fact Bundle replay for all 29 Capability Rule IDs;
- add TP/FP/FN/TN, Precision, Recall, False Positive Rate, F1, Macro/Micro,
  Correlation, Evidence Confidence, Evidence, Coverage, Unknown, duplicate,
  failure, and sample-sufficiency metrics;
- add versioned Text/JSON Calibration Report Output `0.1.0`;
- add `scripts/run-calibration.py` and P2-CAL-02 documentation.

### Boundaries

- current evaluator is a fact-level seed adapter, not a production parser or
  runtime calibration claim;
- current seed metrics are perfect by construction and all Rules remain sample
  insufficient;
- no Hard Gate, CI enforcement, runtime verification, LLM, or Rule publication.

## Unreleased — 2026-08-21 — P2-CAL-01 Calibration Case Schema

### Added

- add strict `agentsec.calibration` Case and Corpus Index models with
  positive/negative/near-miss/incomplete/Unknown/conflict labels;
- add safe JSON codecs, Draft 2020-12 Schema exports, bounded UTF-8 loading,
  root containment, symlink rejection, and current Rule Pack coverage checks;
- add 61 inert seed Cases covering all 29 Capability Rule IDs with match and
  no-match labels, expected Correlation, and Evidence Confidence;
- add ADR-0035 and P2-CAL-01 documentation.

### Boundaries

- seed labels are not statistical Precision/Recall results; P2-CAL-02～04 still
  own replay, adjudication, Confidence calibration, and Hard Gate candidacy;
- no Capability Hard Gate, CI enforcement, runtime verification, or LLM is
  added by P2-CAL-01.

## Unreleased — 2026-08-20 — P2-14 Capability Rule Pack 0.2.0

### Added

- expand the structured Capability Rule Pack from six to 29 deterministic,
  bilingual, source-backed Rules;
- add dedicated production/external permission, automatic approval, missing
  guardrail, runtime-identity, memory/delegation, and relationship-Unknown Rules;
- add P2-14 inventory, production/identity/Unknown, benign negative,
  determinism, evidence, secret-omission, and report-only regression coverage;
- regenerate English and Chinese Capability Drift artifacts: the risky state now
  has 17 Findings across 16 Rule IDs, while baseline and remediation remain zero;
- add ADR-0034 and update Capability Rule, versioning, Demo, Phase 2 Scope, and
  integration documentation.

### Changed

- `CAPABILITY_RULE_PACK_VERSION` `0.1.0` → `0.2.0`;
- keep `CAPABILITY_RISK_MODEL_VERSION = 0.1.0`, Capability Assessment Output
  `0.1.0`, Capability Change Impact Output `0.1.0`, and Agent Manifest Schema
  `0.3.0` unchanged;
- keep all Capability Findings deterministic and report-only with
  `hard_gate=false` and no CI blocking.

### Boundaries

- Package remains `0.2.0` during source development; accepted `dist/0.2.0`
  artifacts are not rebuilt or replaced and still contain Rule Pack `0.1.0`;
- P2-14 does not add `--fail-on`, CI enforcement, runtime Tool/OAuth/Permission
  verification, LLM analysis, automatic Rule publication, or vulnerability proof.

## Unreleased — 2026-08-20 — P2-13 Capability Change Impact

### Added

- deterministic `CapabilityChangeImpactReport` Output `0.1.0` with canonical
  embedded Capability Diff, semantic Tool/Permission/Control before/after state,
  exposure direction, and report-only policy;
- logical Capability Finding Delta matching by `rule_id + related_ids`, with
  `added`, `resolved`, `changed`, and `unchanged` lifecycle states;
- `agentsec capability impact` Text/JSON CLI with bounded Manifest input,
  private atomic output, bilingual presentation, and incomplete-analysis exit `2`;
- English/Chinese Capability Drift Demo impact artifacts and management-summary
  Finding Delta metrics;
- ADR-0033 and P2-13 source-development documentation.

### Boundaries

- Package remains `0.2.0` during source development; P2-13 is not included in
  the accepted `dist/0.2.0/` artifacts;
- Capability Diff `0.1.0`, Capability Rule Pack `0.1.0`, and Capability Risk
  Model `0.1.0` remain unchanged;
- exposure direction is not a new risk score, authorization decision, runtime
  proof, Hard Gate, `--fail-on`, or CI block.

## 0.2.0 — 2026-08-20 — Phase 2 Integration MVP

### Added

- reviewed Simplified Chinese trigger variants for all 15 stable Markdown Rules;
- `agentsec rules list --language zh`;
- Chinese positive and benign negative regression for every Rule ID;
- five inert Chinese corpus Cases, bringing the current corpus to 45 Cases;
- fully Chinese Release Agent baseline, drift, injection, and remediation Demo.

### Changed

- Rule Pack `0.2.0` → `0.3.0`; Rule IDs and risk meanings remain stable.

### P2-01 structured Parser foundation

- add one deep `StructuredParser` interface and normalized source-backed node
  model;
- add deterministic JSON, safe YAML, and TOML Parser adapters;
- add duplicate-key, unsafe YAML, malformed input, source-location, determinism,
  and parser resource-limit regression tests;
- add Phase 2 Scope, ADR-0018, and structured Parser documentation;
- keep structured-file discovery, Agent Manifest, capability mapping, rules, and
  LLM analysis deferred to later Phase 2/3 tasks.

### P2-02 Rules and MCP specialized Parsers

- add a strict non-executing Parser for literal Codex `prefix_rule(...)`
  declarations and inline examples;
- add static MCP declaration parsing for top-level and plugin-bundled server
  tables, STDIO, Streamable HTTP, environment references, tool filters, approval
  modes, and timeouts;
- omit static environment/header values and URL query/fragment values from the
  specialized MCP model;
- retain unknown direct MCP fields by source location without copying values;
- add 34 targeted Rules/MCP parsing, malicious-expression, no-execution,
  no-network, secret-omission, line-location, limit, and determinism tests;
- add ADR-0019 and specialized Parser documentation.

### P2-03 Framework Adapter interface

- add a one-method `FrameworkAdapter.inspect()` Protocol with stable Adapter
  identity and version provenance;
- add portable project/user/plugin locators, neutral Asset roles and formats,
  precedence hints, parser-coherent records, and explicit Coverage models;
- validate deterministic ordering, uniqueness, line-count coherence, role/format
  compatibility, and MCP-role consistency;
- verify two independent fake Adapters through the same interface;
- keep framework inspection output separate from Phase 1 RuleContext and risk
  processing;
- add ADR-0020 and Framework Adapter interface documentation.

### P2-04 Codex Adapter

- add the first production `FrameworkAdapter` implementation for Codex;
- add explicit working-directory context to Framework inspection requests;
- discover project-chain and explicit user-scope Agent, Skill, `.rules`, TOML,
  and MCP configuration assets;
- preserve both base and Override instructions and deterministic precedence
  hints for later effective-configuration resolution;
- enforce root containment, internal-only symbolic links, bounded reads, strict
  UTF-8, depth limits, global asset limits, deterministic ordering, and explicit
  Coverage;
- keep commands, URLs, environment references, Skills, Rules, plugins, and MCP
  servers inert, with no LLM or network access;
- add ADR-0021, Codex Adapter documentation, and targeted discovery,
  non-execution, parser, limit, symlink, precedence, and Coverage tests.

### P2-05 Agent Manifest Schema

- add independent Agent Manifest Schema `0.1.0` without changing frozen Phase 1
  Domain, Baseline, Diff, Assessment, Rule Pack, or Risk Model versions;
- add strict immutable models for subject identity, portable sources,
  instruction candidates, tools, permissions, controls, runtime identities,
  relationships, Unknowns, and Manifest Coverage;
- add explicit unresolved/partial/resolved/unknown/not-applicable/conflict state
  so empty fields cannot silently imply absence or safety;
- add `AgentManifestBuilder` to normalize Framework source metadata, Coverage,
  instruction candidates, and future declaration sources without copying parsed
  source values;
- add deterministic JSON encoding, compatibility-first safe validation, and
  Draft 2020-12 JSON Schema export;
- add ADR-0022, Agent Manifest documentation, domain glossary terms, and
  targeted schema, provenance, safety, ordering, compatibility, and integration
  tests.

### P2-06 Instruction Inheritance / Override Resolver

- add deterministic `InstructionResolver` over Agent Manifest candidates;
- resolve same-directory Base/Override slots without reading instruction text;
- preserve user-before-project and root-before-nested application order;
- add `effective_order`, `overridden_sources`, and `resolution_trace`;
- mark incomplete Coverage as `partial` and fail closed for ambiguous candidates;
- increment Agent Manifest Schema `0.1.0` → `0.2.0`;
- add ADR-0023, Resolver documentation, and inheritance/security tests.

### P2-07 Configuration Precedence Resolver

- add source-level `ManifestConfigurationProfile` and configuration candidate
  kinds for Framework, Rules, and MCP sources;
- add deterministic `ConfigurationResolver` with user/project scope, precedence
  rank, portable path, and chain-key ordering;
- preserve canonical `effective_sources`, semantic `effective_order`, and a
  source-level resolution trace;
- mark incomplete configuration Coverage as `partial` and fail closed for
  duplicate candidate identities;
- keep field-level TOML/Rules/MCP value merging out of P2-07;
- increment Agent Manifest Schema `0.2.0` → `0.3.0`;
- add ADR-0024, Configuration Resolver documentation, and source-order,
  Coverage, no-value-read, and determinism tests.

### P2-08 Skill / MCP / Tool Association

- add deterministic `AssociationExtractor` (and `AssociationResolver` alias)
  over the existing Agent Manifest and Framework inspection seam;
- associate Skills, static MCP servers, and MCP tool filters/policies with
  source-backed `ManifestTool` items;
- add `uses_skill`, `uses_mcp`, and `uses_tool` relationships with declared
  state and exact field/line provenance;
- classify only conservative static MCP potential side effects: STDIO execute,
  Streamable HTTP network, and plugin-bundled unknown;
- normalize stable IDs with bounded collision disambiguation;
- retain explicit partial status for incomplete inspection Coverage;
- keep commands, endpoints, environment values, headers, Skill bodies, runtime
  enumeration, permissions, risk, and LLM analysis outside the boundary;
- keep Agent Manifest Schema at `0.3.0` because no serialized fields changed;
- add ADR-0025, association documentation, and five targeted regression tests.

### P2-09 Static Capability Profile

- add deterministic `CapabilityExtractor` for existing permission, control, and
  runtime identity Manifest profiles;
- map known Skill/MCP/tool side effects into conservative read/write/execute/
  network/secret/admin/unknown permission facts;
- map explicit `.rules` decisions into allow/prompt/deny execute permissions and
  Prefix Rule controls without evaluating commands;
- add MCP enablement, required, approval, tool-filter, timeout, network-policy,
  and secret-handling controls with field/line provenance;
- add credential-free MCP runtime identity hypotheses for OAuth, ChatGPT,
  bearer/environment, plugin-bundled, local, and external evidence;
- keep permission effect separate from Tool availability and runtime identity
  separate from attestation;
- preserve `partial` for incomplete Coverage or uncertain/unsupported facts;
- keep Agent Manifest Schema at `0.3.0` because no serialized fields changed;
- add ADR-0026, static capability documentation, and two targeted regression
  tests.

### P2-10 Sub-Agent / Memory Relationships

- add deterministic `RelationshipExtractor` (and `RelationshipResolver` alias)
  for explicit Markdown frontmatter declarations;
- associate delegation aliases with `delegates_to`;
- associate memory read/write/persist aliases and nested `memory` declarations
  with the existing memory relationship kinds;
- retain P2-08 Skill/MCP/tool relations and merge duplicate logical edges with
  deterministic source provenance;
- hash unsafe paths, URLs, control-character, whitespace, and oversized targets
  into bounded unknown IDs without serializing raw values;
- mark malformed/unsupported declarations and unsafe targets as partial/unknown;
- expand relationship declaration-source roles to Markdown instructions,
  Overrides, Skills, and MCP configuration;
- keep Agent Manifest Schema at `0.3.0` because no serialized fields changed;
- add ADR-0027, relationship documentation, and five targeted regression tests.

### P2-11 Explicit Unknowns and Capability Diff

- add idempotent `UnknownExtractor` (and `UnknownResolver` alias) for profile and
  item uncertainty, runtime verification requirements, and incomplete Coverage;
- map stable Unknown dimensions/reasons without copying source values;
- add versioned `CapabilityDiffer` for Tool, Permission, Control, Runtime
  Identity, Relationship, Unknown, profile-status, and Coverage changes;
- emit added/removed/modified entries with stable IDs, changed-field names,
  SHA-256 fingerprints, and before/after source provenance instead of full item
  values;
- preserve visible changes while marking Diff incomplete if either Manifest has
  incomplete Coverage;
- add independent `CAPABILITY_DIFF_SCHEMA_VERSION = 0.1.0`, deterministic JSON,
  compatibility-first validation, safe errors, and Draft 2020-12 Schema export;
- keep Agent Manifest Schema at `0.3.0` and Phase 1 Diff Output at `0.1.0`;
- add ADR-0028, Unknown/Capability Diff documentation, and five targeted tests.

### P2I-01 Full Agent Analysis Pipeline

- add injectable `AgentAnalysisPipeline` and `AgentAnalysisEngine` application
  seam for one-call P2-04 through P2-11 orchestration;
- add explicit request roots/limits, final Manifest result, current version
  vector, and bounded nine-stage operational trace;
- add safe required-stage error codes without copying dependency diagnostics;
- add `CapabilityExtractor.extract_associated()` and
  `RelationshipExtractor.extract_associated()` while preserving existing public
  `extract()` behavior;
- ensure Association extraction runs once inside the integrated Pipeline;
- retain valid Partial Manifest results and explicit Unknowns for incomplete
  Coverage;
- keep Agent Manifest, Capability Diff, Phase 1 Domain, Rule Pack, Risk Model,
  CLI, and enforcement versions unchanged;
- add Pipeline documentation and deterministic/order/partial/error-safety
  regression tests.

### P2I-02 Deterministic Capability Rule Pack

- add an independent framework-neutral `CapabilityRule` seam over finalized
  Agent Manifests;
- add immutable deterministic context indexes for Tools, Permissions, Controls,
  Runtime Identities, parent/child Tools, Relationships, Unknowns, and Sources;
- add Capability Rule Pack `0.1.0` with six stable bilingual Rule IDs for
  approval, execution/secret/network chain, Coverage, delegation, external MCP,
  and persistence risk;
- add Capability Risk Model `0.1.0` with correlation-based Evidence Confidence
  and static likelihood, NIST matrix scoring, FIPS-style high-water-mark impact,
  and FIRST CVSS Severity ranges;
- prefer same-target and MCP parent/child correlation, avoid Agent-wide Cartesian
  products, and lower Agent-wide/incomplete evidence to D Confidence;
- add value-free hash-backed evidence and deterministic Finding identity without
  source excerpts, commands, URLs, Headers, environment values, or credentials;
- add atomic per-Rule failure isolation and deterministic result ordering;
- keep `hard_gate=false`, CI blocking disabled, Phase 1 Rule/Risk versions
  unchanged, and no LLM/runtime/network/MCP behavior;
- add ADR-0029, Capability Rule documentation, version documentation, and
  positive/negative/Unknown/determinism/failure-isolation tests.

### P2I-03 Manifest, Capability Assessment, and Capability Diff Reports

- add `ManifestTextRenderer` and canonical `ManifestJsonRenderer`;
- add `CapabilityDiffTextRenderer` and canonical `CapabilityDiffJsonRenderer`;
- add `CapabilityAssessmentEngine` application composition for the full analysis
  Pipeline plus deterministic Capability Rule Pack;
- add independently versioned Capability Assessment Output `0.1.0` with strict
  JSON wrapper, derived summary/status validation, fixed report-only policy,
  canonical embedded Manifest, Findings, Stage Trace, and Rule failures;
- add deterministic Draft 2020-12 Capability Assessment Schema export and
  compatibility-first safe validation errors;
- add English and Simplified Chinese Text presentation for management summary and
  developer evidence;
- add per-section Text bounds, explicit omitted counts, secret redaction, and
  untrusted-text sanitization;
- retain Agent Manifest Schema `0.3.0`, Capability Diff Schema `0.1.0`, Phase 1
  Assessment Output `0.2.0`, and report-only/no-runtime-proof boundaries;
- add ADR-0030, report documentation, version documentation, and complete/partial/
  localization/determinism/non-disclosure tests.

### P2I-04 Manifest and Capability CLI

- add `agentsec manifest` with explicit project/working/user/Codex roots, Agent
  ID, Text/JSON, English/Chinese, output, and restricted force options;
- add `agentsec capability assess`, `capability diff`, and bilingual
  `capability rules list`;
- add `DeterministicManifestCapabilityDiffEngine` application seam;
- add bounded no-follow compatibility-first Agent Manifest file input;
- add kind-validated `.json`/`.txt` mode-0600 atomic report output;
- make no-clobber the default and limit `--force` to an existing valid artifact
  of the same kind and format;
- reject Diff output paths that equal either Manifest input;
- add `ARTIFACT_ERROR` as numeric exit-code-4 alias while retaining report-only
  Finding exit `0`, incomplete exit `2`, and reserved risk-policy exit `1`;
- add ADR-0031, CLI guide, help/exit/security documentation, and end-to-end CLI/
  storage regression tests;
- keep all Schema, Output, Rule Pack, Risk Model, and frozen distribution
  versions unchanged pending a separate Phase 2 release task.

### P2I-05 Capability Drift Story Demo

- add inert English and Chinese baseline, risky-drift, incomplete, and
  remediated Release Agent capability projects;
- demonstrate seven Findings across six Capability Rule IDs with highest High,
  complete Capability Diff, incomplete exit `2`, and remediation back to zero
  Findings;
- add live automated and seven-stage presenter runners with language, pause,
  output-directory, and offline options;
- add deterministic frozen Manifest, Capability Assessment, Capability Diff,
  localized Text, management summary, and SHA-256 checksum artifacts for both
  languages;
- add semantic validation for report-only policy, Coverage, Rule IDs, Diff,
  remediation, and synthetic secret/endpoint non-disclosure;
- add developer/management scripts, bilingual acceptance records, documentation,
  and E2E tests;
- keep all Schema, Output, Rule Pack, Risk Model, Hard Gate, enforcement, and
  frozen Phase 1 distribution versions unchanged.

### Phase 2 Integration Hardening and Release Review

- increment Package `0.1.0` → `0.2.0` while retaining every independent Schema,
  Output, Rule Pack, and Risk Model version;
- sanitize malicious Manifest/Capability Diff validation location keys;
- enforce no-follow regular-file reads when validating `--force` replacement;
- freeze Agent Manifest, Capability Diff, and Capability Assessment JSON Schemas;
- make build/install scripts derive the current source version and verify Phase 1
  plus Phase 2 CLI paths offline;
- add exact wheel/sdist checksum, metadata, required-content, and reviewed-source
  consistency tests for the preserved Phase 2 release candidate;
- replay both English and Chinese Capability Drift Demo tracks in live and
  checksum-verified offline modes during release checks;
- add ADR-0032, 0.2.0 release notes, known limitations, acceptance evidence, and
  preserved version-specific artifacts under `dist/0.2.0/`.

### Distribution boundary

The accepted 0.1.0 wheel/sdist remain preserved at the `dist/` root. AgentSec
0.2.0 artifacts and checksums are stored separately under `dist/0.2.0/`. No
remote publication, Git tag, or production deployment is claimed.

## 0.1.0 — 2026-08-19

First Phase 1 Markdown static-scanning PoC release.

### Added

- installable `agentsec` Python package and console entry point;
- `version`, `scan`, `baseline create`, `diff`, and `rules list` commands;
- safe Markdown collection, path containment, resource limits, CommonMark
  parsing, frontmatter/reference extraction, and obfuscation indicators;
- versioned Baseline Schema, atomic Baseline writer, Asset Diff, and bounded Text
  Diff;
- 15 deterministic Markdown Rules with isolated failure Coverage;
- NIST-style preliminary risk, high-water-mark Impact, 0–10 score, Severity,
  A/B/C/D Evidence Confidence, and report-only Hard Gate metadata;
- ANSI-free Rich Text and strict `agentsec-assessment` JSON reports;
- shared hardened secret redaction and control-character escaping;
- explicit Coverage reporting and stable exit codes;
- 40-Case Safe/Risky/Prompt Injection/Malformed corpus;
- frozen JSON Schemas;
- Release Agent developer/management Demo with offline fallback;
- README, complete PoC usage guide, release notes, known limitations, and
  acceptance records.

### Security policy

```text
enforcement_mode=report_only
ci_blocking_enabled=false
global_safety_claimed=false
```

### Compatibility vector

```text
Package 0.1.0
Config Schema 0.1.0
Domain Schema 0.3.0
Baseline Schema 0.1.0
Diff Output 0.1.0
Assessment Output 0.2.0
Rule Pack 0.2.0
Risk Model 0.4.0
```

## 2026-08-31

- **P3-AG-05:** Added deterministic, report-only association between static
  Attack Paths, existing Finding Evidence, and trusted Shadow Semantic Evidence.
  The new value-minimized report binds graph/path/Finding/Semantic digests,
  distinguishes exact/partial/unmatched correlation, deduplicates shared
  node/edge locators, and grants no Finding, Policy, CI, Hard Gate, release, or
  runtime authority.

- **P3-AG-06:** Added `agentsec attack-graph-associate` with bounded strict
  graph/Finding/Semantic input readers, project-mode E2E integration, Text/JSON
  association reports, safe artifact output, and report-only exit behavior.

- **P3-AG-07:** Added an inert Homi-like Attack Path Story Demo and presenter
  runner that exercises the production association CLI with deterministic,
  semantic, exact, partial, and unmatched Evidence outcomes.

- **P3-AG-08:** Added digest-bound Attack Path Evidence calibration cases,
  multi-class relation metrics, seed pilot artifacts, and a safe calibration
  runner.

## P3-REL-02 — Reconciled Candidate Acceptance Wiring (2026-08-31)

- Added `--reconciled-candidate-report` to the Phase 3 Candidate Acceptance
  workflow.
- Rechecked the P3-REL-01 source inventory, Candidate directory safety, Wheel/
  sdist digests, checksums, reproducibility, and installed CLI smoke evidence.
- Preserved legacy candidate-verification fixtures and the historical
  `dist/0.4.0/` artifacts; no publication or production authority was added.
