# AgentSec Current Architecture

- Authority: this is the single authoritative architecture page (P2-EXIT-05).
  When other documents disagree, this page and the interface provenance
  registry win.
- Date: 2026-08-31
- Companion status page: `docs/current-release-status.md`

## 1. Mission

AgentSec statically analyzes Agent control assets, resolves effective
capabilities, detects risky changes, and produces evidence-backed security
findings. It never executes scanned content, never connects to MCP servers or
the network by default, and never claims global Agent safety or runtime
exploitability.

## 2. Analysis pipeline

```text
CodexAdapter (Framework Adapter, project/user roots, PathGuard-bounded)
HomiAdapter (P2-HOMI-01, six project-root files, static classification only)
→ HomiWorkspacePolicyResolver (P2-HOMI-02, static precedence/visibility/conflict model)
→ Markdown + JSON/YAML/TOML/.rules/MCP safe parsers
→ AgentAnalysisPipeline: Agent Manifest schema 0.3.0
  (Instruction Resolver, Configuration Precedence Resolver,
   Association/Capability/Relationship/Unknown extractors)
→ Deterministic Capability Rule Pack 0.2.0 (29 rules)
→ Capability Shadow Gate (report-only HG-CAPCHAIN-001 evaluation)
→ Capability Assessment / Capability Diff / Change Impact
→ Agentic Scoring chain (report-only)
→ P3-01 SemanticAnalysisContract (strict Evidence and Authority seam)
→ P3-02 SemanticPromptBuilder → Provider Adapter
  → P3-03 Live/Offline SemanticShadowInvocationAdapter
→ P3-04 Provider-specific adapter + Offline/Live parity + semantic trial CLI
→ P3-05 Quality/Human Review/Shadow Promotion
→ P3-06 Semantic Finding integration + Rule Candidate Workflow
    (trusted Evidence links; review-required Rule proposals; no publication)
→ P3-07 Candidate calibration + Finding promotion review + deterministic Rule replay
    (human labels and inert fixture replay; no authority escalation)
→ P3-09 Trusted Semantic Input Builder + `semantic analyze` CLI
    (end-to-end Shadow report; offline default; no authority escalation)
→ P3-08 Semantic Shadow Pipeline Integration
    (one aggregate report; no production authority)
→ P3-10 Controlled Semantic Rule Promotion / Rule Pack Staging
    (Owner-reviewed, immutable staging artifact; no publication)
→ Reporting: bilingual Text, versioned JSON, SARIF 2.1.0
→ Deterministic Policy decisions (organization Policy, fail-on, Gate enforcement)
```

Phase 1 Markdown scanning (`agentsec scan`) and Phase 2 capability analysis
share domain models but keep independent, versioned output contracts.

## 3. CLI surface

```text
agentsec version
agentsec scan PROJECT [--fail-on high|critical] [--policy POLICY.yaml]
                      [--trust-root DIR] [--expect-policy-sha256 HEX]
agentsec baseline create PROJECT
agentsec diff PROJECT
agentsec rules list
agentsec manifest PROJECT [--format text|json] [--output PATH]
agentsec capability assess PROJECT [--format text|json|sarif]
agentsec capability enforce PROJECT --policy POLICY
                      [--trust-root DIR] [--expect-policy-sha256 HEX]
                      [--expect-registry-sha256 HEX]
agentsec capability diff --before A.json --after B.json
agentsec capability impact --before A.json --after B.json
agentsec capability rules list
agentsec score PROJECT --before MANIFEST.json [--context CONTEXT.json]
              [--format text|json|sarif]
```

Exit codes: `0` pass/report-only, `1` deterministic block, `2` incomplete
(fail closed), `3` configuration/trust error, `4` artifact error,
`5` required analysis failure, `64` usage error. See `docs/exit-codes.md`.

## 4. Trust and enforcement model

- Deterministic Rules own CI blocking. LLM output is never part of a
  decision; runtime evidence is never claimed.
- Capability Gate authority flows through the Qualified Gate Registry chain
  (ADR-0062): Policy pins → registry digest pin → qualification report digest
  pin → recomputed artifact IDs. Phase 2 MVP scope is exactly one qualified
  Gate, `HG-CAPCHAIN-001` (ADR-0064); other candidates are shadow-only.
- Trust artifacts are never auto-discovered from scanned project content.
  `--trust-root` (separate protected checkout) and `--expect-*-sha256` digest
  pins (protected CI configuration) separate the trust plane from the target
  checkout; mismatches fail closed with exit `3`.
- Waivers live inside pinned Policy artifacts, carry owner/reason/expiry, and
  remove blocking without hiding Findings.
- See `docs/trusted-ci.md`, `docs/organization-policy.md`,
  `docs/p2-15b-policy-controlled-ci-enforcement.md`.

## 5. Agentic scoring chain (report-only)

```text
Agentic Factor vector → Threat/Mitigation → Technical Score (+ CVSS high-water)
→ Capability Diff → Drift Score → Governance Score
→ Overall Score = high-water base, plus qualified Hard Gate floor
```

Drift and Governance semantics come only from the explicit
`agentsec-score-context` file or conservative unknowns — they are never
fabricated. Scores never block CI. See `docs/agentic-score.md`.

## 6. Phase 3 Shadow-only semantic contract

P3-01 defines the `SemanticAnalysisContract` and frozen JSON Schemas for
trusted input, constrained untrusted model output, and trusted final result.
Evidence is bounded, sanitized, content-addressed, and referenced by opaque IDs.
Trusted post-processing preserves deterministic Coverage and Unknowns, assigns
Evidence Confidence `C`, and emits only report-only, runtime-unverified,
non-blocking candidate evidence.

P3-02 adds a fixed Prompt envelope, separate trusted instruction/untrusted data
channels, an approved in-memory offline fixture Provider/Model identity, bounded
request/response contracts, timeout/token/zero-cost checks, and a deterministic
Shadow Invocation result. P3-03 adds an explicitly opt-in HTTPS live Provider
seam and a value-free semantic Evaluation Harness, but no default endpoint,
credential, live invocation, Policy authority, or CI influence. P3-04 adds the
provider-specific adapter, Offline/Live parity, and protected semantic trial
CLI. P3-05 adds quality evaluation, independent Human Review, and controlled
Shadow promotion. P3-06 adds deterministic trusted Evidence links to existing
Findings and review-required Rule Candidate proposals; it cannot mutate a
Finding or publish a Rule. No SDK is installed and no network call is made by
default. See `docs/semantic-shadow-invocation.md`,
`docs/semantic-evaluation.md`, `docs/semantic-finding-integration.md`,
ADR-0083, ADR-0084, and ADR-0087.

LLM output is never part of a decision. Deterministic Rules and reviewed Policy
remain the only sources of CI blocking authority.

## 7. Phase 3 live-trial and evaluation boundary

P3-03 permits a caller to explicitly construct `LiveSemanticProvider` with an
HTTPS endpoint and environment-variable credential reference, then pass
`allow_live_provider=true` to the Shadow Adapter. The repository and default
CLI configure neither. Live transport access is separate from model Tool/network
authority and the resulting analysis remains `shadow_only`, `report_only`,
`runtime_verified=false`, `blocks=false`, and `policy_authority=false`.

`SemanticEvaluationHarness` calculates TP/FP/FN, Precision, Recall, F1, Evidence
Binding Accuracy, Coverage Rate, and safe failure counts. Evaluation output is
quality evidence only; it cannot qualify a Provider, publish a Rule, change a
Gate, or authorize a release.

### P3-10 controlled semantic Rule promotion and staging

P3-10 adds a final controlled workflow:

```text
accepted_for_implementation candidate
  → deterministic implementation replay
  → promotion assessment
  → explicit Owner approval
  → staged report-only artifact
  → separate release review
```

The staging artifact contains only content-addressed report metadata and a
value-free Rule ID diff. `staged` never means published: the controller does
not mutate the installed Rule Pack, create or modify Findings, affect Policy/CI
or Hard Gates, or authorize release. A rejected or duplicate Rule ID remains
representable as rejected evidence. See `docs/semantic-rule-promotion.md` and
ADR-0091.

### Attack Graph Track: schema, builder, matcher, and path report (P3-AG-01～04)

The Attack Graph Track is separate from the Semantic Track (2026-08-31
roadmap erratum). P3-AG-01 adds the frozen
`agentsec-capability-attack-graph` `0.1.0` contract in `agentsec.attack_graph`:
eleven node kinds and fourteen directed edge kinds with a validated
endpoint-kind matrix, content-addressed `attack-node/edge/path-sha256`
identifiers, value-free Evidence locators, Manifest schema/digest binding,
deterministic ordering, and size bounds. Every path is a
`static_declared_path` with `runtime_verified=false`,
`reachability=not_proven`, and `exploitability=not_proven`; the graph is
`report_only=true` with all authority booleans false.
P3-AG-02 adds `ManifestCapabilityGraphBuilder`: it consumes only validated
Manifest declaration fields, maps identity/tools/relations/permissions/MCP
declarations and instruction overrides through fixed reviewed tables, keeps
Evidence value-free, merges deterministically with fail-closed Evidence
bounds, suppresses disabled tools and deny permissions, binds the graph to
`canonical_manifest_sha256`, and emits `paths=()` (matching is reserved for
P3-AG-03). ADR-0097 amends the endpoint matrix so Manifest tool families may
source `sends_to`, `writes_to`, and `installs`. P3-AG-03 adds the reviewed
`ATTACK_PATH_PATTERN_LIBRARY_VERSION 0.1.0` vocabulary (seven static
patterns covering the roadmap's five families plus the optional
supply-chain family and an egress variant) and the deterministic
`AttackPathMatcher`: ordered DFS over declared edges, start-node-bound
preconditions, content-addressed path IDs, fail-closed 64-per-pattern and
256-graph bounds, and `match_into_graph()` re-emitting a fully re-validated
report-only graph. Every matched path is a `static_declared_path` with
`runtime_verified=false`, `reachability=not_proven`, and
`exploitability=not_proven`; `mcp-production-write` and
`tool-dependency-install` match zero paths while the builder emits no
`writes_to`/`installs` edges (disclosed in ADR-0099). The path report
`writes_to`/`installs` edges (disclosed in ADR-0099). P3-AG-04 adds the
frozen `agentsec-attack-path-report` `0.1.0` contract: value-free entries
(pattern ID, node kind sequence, content-addressed node IDs, counts) with
per-entry coherence checks, report-level digest bindings (Manifest schema
and digest, `canonical_attack_graph_sha256`, pattern-library version), a
single `build_attack_path_report` producer that fails closed outside a
validated graph, a boundary-first bounded Text renderer, and canonical
round-tripping JSON. P3-AG-04B wires the validated Manifest→graph→matcher→report
chain to `agentsec attack-graph PROJECT`, with Text/JSON output and hardened
artifact writing. A matched path is explicitly not a Finding: no severity,
confidence, or recommendation is rendered and every authority boolean stays
false with `exploitability_claimed=false`. P3-AG-05 adds the value-minimized
Evidence association contract described in section 28 below. See
`docs/tasks/P3-AG-01-attack-graph-node-edge-schema.md`,
`docs/tasks/P3-AG-02-manifest-capability-graph-builder.md`,
`docs/tasks/P3-AG-03-attack-path-pattern-library-matcher.md`,
`docs/tasks/P3-AG-04-attack-path-report.md`,
docs/tasks/P3-AG-05-semantic-deterministic-evidence-association.md,
ADR-0093, ADR-0097, ADR-0099, ADR-0101, and ADR-0103.

## 8. Version governance

- Every public interface version is classified exactly once in the interface
  provenance registry: `agentsec.provenance.interface_provenance_registry()`
  (product version vector / report-family vector / historical-immutable /
  fixture-internal / reserved Phase 3). See `tests/test_provenance_registry.py`
  for the consistency guarantees.
- Product version vector (embedded in analysis provenance):
  `agentsec.versioning.current_versions()`.
- Frozen published schemas live under `schemas/` with central ownership in
  `agentsec.provenance.schema_file_ownership()` and one-command regeneration
  via `scripts/export_release_schemas.py`. See `schemas/README.md`.
- No interface version grants authorization authority. The local 0.4.0 candidate
  is a build/acceptance artifact only; it is not remote publication or production
  authorization. The activated P3-01
  semantic contracts and P3-02 offline Provider/Prompt/Invocation contracts are
  Shadow-only and carry no decision authority. Attack Graph and Runtime
  Attestation remain unconfigured until separately approved.
- Core schema or risk-model changes require an ADR. See `docs/decisions/`.

## 9. Security invariants (always true)

```text
No execution of scanned code, scripts, hooks, skills, or MCP servers
No default network access; no MCP connections
Homi TOOLS.md does not grant runtime tool authority; empty HEARTBEAT.md does not prove scheduler state
Homi precedence ranks are static security-resolution metadata, not runtime loader attestation
Secret values are redacted and never logged or shipped
Bounded reads: size limits, depth limits, no-follow symlinks, path containment
Single-file or single-rule failures never abort a scan; gaps are reported
High/Critical findings carry direct evidence; Confidence never lowers Severity
Hard Gate floors are never diluted by averaging
Deterministic, reproducible output for identical inputs and versions
LLM output is candidate evidence only; semantic links and Rule proposals are report-only
No semantic path can create/update a Finding, publish a Rule, or affect Policy/CI/Hard Gates
Calibration, replay, Shadow Pipeline aggregation, and Rule Pack staging remain evidence-only
```

## 10. Document authority

Historical task logs and phase plans under `docs/` record development
history and may contain outdated status claims. For current facts use:

```text
docs/current-architecture.md       this page
docs/current-release-status.md     release and remediation status
CHANGELOG.md                       change history
docs/decisions/                    accepted decisions (ADRs)
```

## 28. P3-AG-05 semantic/deterministic Evidence association

```text
Task                              P3-AG-05 Complete
Deliverable                       agentsec-attack-path-evidence-association-report 0.1.0
Producer                          AttackPathEvidenceAssociator.associate
Bindings                         graph + path-report + Finding + optional Semantic digests
Match basis                       normalized path + SHA-256 + overlapping lines
Finding input                    existing Finding only; file/diff Evidence only
Semantic input                   existing Semantic Result + trusted Evidence chunks
Relations                        duplicates / supports / partially_supports / unmatched
Authority                         report_only=true; blocks=false; all authority false
Value minimization                graph and target locators only; no excerpts or secrets
Runtime                           runtime_verified=false; reachability/exploitability not proven
Tests                             tests/test_attack_graph_p3_ag_05.py (8 passed)
```

P3-AG-05 adds a deterministic read-only correlation layer between matched
static paths, existing deterministic Findings, and Shadow semantic candidates.
It deduplicates shared node/edge locators, fails closed on path/hash/line
mismatches or missing trusted Semantic Evidence, and emits a frozen
`attack-path-evidence-association-report` Schema. It never creates or mutates a
Finding or candidate and does not affect Severity, Confidence, Policy, CI, Hard
Gates, release state, runtime reachability, or exploitability. See
`docs/tasks/P3-AG-05-semantic-deterministic-evidence-association.md`,
`docs/decisions/0103-attack-path-evidence-association.md`, and
`schemas/attack-graph/attack-path-evidence-association-report.schema.json`.


## 29. P3-AG-06 association CLI / E2E

P3-AG-06 adds `agentsec attack-graph-associate` without changing the existing
`agentsec attack-graph PROJECT` interface. The command supports validated
artifact mode (`--graph`) and project mode (`--project`), optional Finding and
Semantic Evidence inputs, Text/JSON output, bounded no-follow readers, and
same-kind atomic artifact writing. It invokes only the P3-AG-05 read-only
associator. Valid reports remain non-blocking and carry no runtime or
Finding/Policy/CI/Hard-Gate authority. See
`docs/tasks/P3-AG-06-attack-path-evidence-association-cli-e2e.md` and
ADR-0104.


## 30. P3-AG-07 Attack Path Story Demo

P3-AG-07 adds the inert `demos/attack-path-story-agent/` Homi-like fixture and
repeatable `scripts/run-attack-path-demo.sh` / `scripts/demo-attack-path.sh`
runner. It exercises the production association CLI and produces a bounded one-
path story with deterministic Finding, Shadow Semantic Candidate, exact,
partial, and unmatched Evidence outcomes. The Demo is presenter evidence only:
no target execution, runtime claim, CI block, or authority transition is
possible. See `docs/tasks/P3-AG-07-attack-path-story-demo.md` and ADR-0105.


## 31. P3-AG-08 Attack Path Evidence Calibration

P3-AG-08 adds strict digest-bound human label cases and a deterministic
calibration report for the P3-AG-05 association output. It preserves the
relation classes, exposes missing/unreviewed rows, and computes exact accuracy
and one-vs-rest metrics. The checked-in three-case corpus is seed wiring
evidence only, not an independent quality qualification set. No calibration
result changes Findings, Rules, Policy, CI, Hard Gates, or runtime claims. See
`docs/tasks/P3-AG-08-attack-path-evidence-calibration.md` and ADR-0106.


## P3-AG-09 Attack Path Score Integration

The Score command accepts the validated Attack Path Evidence Association Report
and an optional digest-bound calibration report. The resulting
`AttackPathScoreContext` is embedded in Agentic Assessment output as explanatory
context only. It records path/association counts and calibration provenance, but
its contract fixes `scoring_mode=context_only`, `numeric_score_effect=0.0`,
and `calibration_qualified=false`; therefore Attack Paths cannot change
Technical/Drift/Governance/Overall scores, Severity, Hard Gates, CI, or release
authority.

## P3-19 Semantic Gate human evidence and Provider Pilot

The P3-19 path adds a Gate-scoped, digest-bound Human Corpus ahead of Provider quality
qualification. Corpus coverage and reviewer provenance are deterministic inputs to the
P3-18 qualification runner. A separate Real Provider Pilot runner performs fail-closed
preflight and, only after explicit opt-in and organizational approval, invokes the existing
Shadow Adapter at a bounded one-call-per-case budget. The resulting artifact contains no
raw prompt, response, credential, or sensitive endpoint data, and all authority fields
remain report-only / false.

## P3-20 Provider Evaluation Import and Qualification

Provider Evaluation Reports no longer enter Gate qualification as unbound JSON. The
`SemanticGateEvaluationImport` contract binds the current Candidate, Gate-specific Human
Corpus, Evaluation Digest, Provider/Model identity, and current Prompt Contract. The
qualification adapter consumes the imported report without re-invoking the Provider and
produces only report-only qualification/promotion evidence. A successful quality result
still has no CI, Rule, Policy, Waiver, Runtime, or Release authority.
