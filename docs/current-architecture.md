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

### P3-AG-01 attack graph schema and P3-AG-02 builder

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
source `sends_to`, `writes_to`, and `installs`. The path matcher
(P3-AG-03) and path report (P3-AG-04) are not implemented. See
`docs/tasks/P3-AG-01-attack-graph-node-edge-schema.md`,
`docs/tasks/P3-AG-02-manifest-capability-graph-builder.md`, ADR-0093, and
ADR-0097.

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
