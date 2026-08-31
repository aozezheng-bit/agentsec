# AgentSec Phase 2 Exit Hardening 项目修复方案

- Plan ID: `P2-EXIT`
- Date: 2026-08-25
- Source audit: `docs/reviews/phase2-completion-audit-2026-08-25.md`
- Current release: AgentSec `0.3.0` Local Internal MVP
- Target release: AgentSec `0.4.0` Phase 3 Ready Candidate
- Overall status: In progress (P2-EXIT-01～05 complete, 2026-08-25)
- Phase 3 policy: Architecture design may proceed; LLM semantic output must not
  enter CI, Policy, Rule publication, Waiver, Severity, or authorization before
  P2-EXIT completion.

## 1. Objective

Phase 2 has completed its principal deterministic analysis and internal MVP
chain, but the completion audit identified trust-root, product-integration,
requirements, documentation, Pilot, package-API, and supply-chain gaps.

P2-EXIT converts those findings into one bounded hardening project:

```text
seal deterministic authorization trust
→ integrate the complete deterministic score chain
→ close or formally rescope Hard Gate requirements
→ establish one current source of truth
→ collect external report-only Pilot evidence
→ harden package and release provenance
→ perform Phase 3 Go/No-Go review
```

The project does not add LLM semantic analysis. It prepares a trustworthy seam
for Phase 3.

## 2. Success criteria

P2-EXIT is complete only when all of the following hold:

1. a repository-controlled minimal forged qualification artifact cannot obtain
   Gate authority;
2. Policy and Qualification authority are pinned or loaded from a protected
   trust source independent from untrusted target changes;
3. Agentic Factor, Technical, Drift, Governance, Overall, and qualified Gate
   results are available through a versioned user-facing report and CLI path;
4. the “3–5 Hard Gates” requirement is either satisfied or formally changed to
   the reviewed one-Gate MVP scope;
5. current-state documentation contains no contradictory CLI, Gate, Policy, or
   version claims;
6. a complete product provenance registry accounts for every public interface;
7. at least one real external Agent repository completes a report-only Pilot;
8. public package imports work from a clean process and the Wheel is typed;
9. two builds from identical reviewed source produce identical artifacts, or a
   documented deterministic-build exception is explicitly accepted;
10. lockfile/SBOM/license evidence is produced for Phase 3 dependencies;
11. all existing security invariants remain true;
12. a Phase 3 Go/No-Go report is accepted before LLM integration begins.

## 3. Scope and non-goals

### In scope

- trusted Policy and Qualification control plane;
- Capability enforcement trust binding;
- integrated deterministic score reporting;
- Gate requirement closure;
- current-state documentation and provenance repair;
- external report-only Pilot;
- package import, typing, dependency, SBOM, and reproducible-build hardening;
- release candidate and Phase 3 entry review.

### Out of scope

- LLM provider integration;
- semantic Finding generation;
- semantic Diff;
- automatic Rule generation or publication;
- runtime exploit execution;
- active MCP connection;
- OAuth or identity attestation implementation;
- production authorization based on LLM output.

## 4. Workstreams

## P2-EXIT-01 — Trusted Gate Qualification Registry

- Priority: P0
- Depends on: P2-AUDIT-01
- Estimated effort: 1 engineer, 5–8 working days
- Version impact: new Qualification Registry contract; Capability CI Report
  review required

### Problem

The current Capability enforcement path accepts a repository-relative minimal
JSON artifact as qualification authority without verifying its full evidence
binding chain or an approved digest.

### Required design

Introduce a strict trusted registry such as:

```yaml
format: agentsec-qualified-gate-registry
schema_version: "0.1.0"
registry_id: internal-approved-gates
registry_version: "2026.08.25"
gates:
  - gate_id: HG-CAPCHAIN-001
    qualification_artifact_id: qualification-report-sha256:...
    qualification_sha256: ...
    evidence_mode: human
    qualification_status: accepted
    allowed_floor: high
```

The Policy references the registry or pins the expected Gate qualification:

```yaml
capability:
  qualification_registry_sha256: ...
  qualified_gates:
    - HG-CAPCHAIN-001
```

### Implementation requirements

- full Pydantic/JSON Schema contract;
- bounded UTF-8 regular-file no-follow loader;
- duplicate/unknown field rejection;
- complete qualification report validation;
- recomputation and verification of artifact/evidence IDs;
- qualification SHA-256 pinning;
- Gate ID, floor, evidence mode, qualification status, and Rule binding checks;
- no repository auto-discovery from scanned Agent content;
- missing or invalid trust evidence fails closed with exit `3`;
- no LLM, runtime-unverified, or D-confidence Gate authority.

### Tests

```text
minimal forged qualification rejected
truncated qualification rejected
wrong evidence artifact ID rejected
wrong qualification SHA-256 rejected
wrong Gate ID or Rule ID rejected
wrong floor rejected
symlink rejected
duplicate key rejected
valid pinned qualification accepted
missing registry fails closed
```

### Definition of Done

A PR-created qualification file cannot gain Gate authority unless it matches the
separately approved registry and digest.

## P2-EXIT-02 — Trusted CI Control Plane

- Priority: P0
- Depends on: P2-EXIT-01
- Estimated effort: 1–2 engineers, 4–7 working days
- Version impact: Organization Policy Schema `0.2.0 → 0.3.0` expected

### Problem

Current CI reads Workflow, Runner, Policy, Waiver, and Qualification from the
same PR checkout that is being evaluated.

### Required modes

Support and document at least one protected mode:

```text
Mode A: separate trusted security-policy repository checkout
Mode B: immutable artifact/digest supplied by protected CI configuration
Mode C: signed Policy/Qualification bundle verified locally
```

Repository-local Policy may remain available only as an explicitly lower-trust
mode with documented prerequisites.

### Implementation requirements

- Policy expected SHA-256 option or protected Policy bundle;
- Qualification Registry expected SHA-256;
- separate target root and trust-root parameters;
- no trust artifact discovered under scanned project content;
- protected Waiver source or signed/pinned Waiver bundle;
- CI examples using two checkouts or immutable Policy artifact;
- CODEOWNERS and branch-protection guidance;
- report trust-source ID, digest, and verification state;
- fail closed on digest mismatch;
- preserve Findings when trust verification fails.

### Definition of Done

Changing files in the target PR alone cannot disable enforcement, create a
Waiver, or qualify a Gate.

## P2-EXIT-03 — Integrated Agentic Score CLI and Report

- Priority: P0
- Depends on: P2-31, P2-EXIT-01 architecture review
- Estimated effort: 2 engineers, 8–12 working days
- Version impact:
  - Capability Assessment Output `0.2.0 → 0.3.0` or a new Agentic Assessment
    Output `0.1.0`;
  - Package `0.3.0 → 0.4.0`;
  - SARIF Reporter version review.

### Problem

P2-18 through P2-23 engines and P2-24 replay exist, but the main CLI does not
expose the complete score chain.

### Required product decision

Choose one reviewed command surface:

```text
Option A: agentsec capability assess --include-score
Option B: agentsec score PROJECT
Option C: agentsec assess PROJECT as a unified orchestration command
```

Recommended minimum: additive `agentsec score` to avoid silently changing
existing Capability Assessment semantics.

### Required explicit inputs

Drift and Governance cannot be fabricated. CLI must accept a bounded context
file containing reviewed values such as:

```text
before Manifest/Baseline
change source
approval status/reference
deployment scope
baseline trust
policy owner
approval owner
waiver counts/expiry state
optional CVSS association
accepted deterministic Gate matches
```

### Report requirements

```text
Agentic Factor Vector
Threat/Mitigation Vector
Technical Score
Drift Score
Governance Score
Base Overall Score
Qualified Hard Gate Floor
Overall Score and Severity
component versions and SHA-256
Coverage/Unknown state
explicit report-only policy
```

Text, JSON, and SARIF must be supported. Score must not acquire CI authority in
this task.

### Definition of Done

A user can run one documented CLI command and obtain the full deterministic
score chain with all required inputs, evidence, versions, and boundaries.

## P2-EXIT-04 — Hard Gate Scope Closure

- Priority: P1
- Depends on: P2-EXIT-01, external evidence review
- Estimated effort:
  - rescope path: 2–3 working days;
  - additional Gate path: 2–4 weeks including independent review.

### Decision required

The original requirement says 3–5 Capability Hard Gates, while the product
supports one qualified Gate.

Select exactly one path:

#### Path A — Formal one-Gate MVP scope

- accept `HG-CAPCHAIN-001` as the Phase 2 MVP Gate;
- keep `HG-PRODAUTO-001` and `HG-EXTERNALPROD-001` as Shadow candidates;
- update the requirement table, ADR, release notes, and acceptance criteria;
- state that additional Gates require external Pilot evidence.

#### Path B — Complete 3–5 Gates

- prepare at least 20 reviewed Positive and 20 eligible Negative/Near-miss Cases
  per Gate;
- independent Reviewer A/B plus Adjudication;
- Confidence calibration;
- qualification report and registry binding;
- Shadow and report-only Pilot;
- only then add to enforcement allow-list.

### Recommendation

Use Path A before Phase 3. Do not manufacture Gate count without external
evidence.

## P2-EXIT-05 — Documentation, Schema, and Version Provenance Consolidation

- Priority: P1
- Depends on: P2-EXIT-03 and P2-EXIT-04 decisions
- Estimated effort: 1 engineer, 5–7 working days

### Deliverables

- one authoritative `docs/current-architecture.md`;
- one authoritative Phase 2 completion/status page;
- updated README command and release surface;
- corrected Organization Policy, Capability CI, Change Impact, Scope, and
  Integration documents;
- superseded banners linking Qualification v1 to v2;
- complete public interface version registry;
- central Schema ownership map;
- documentation consistency tests.

### Provenance requirements

Every public interface must be classified as one of:

```text
included in product version vector
included in a report-family version vector
historical and immutable
fixture-only/internal and explicitly excluded
```

Phase 3 additions must reserve version fields for:

```text
semantic analyzer
model/provider/model ID
Prompt
semantic output Schema
Rule Candidate workflow
Attack Graph
runtime attestation
```

No model version may imply authorization authority.

## P2-EXIT-06 — External Real-project Report-only Pilot

- Priority: P1
- Depends on: P2-EXIT-02; may run in parallel with P2-EXIT-03
- Estimated calendar: 2–4 weeks
- Minimum participants: project owner, developer, security reviewer

### Minimum scope

- at least one real Agent repository;
- at least 20 scans and 10 PR scans;
- report-only first;
- one risky-change exercise;
- one incomplete-Coverage exercise;
- one Waiver lifecycle exercise;
- independent TP/FP/FN labels;
- performance p50/p95/max;
- Coverage and Unknown distribution;
- developer usability feedback;
- no LLM influence.

### Deliverables

```text
pilots/<project>/pilot.yaml
pilots/<project>/human-labels.json
pilots/<project>/results/pilot-report.json
pilots/<project>/results/pilot-report.md
docs/pilots/<project>/acceptance.md
```

### Phase 3 use

The Pilot identifies the real semantic gaps that Phase 3 LLM analysis should
address. LLM scope must be selected from reviewed FN/Unknown evidence rather
than feature intuition.

## P2-EXIT-07 — Package API and Supply-chain Hardening

- Priority: P2, but required before adding third-party LLM SDKs
- Depends on: P2-EXIT-03
- Estimated effort: 1–2 engineers, 5–8 working days

### Package/API work

- remove `agentsec.policy` circular import;
- move stable exit-code types below CLI initialization;
- add clean-process public import tests;
- add and package `py.typed`;
- define supported public Python API surface.

### Build/supply-chain work

- dependency lockfile for runtime and development environments;
- license inventory;
- CycloneDX or SPDX SBOM;
- `SOURCE_DATE_EPOCH` support;
- reproducible Wheel and sdist double-build test;
- pin build backend/tool versions;
- optional artifact signature and provenance statement;
- replace dependency `.pth` bridge with a reviewed offline dependency bundle or
  explicitly rename the current test to Wheel-isolation verification.

### Distribution governance

- decide which Calibration and Reviewer artifacts ship in sdist;
- remove unnecessary duplicated blinded packs from general distribution;
- retain a separate evidence archive if needed;
- scan release inputs for personal/internal identifiers.

## P2-EXIT-08 — Phase 3 Entry Review and 0.4.0 Candidate

- Priority: P0 release gate
- Depends on: P2-EXIT-01～07, with explicit exception records for any deferred P2
  item
- Estimated effort: 3–5 working days

### Required review

```text
security invariant review
threat-model update
Policy/Qualification trust review
integrated scoring contract review
Hard Gate scope decision
external Pilot evidence review
documentation consistency review
supply-chain review
clean install and artifact review
```

### Release target

Recommended:

```text
AgentSec 0.4.0 Phase 3 Ready Candidate
```

A pre-1.0 minor version is appropriate because P2-EXIT adds new public trust,
Policy, CLI, and report contracts.

### Go criteria

```text
all P0 findings closed
no open unreviewed authorization path
trusted Policy/Qualification digest verification demonstrated
integrated score report available
Hard Gate scope explicit
external Pilot complete or formally accepted as a Phase 3 Shadow-only exception
current docs consistent
full tests and release checks pass
```

### No-Go conditions

```text
LLM output can reach Allow/Block
Policy or Qualification can be self-modified by target PR
forged qualification is accepted
Agentic score context is implicit or invented
Gate scope remains contradictory
current-state docs remain stale
```

## 5. Delivery waves and dependencies

```text
Wave 0 — 1–2 days
  approve P2-EXIT plan
  freeze new Phase 3 authorization features
  assign owners

Wave 1 — Security foundation, 1–2 weeks
  P2-EXIT-01 Trusted Qualification Registry
  P2-EXIT-02 Trusted CI Control Plane

Wave 2 — Product integration, 2–3 weeks
  P2-EXIT-03 Agentic Score CLI/Report
  P2-EXIT-04 Hard Gate Scope Closure
  P2-EXIT-05 Docs/Version/Schema Consolidation

Wave 3 — Evidence and supply chain, 2–4 weeks calendar
  P2-EXIT-06 External Pilot
  P2-EXIT-07 Package/Supply-chain Hardening

Wave 4 — 3–5 days
  P2-EXIT-08 Phase 3 Go/No-Go and 0.4.0 Candidate
```

Critical path:

```text
EXIT-01 → EXIT-02 → EXIT-06 → EXIT-08
         ↘ EXIT-03 → EXIT-05 ↗
```

## 6. Staffing and estimate

Recommended team:

| Role | Allocation |
|---|---:|
| Security/Policy engineer | 1 |
| Core Python/CLI engineer | 1 |
| Test/Release engineer | 0.5–1 |
| External Pilot owner/reviewer | 1 part-time |

Estimated effort:

```text
Minimum Phase 3-safe foundation: 3–5 weeks
Full P2-EXIT including external Pilot and supply chain: 6–9 weeks calendar
```

The external Pilot calendar may overlap product integration work.

## 7. Test strategy

### Security regression

- Policy/Qualification forgery and tampering;
- protected trust-root containment;
- fail-closed behavior;
- Waiver scope/expiry/digest;
- Coverage/Unknown precedence;
- LLM authority remains false.

### Contract regression

- JSON Schema freeze and compatibility;
- complete version/provenance vector;
- Agentic component hash binding;
- deterministic score replay;
- SARIF mapping;
- CLI exit codes.

### Release regression

- clean public imports;
- typed package marker;
- two-build byte reproducibility;
- lockfile consistency;
- SBOM completeness;
- Wheel/sdist contents;
- clean non-editable installation;
- Policy trust mode smoke test.

## 8. Governance

Every task must follow:

```text
one Task ID at a time
ADR before security-significant contract changes
version impact review
no execution of scanned content
no secret values in reports or fixtures
deterministic Rules retain authorization authority
LLM remains candidate evidence only
```

Required ADRs:

```text
ADR-0062 Trusted Policy and Qualification Root
ADR-0063 Integrated Agentic Assessment Contract
ADR-0064 Hard Gate Phase 2 Scope Decision
ADR-0065 Phase 3 Ready Version/Provenance Contract
ADR-0066 Reproducible Build and SBOM Policy
```

## 9. Phase 2 completion and Phase 3 handoff

P2-EXIT-01 through P2-EXIT-07 are complete. The independently reviewed external
Homi Pilot completed on 2026-08-26 after P2-EXIT-06-05A corrected four bounded
false negatives in Rule Pack `0.3.1`.

```text
External Pilot       20/20 passed
FP / FN              0 / 0
Precision / Recall   1.0 / 1.0
Entry state          ready_for_candidate
Phase 3 Shadow-only  permitted
Release              not permitted
```

Phase 3 implementation may now begin in Shadow-only mode. Semantic output must
remain disconnected from Policy and CI authority. Candidate version promotion,
artifacts, verification, and release remain in the later
`candidate_acceptance` stage and require explicit release-owner action.

## 10. Non-negotiable Phase 3 authority boundary

```text
LLM output = candidate evidence only
LLM output != Allow/Block
LLM output != automatic Rule publication
LLM output != Waiver approval
LLM output != Severity downgrade
```
