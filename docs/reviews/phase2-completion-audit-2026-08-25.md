# AgentSec Phase 2 Completion Audit

- Audit ID: `P2-AUDIT-01`
- Date: 2026-08-25
- Scope: Phase 2 requirements, source, tests, Policy, calibration, CI, Pilot,
  release artifacts, and Phase 3 entry readiness
- Audited package: AgentSec `0.3.0`
- Conclusion: **Nominally complete; Phase 3 entry is conditionally blocked**

## 1. Executive conclusion

The repository has completed the majority of Phase 2 engineering and has a
verified local internal MVP release:

```text
15 Markdown Rules
29 Capability Rules
Agent Manifest / Capability Diff / Change Impact
CVSS and Agentic score engines
SARIF / fail-on / Organization Policy / Waivers
1 qualified Capability Gate
CI examples
8-case internal Pilot
Rule/Score calibration v1
0.3.0 Wheel and sdist
1154 passing tests
```

However, the audit found two security/integration blockers and several
requirements or readiness items that are not substantively closed. Phase 3
architecture work may start, but LLM semantic analysis must not be connected to
CI, Policy, Rule publication, or authorization until the P0 findings below are
fixed.

## 2. Verified strengths

| Area | Audit result |
|---|---|
| Static scanning does not execute scanned content | Pass |
| Secret-value minimization in principal reports | Pass |
| Deterministic Rules own CI decisions | Pass by design |
| Severity and Evidence Confidence remain separate | Pass |
| Critical/High cannot be diluted by averaging | Pass |
| Coverage incomplete returns a visible non-clean result | Pass |
| Markdown Rule count | Pass — 15 |
| Capability Rule count | Pass — 29 |
| SARIF / JSON / Text | Pass |
| Organization Policy and expiring Waivers | Pass for local explicit files |
| Internal Pilot | Pass — 8/8 curated scenarios |
| Scoring replay | Pass — 7/7 after 0.3.0 provenance refresh |
| Full test suite | Pass — 1154 |
| Clean non-editable Wheel installation | Pass |
| Release artifact checksums | Pass |

## 3. P0 blockers before Phase 3 semantic or authorization integration

### P2-AUDIT-F01 — Capability Gate qualification has no trusted root

**Severity: Critical design gap**

`src/agentsec/policy/ci_enforcement.py::_qualification_accepted` discovers a
repository-relative JSON file and accepts it when a small set of fields says the
Gate is accepted. It does not validate the complete qualification contract,
bind an approved SHA-256 in Policy, verify a signature, or require an immutable
external trust source.

Audit reproduction created a minimal fabricated report containing only:

```json
{
  "format": "agentsec-gate-scoped-qualification-report",
  "schema_version": "0.1.0",
  "gate_id": "HG-CAPCHAIN-001",
  "qualification": {
    "status": "accepted",
    "eligible_for_report_only_gate": true
  }
}
```

Observed result:

```text
minimal_forged_qualification_accepted = True
```

A repository change can therefore manufacture the qualification authority that
the enforcement engine is intended to trust.

Required remediation:

1. introduce a typed qualification registry/loader;
2. validate the complete qualification artifact and evidence binding chain;
3. require Policy to pin an expected qualification artifact ID/SHA-256;
4. preferably load qualification from a protected path outside the scanned PR
   checkout or verify a trusted signature;
5. add tamper, truncation, wrong-evidence-ID, wrong-hash, and forged-minimal-file
   tests;
6. keep fail closed when trusted qualification is unavailable.

### P2-AUDIT-F02 — CI Policy and Waiver authority are mutable inside the PR checkout

**Severity: Critical deployment gap**

The GitHub workflow reads these paths from the checked-out repository:

```text
scripts/run-agentsec-ci.sh
policies/organization-policy-enforce-example.yaml
qualification evidence under calibration/
```

The workflow provides no Policy digest pin, protected external Policy checkout,
signature verification, or repository `CODEOWNERS` file. A PR capable of
changing the Policy, Waiver, CI Runner, Workflow, or qualification evidence can
attempt to weaken the same control evaluating that PR.

Recording Policy SHA-256 in the output is provenance, not trust enforcement.

Required remediation:

1. define a trusted Policy delivery mode independent from untrusted target
   changes;
2. pin approved Policy and qualification SHA-256 values in protected CI
   configuration;
3. add CODEOWNERS/branch-protection deployment guidance;
4. separate scanner source checkout from target project checkout where possible;
5. make CI fail if workflow/Policy/qualification files change without approved
   ownership;
6. document that repository-local Policy is suitable only when the repository
   change-control plane is already trusted.

### P2-AUDIT-F03 — Agentic scoring is not integrated into the primary CLI reports

**Severity: High integration blocker**

P2-18 through P2-23 implement Factor, Threat/Mitigation, Technical, Drift,
Governance, Overall, and Hard Gate engines. P2-24 provides a replay script.
However, current `agentsec capability assess` output contains no:

```text
agentic_factors
technical_score
drift_score
governance_score
overall_score
unified Overall Hard Gate assessment
```

There is no public score CLI command. The primary Scan and Capability Assessment
reports therefore cannot deliver the full Phase 2 score chain that the release
advertises, and Organization Policy cannot consume the Overall Score.

Required remediation:

1. define a versioned integrated Agentic Assessment contract;
2. define explicit Drift/Governance context inputs rather than inventing them;
3. attach Technical/Drift/Governance/Overall results to a user-facing report;
4. add Text/JSON/SARIF delivery;
5. decide whether the command is `capability assess`, a new `score` command, or
   an explicit orchestration report;
6. keep score report-only until separately calibrated Policy semantics exist;
7. preserve component evidence and version fingerprints.

Phase 3 semantic Evidence needs this seam before it can be safely introduced.

## 4. High-priority requirement gaps

### P2-AUDIT-F04 — Original 3–5 Capability Hard Gate requirement is not met

**Severity: High scope gap**

The Phase 2 table requires 3–5 combination Hard Gates. The implementation and
Organization Policy allow-list currently support only:

```text
HG-CAPCHAIN-001
```

`HG-PRODAUTO-001` and `HG-EXTERNALPROD-001` remain unqualified candidates.

Required decision before Phase 3:

- either formally change the Phase 2 MVP acceptance criterion to “one qualified
  Gate plus candidate framework” through ADR and plan update;
- or implement and qualify at least two additional Gates.

Do not leave the table claiming 3–5 while the product supports one.

### P2-AUDIT-F05 — P2-30 is an internal fixture Pilot, not a real external project

**Severity: High evidence gap**

The Pilot correctly declares:

```text
evidence_mode = internal_integration
```

It is deterministic and useful, but it does not provide production repository
FP/FN, PR behavior, Coverage gaps, performance distribution, user feedback, or
Waiver governance evidence.

Before using Phase 3 LLM output to influence tuning, select at least one real
Agent repository and collect report-only evidence with independent human labels.

### P2-AUDIT-F06 — Phase 2 source-of-truth documentation is stale and contradictory

**Severity: High AI-development readiness gap**

Examples:

- `README.md` says Capability Diff is not in the CLI, then later documents its
  CLI command;
- `docs/phase2-scope.md`, `docs/phase2-integration-plan.md`, and
  `docs/capability-calibration-hard-gate-enforcement-plan.md` still say P2-15A
  is pending and no Capability Hard Gate exists;
- `docs/capability-change-impact.md` says the package is 0.2.0 and the feature is
  unreleased;
- `docs/organization-policy.md` header says Policy/Report `0.2.0`, while its body
  says Assessment Output `0.1.0`, Organization YAML `0.1.0`, and Capability CI
  Output `0.2.0` instead of the current `0.3.0`;
- `docs/p2-15b-policy-controlled-ci-enforcement.md` has the same stale
  Organization Policy and output versions;
- old qualification task documents still present the pre-v2
  `more_data_required` result without a clear superseded banner.

This is especially risky for Phase 3 because coding agents will use these files
as authoritative context.

Required remediation:

1. designate one current Phase 2 architecture/status document;
2. mark historical task/ADR statements as historical rather than current;
3. update current CLI, versions, Gate status, enforcement, and release status;
4. add a documentation consistency regression test for current-state pages;
5. add superseded pointers from qualification v1 to v2.

### P2-AUDIT-F07 — The “complete” version vector omits many Phase 2 interfaces

**Severity: High provenance gap**

`VersionSet` is described as complete but contains only 16 fields. It omits,
among others:

```text
Agentic Factor
Threat/Mitigation
Technical/Drift/Governance/Overall Score
Scoring Replay
SARIF Reporter
Fail-On Policy and Report
Organization Policy and Report
Capability CI Report
Calibration contracts
Pilot contracts
Rule/Score Calibration
```

Individual reports sometimes carry local versions, but the central provenance
contract is not complete. Adding LLM model, Prompt, semantic analyzer, and graph
versions on top of this will worsen traceability.

Required remediation:

- introduce a complete, versioned product provenance vector or split it into
  explicit report-family vectors with a common top-level registry;
- add tests that every public serialized interface version is either included or
  explicitly declared local-only;
- include future LLM model ID, Prompt version, semantic schema, and Rule Candidate
  pipeline version without giving them authorization authority.

## 5. Medium-priority engineering and release gaps

### P2-AUDIT-F08 — `agentsec.policy` has an import-order circular dependency

A fresh process running:

```python
import agentsec.policy
```

fails because Policy imports `agentsec.cli.exit_codes`, which initializes the
CLI application, which imports Capability CLI, which imports Policy again.
Existing tests hide the issue by importing `agentsec.cli` first.

Remediation: move stable exit-code types out of the CLI package or remove the
Policy domain module's dependency on CLI initialization; add a clean-process
public-import smoke test.

### P2-AUDIT-F09 — Release builds are not byte-reproducible

Two Wheel builds from unchanged source produced different SHA-256 values while
all member contents were equal. Differences were ZIP timestamps in six
`.dist-info` entries.

Remediation:

- honor `SOURCE_DATE_EPOCH`;
- normalize Wheel and sdist timestamps/order/ownership;
- add a double-build reproducibility test;
- pin build backend versions.

### P2-AUDIT-F10 — Dependency and supply-chain evidence is minimal

There is no dependency lockfile, SBOM, signature, SLSA provenance, or artifact
attestation. The offline installation test bridges dependencies from the base
environment through a `.pth` file, so it proves Wheel isolation but not a fully
self-contained dependency set.

This is accepted for 0.3.0, but Phase 3 LLM SDK/provider dependencies should not
be added until dependency locking, license review, and SBOM generation are
defined.

### P2-AUDIT-F11 — Public typing and package API hardening are incomplete

The Wheel has no `py.typed` marker, so downstream strict type checkers cannot
reliably consume the package's annotations. Public import smoke tests are also
not comprehensive.

Remediation: add `py.typed`, package it, and test representative public imports
from a clean installed Wheel.

### P2-AUDIT-F12 — Central Schema export does not own every shipped Schema

The release exports most public Schemas centrally, but at least these are
maintained outside `scripts/export_release_schemas.py`:

```text
capability-shadow-gate-demo.schema.json
joint-expert-review-evidence.schema.json
```

Either register them in the central exporter and frozen-schema test or classify
them explicitly as generated fixture contracts with their own authoritative
export path.

### P2-AUDIT-F13 — Sdist distribution scope needs data-governance review

The sdist includes the entire Calibration tree, including reviewer packs,
completed human-review evidence, templates, and duplicated blinded case files.
No obvious personal identity or internal host was found in the sampled scan, but
release distribution should explicitly define which human-review evidence may
leave the development workspace and which aliases/metadata are acceptable.

## 6. Items correctly deferred to Phase 3

The following are not Phase 2 omissions when kept out of authorization:

```text
LLM semantic analysis
semantic natural-language Diff
automatic Rule Candidate generation
Capability Attack Graph
runtime Tool/OAuth/Permission attestation
dynamic exploit validation
active red-team execution
automatic Rule publication
```

They become Phase 3 work only after the P0 trust and integration blockers are
resolved.

## 7. Phase 3 entry gate

### Must complete before Phase 3 implementation touches CI or authorization

```text
P2-EXIT-01 Trusted Policy and Gate Qualification Root
P2-EXIT-02 Integrated Agentic Score CLI/Report Contract
P2-EXIT-03 Hard Gate scope decision: implement 3–5 or formally descope to 1
P2-EXIT-04 Current-state documentation and version provenance consolidation
```

### May run in parallel with early Phase 3 architecture design

```text
P2-EXIT-05 External real-repository report-only Pilot
P2-EXIT-06 Policy package import/API repair
P2-EXIT-07 Reproducible build, lockfile, SBOM, py.typed
P2-EXIT-08 Release calibration-data governance
```

### Phase 3 authorization constraint

Until external calibration and runtime attestation exist:

```text
LLM output = candidate evidence only
LLM output != Allow/Block
LLM output != Rule publication
LLM output != Waiver approval
LLM output != Severity downgrade
```

## 8. Recommended next task

Start with:

```text
P2-EXIT-01: Trusted Policy and Gate Qualification Root
```

It is the highest-risk omission because Phase 3 will introduce a less
deterministic analyzer. The deterministic authorization plane must be protected
before new semantic evidence is connected to it.
