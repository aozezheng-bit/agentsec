# ADR-0034: Capability Rule Pack 0.2.0 Expansion

- Status: Accepted
- Date: 2026-08-20
- Task: P2-14
- Development package: `0.2.0` source line; unreleased from accepted `dist/0.2.0`
- Capability Rule Pack: `0.1.0` → `0.2.0`
- Capability Risk Model: `0.1.0` (unchanged)
- Agent Manifest Schema: `0.3.0` (unchanged)
- Enforcement: report-only, unchanged

## Context

P2I-02 established the framework-neutral Capability Rule seam and six initial
combination Rules. P2-13 then made the appearance, resolution, and change of
those Findings visible through Capability Change Impact and Finding Delta.

The six-Rule pack demonstrates the architecture but leaves common Manifest
facts without a dedicated deterministic review signal, including:

```text
production-scoped permissions
external write or execution
explicit automatic approval
missing sandbox, network, secret, timeout, or tool-filter controls
external and privileged runtime identities
memory combined with secrets, network, or production authority
delegation combined with persistence or external authority
Unknown high-impact relationships
```

P2-14 must expand coverage without introducing an LLM, runtime verification,
CI blocking, an attack graph, or a new scoring formula. The existing Manifest
already contains the normalized facts needed for conservative static Rules.

## Decision

### 1. Expand the built-in inventory to 29 Rules

Keep the six existing stable IDs and add 23 stable IDs:

```text
CAP-AUTONETWORK-001
CAP-AUTOPROD-001
CAP-AUTOSECRET-001
CAP-DELEGATEEXTERNAL-001
CAP-DELEGATEPERSIST-001
CAP-EXTERNALEXEC-001
CAP-EXTERNALPRIVILEGED-001
CAP-EXTERNALUNVERIFIED-001
CAP-EXTERNALWRITE-001
CAP-MEMORYNETWORK-001
CAP-MEMORYPROD-001
CAP-MEMORYSECRET-001
CAP-NONETWORKPOLICY-001
CAP-NOSANDBOX-001
CAP-NOSECRET-001
CAP-PRODADMIN-001
CAP-PRODEXEC-001
CAP-PRODIDENTITY-001
CAP-PRODWRITE-001
CAP-RELATIONUNKNOWN-001
CAP-REQUIREDNOFILTER-001
CAP-REQUIREDNOTIMEOUT-001
CAP-SECRETPROD-001
```

The resulting inventory has 29 Rules, within the P2-14 target of 20–30.
Existing Rule IDs and their conditions remain stable.

### 2. Increment only the Capability Rule Pack

Set:

```text
CAPABILITY_RULE_PACK_VERSION = 0.2.0
CAPABILITY_RISK_MODEL_VERSION = 0.1.0
```

Adding Rule IDs and new deterministic Rule meanings is a pre-1.0 minor Rule Pack
change. No correlation-to-likelihood mapping, Confidence grade, impact
high-water-mark rule, NIST matrix, representative score, Severity range, or
Hard Gate behavior changes, so the Capability Risk Model remains `0.1.0`.

The Phase 1 Markdown Rule Pack remains `0.3.0` and is not affected.

### 3. Use only finalized Manifest facts

Every new Rule consumes only:

```text
ManifestTool
ManifestPermission
ManifestControl
ManifestRuntimeIdentity
ManifestRelation
ManifestUnknown
ManifestCoverage
source provenance references
```

Rules do not reread source files and do not access source values. Production and
external scope are matched only from normalized enum values. Missing controls
produce review Findings only when a relevant visible capability exists; they do
not assert that exploitation is possible.

### 4. Bound correlation and Finding cardinality

The extension keeps the P2I-02 correlation policy:

1. same target;
2. parent/child family where applicable;
3. explicit relation where a relation target directly correlates;
4. one bounded Agent-wide candidate when reachability is not proven;
5. incomplete/Unknown correlation for unresolved relationship state.

The implementation does not generate global permission × relation or
permission × identity Cartesian products. One Rule may emit multiple
same-target Findings when several independent targets meet its condition, but
Agent-wide combination Rules emit one candidate containing a bounded,
deduplicated set of related IDs.

### 5. Treat Unknown as visible uncertainty, not safety

Rules for missing controls accept a configured safe state only when it is
explicitly represented. Absent, disabled, or Unknown controls remain visible as
review Findings. `CAP-RELATIONUNKNOWN-001` specifically reports Unknown
high-impact delegation or memory relations.

`CAP-EXTERNALUNVERIFIED-001` records that static external identity metadata is
not a runtime attestation. It does not connect to the MCP server, enumerate
tools, inspect OAuth scopes, or validate the active principal.

### 6. Keep bilingual, evidence-backed, and report-only output

Every Rule includes reviewed English and Simplified Chinese:

```text
title
description
recommendation
impact rationale
```

Every materialized Finding retains source-backed, value-free evidence. Every
Rule and Finding remains:

```text
deterministic = true
hard_gate = false
CI blocking = false
runtime capability verified = false
```

P2-15 owns any separately reviewed report-only Capability Hard Gate design.
`--fail-on`, CI enforcement, waivers, runtime OAuth/permission verification,
LLM analysis, automatic Rule publication, and vulnerability reproduction remain
out of scope.

### 7. Preserve accepted 0.2.0 release artifacts

P2-14 changes the source tree and regenerated source-tree Demo fixtures. It does
not rebuild or replace the accepted local `dist/0.2.0` wheel and sdist. Those
accepted artifacts continue to contain Capability Rule Pack `0.1.0` with six
Rules. A future release review must choose a new Package version before
publishing Rule Pack `0.2.0`.

## Consequences

### Positive

- Deterministic coverage grows from six to 29 Rules without an LLM dependency.
- Production, external, approval, control, identity, memory, delegation, and
  Unknown risks become separately explainable.
- New Findings participate automatically in existing Text/JSON Assessment and
  Finding Delta output.
- Capability Risk Model semantics and report-only policy remain stable.
- Same-target and bounded Agent-wide correlation prevent unbounded Finding
  growth.

### Negative

- Some Rules intentionally overlap: for example a production admin permission
  may trigger production-admin, automatic-production, approval-gap, and
  sandbox-gap Findings. These are distinct control questions rather than a
  single averaged score.
- Static production scope and identity declarations remain hypotheses rather
  than runtime grants.
- Missing-control Findings may require organization policy context before a
  reviewer decides whether the control is mandatory.
- The Capability Drift Demo now contains more Findings and requires regenerated
  frozen artifacts and updated presenter narration.
- The accepted `0.2.0` distribution and current source tree intentionally differ
  until the next release review.
