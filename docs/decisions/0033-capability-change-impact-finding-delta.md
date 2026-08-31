# ADR-0033: Capability Change Impact and Finding Delta Output 0.1.0

- Status: Accepted
- Date: 2026-08-20
- Task: P2-13
- Development package: `0.2.0` source line; a future release review must choose
  the next package version
- Last accepted local release: `0.2.0`
- Capability Change Impact Output: `0.1.0` (new)
- Agent Manifest Schema: `0.3.0` (unchanged)
- Capability Diff Schema: `0.1.0` (unchanged)
- Capability Rule Pack / Risk Model: `0.1.0` / `0.1.0` (unchanged)
- Enforcement: report-only, unchanged

## Context

P2-11 and P2I-04 can compare normalized Manifest collections and report added,
removed, or modified Tool, Permission, Control, Runtime Identity, Relationship,
and Unknown items. The value-minimizing Capability Diff intentionally contains
item IDs, changed field names, fingerprints, and provenance rather than complete
before/after values.

That contract cannot yet answer:

```text
What reviewed semantic state existed before and after?
Did the Tool/Permission/Control change increase or reduce static exposure?
Which deterministic Findings appeared, disappeared, changed, or persisted?
Did any new High/Critical Finding appear?
Which capability changes are correlated to a Finding Delta?
```

Adding source values or complete Manifest item payloads to the existing
Capability Diff would weaken its disclosure boundary. Directly assigning a new
numeric score to every change would also silently introduce a new risk model
without calibration.

## Decision

### 1. Add one deep application interface

Add:

```python
ManifestCapabilityChangeImpactEngine.compare(
    before: AgentManifest,
    after: AgentManifest,
) -> CapabilityChangeImpactReport
```

The deterministic implementation hides three operations behind this interface:

```text
CapabilityDiffer.compare
Capability Rule evaluation for before and after
semantic Change Impact + logical Finding Delta analysis
```

The caller supplies two already-validated Manifests. The implementation performs
no filesystem discovery, source reread, execution, network access, environment
access, MCP connection, memory access, or LLM call.

### 2. Preserve the existing Capability Diff contract

Keep:

```text
CAPABILITY_DIFF_SCHEMA_VERSION = 0.1.0
```

and embed the canonical `CapabilityDiffResult` in the new artifact. Existing
`agentsec capability diff` output therefore remains readable and value-minimizing.

### 3. Add an independent output contract

Create:

```text
format = agentsec-capability-change-impact
CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION = 0.1.0
```

The strict artifact contains:

```text
status and versions
fixed report-only policy
management summary
canonical Capability Diff
Tool/Permission/Control semantic Change Impacts
Finding Delta
before/after isolated Rule failures
```

Package source remains `0.2.0` during this task so the accepted local release
boundary is not silently converted into a publication. A future release review
must choose and verify the next package version before distributing P2-13.

### 4. Expose reviewed semantic before/after state only

P2-13 serializes only these normalized fields:

```text
Tool: kind, availability, side_effects, parent_tool_id
Permission: action, effect, resource, scope, target
Control: kind, state, target
```

It excludes Tool display names, source text, Commands, arguments, URLs, Headers,
environment values, credential values, memory content, parser values, and
complete Manifest item payloads.

### 5. Classify exposure direction without adding a risk score

Each Tool/Permission/Control change receives one deterministic direction:

```text
increased_exposure
reduced_exposure
mixed
neutral
uncertain
```

Stable reason codes explain the classification. This direction is a semantic
change interpretation, not Severity, CVSS, authorization, exploitability, or a
CI decision. Unknown normalized states produce `uncertain` rather than an
optimistic decrease.

The implementation uses ordered exposure/protectiveness comparisons only to
select direction. No numeric intermediate value is serialized and Capability
Risk Model `0.1.0` remains unchanged.

### 6. Match logical Findings independently from evidence identity

Finding IDs include evidence provenance and may change when source hashes change.
Finding Delta therefore matches by:

```text
rule_id + sorted related_ids
```

The lifecycle is:

```text
added
resolved
changed
unchanged
```

A changed entry identifies trusted fields such as correlation, score, Severity,
Confidence, or evidence fingerprint. Added and resolved Findings retain complete
before/after risk snapshots without source excerpts.

### 7. Preserve high-water-mark behavior

The summary reports:

```text
highest before Severity
highest after Severity
added High/Critical count
resolved High/Critical count
```

It never averages Findings. Added High/Critical Findings remain visible even if
many lower or unchanged Findings exist. Severity and Evidence Confidence remain
separate.

### 8. Completeness and failure policy

The Change Impact report is complete only when:

```text
both Manifest Coverage values are complete
before Capability Rule execution is complete
after Capability Rule execution is complete
```

Visible changes and Finding Delta remain available when incomplete, but status
and CLI exit code are `incomplete` / `2`. Findings alone continue to return `0`.
Exit `1` remains reserved.

### 9. Add an additive CLI command

Add:

```text
agentsec capability impact \
  --before BEFORE.manifest.json \
  --after AFTER.manifest.json \
  --format text|json \
  --language en|zh
```

The command reuses bounded no-follow Manifest input and private atomic report
output. It does not change the existing `capability diff` JSON shape.

## Consequences

### Positive

- Developers see safe semantic before/after state instead of hashes alone.
- Management can see new, resolved, changed, and persistent Findings.
- High/Critical Finding increases cannot be hidden by averaging.
- Existing Capability Diff 0.1.0 remains stable.
- Finding matching survives evidence-only source hash changes.
- The report remains deterministic, bilingual, Schema-backed, and report-only.

### Negative

- Only Tool, Permission, and Control changes receive P2-13 semantic impact;
  Runtime Identity, Relationship, Unknown, and profile changes remain visible in
  embedded Capability Diff but count as unassessed impact.
- Exposure direction is deterministic but not empirically calibrated Severity.
- Logical matching depends on stable Rule IDs and related IDs.
- Runtime grants, reachability, OAuth scopes, successful exploitation, and global
  Agent safety remain unverified.
- The accepted 0.2.0 distribution does not contain P2-13; a later release review
  must rebuild and accept a new package artifact.
