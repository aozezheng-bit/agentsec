# ADR-0028: Explicit Unknowns and Versioned Capability Diff

- Status: Accepted
- Date: 2026-08-20
- Task: P2-11
- Agent Manifest Schema: `0.3.0` (unchanged)
- Capability Diff Schema: `0.1.0` (new)

## Context

P2-06 through P2-10 populate the Agent Manifest with resolved, partial,
unknown, unresolved, and conflicting profile states. They also retain unknown
values within individual Tools, Permissions, Controls, Runtime Identities, and
Relationships. Those states are machine-visible, but there is no systematic
`ManifestUnknown` inventory and no typed comparison between two complete
capability profiles.

A file-level Diff cannot safely answer whether a Tool was enabled, a network
permission appeared, an approval control changed, an identity became external,
or a delegation edge was added. Capability Diff therefore needs a separate,
versioned, value-minimizing interface.

## Decision

### 1. Explicit Unknown materialization

Add:

```python
UnknownExtractor.extract(manifest) -> AgentManifest
```

The extractor does not change existing profile resolution states. It adds
stable `ManifestUnknown` entries for unresolved profile status, item-level
unknown values, runtime verification requirements, and incomplete Coverage.
Repeated extraction is idempotent.

Profile mapping:

| Resolution | Unknown reason |
|---|---|
| `unresolved` | `not_analyzed` |
| `unknown` with no sources | `missing_source` |
| `unknown` with sources | `not_analyzed` |
| `partial` with incomplete Coverage | `incomplete_coverage` |
| `partial` with complete Coverage | `unsupported_field` |
| `conflict` | `conflicting_declarations` |
| `resolved` / `not_applicable` | no profile Unknown |

Item-level Unknowns include:

```text
Tool availability or side effects = unknown
Permission action/effect/resource/scope = unknown
Control state = unknown
Runtime principal/authentication/environment = unknown
Runtime privileged = null → runtime_verification_required
Relationship state = unknown
Coverage complete = false
```

Unknown IDs are SHA-256-derived from trusted dimension/reason/field/provenance
metadata. Raw source values are not used as display text.

### 2. Capability Diff scope

Add a versioned `CapabilityDiffer.compare(before, after)` interface for the same
Agent and Framework. It compares:

```text
Tools
Permissions
Controls
Runtime Identities
Relationships
Unknowns
profile resolution transitions
Coverage complete/incomplete transition
```

It deliberately does not compare source text, execute code, or replace the
existing Phase 1 file/text Diff.

### 3. Change model

Every item change is one of:

```text
added
removed
modified
```

The output contains:

```text
dimension
stable item_id
change_type
trusted changed_fields names
before/after SHA-256 fingerprints
before/after source references
```

The output does not serialize the complete before/after item payload. This
prevents a new Diff interface from becoming a second channel for normalized
untrusted names or future sensitive values. A modified item is detected from a
canonical JSON fingerprint and lists only top-level fields whose values differ.

Profile status changes are represented separately for:

```text
identity
instructions
configuration
tools
permissions
controls
runtime_identities
relationships
coverage
```

### 4. Compatibility and completeness

Capability Diff requires:

```text
same Agent Manifest schema version
supported current Agent Manifest schema
the same agent_id
the same framework_id
```

The result is `complete=true` only when both input Manifests have complete
Coverage. Incomplete inputs are still compared so visible changes are not lost,
but the result remains explicitly incomplete.

### 5. Independent Capability Diff Schema

Create:

```text
CAPABILITY_DIFF_SCHEMA_VERSION = 0.1.0
```

and add it to the central version vector. The new artifact has strict immutable
models, deterministic JSON encoding, compatibility-first validation, safe field
path errors, and deterministic Draft 2020-12 JSON Schema export.

`AGENT_MANIFEST_SCHEMA_VERSION` remains `0.3.0` because P2-11 only populates the
existing `unknowns` field. Existing Phase 1 `DIFF_OUTPUT_VERSION` remains
`0.1.0` because Capability Diff is not yet integrated into the `agentsec diff`
CLI output.

## Security boundary

P2-11 never:

- reads source files or source text during Unknown generation or Diff;
- executes Skills, Commands, Sub-Agents, Hooks, Plugins, Rules, or MCP;
- connects to network targets or reads environment/memory/credential values;
- copies full capability payloads into Diff changes;
- turns Unknown or Diff into a Risk Finding, Severity, or CI block;
- calls an LLM or treats LLM output as authorization.

Deterministic risk and policy rules remain a later, separate layer.

## Consequences

### Positive

- Missing and unresolved facts no longer remain only implicit in profile state.
- Unknowns are deterministic, source-backed, and idempotent.
- Capability changes are visible independently from file text changes.
- Diff output minimizes values while retaining stable identity and provenance.
- Incomplete Coverage cannot be presented as a complete Capability Diff.
- The new interface can evolve independently from Phase 1 Diff output.

### Negative

- Capability Diff does not yet have a CLI command or reporter.
- Top-level `changed_fields` do not explain nested value details.
- Added/removed item IDs may still be normalized human-readable identifiers;
  reporters must continue to apply output safety policy.
- Risk scoring for capability combinations remains future work.
