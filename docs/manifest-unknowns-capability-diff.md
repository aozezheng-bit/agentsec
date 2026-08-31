# AgentSec Explicit Unknowns and Capability Diff

- Task: `P2-11`
- Status: Complete
- Agent Manifest Schema: `0.3.0`
- Capability Diff Schema: `0.1.0`
- Decision: `docs/decisions/0028-explicit-unknowns-capability-diff.md`

## 1. Explicit Unknown generation

`UnknownExtractor` converts profile and item uncertainty into explicit
`ManifestUnknown` records:

```python
from agentsec.manifests import UnknownExtractor

final_manifest = UnknownExtractor().extract(manifest)
```

The extractor is idempotent. Running it again does not duplicate Unknowns.

Examples:

```text
identity.resolution = partial
→ dimension=identity, reason=unsupported_field

tools.skill:review.side_effects = unknown
→ dimension=tools, reason=unsupported_field

runtime_identities.identity:mcp-server:docs.privileged = null
→ dimension=runtime_identities,
  reason=runtime_verification_required

coverage.complete = false
→ dimension=coverage, reason=incomplete_coverage
```

Unknown does not mean absent, denied, or safe.

## 2. Profile status mapping

| Profile state | Explicit reason |
|---|---|
| `unresolved` | `not_analyzed` |
| `unknown`, no declaration sources | `missing_source` |
| `unknown`, declaration sources retained | `not_analyzed` |
| `partial`, incomplete Coverage | `incomplete_coverage` |
| `partial`, complete Coverage | `unsupported_field` |
| `conflict` | `conflicting_declarations` |
| `resolved` / `not_applicable` | no profile-level Unknown |

Item-level unknown fields can coexist with a profile-level Unknown. They answer
different questions: the profile entry explains completeness, while the item
entry identifies the exact unresolved field.

## 3. Capability Diff

`CapabilityDiffer` compares two compatible final Manifests:

```python
from agentsec.manifests import CapabilityDiffer

result = CapabilityDiffer().compare(
    before=before_manifest,
    after=after_manifest,
)
```

The two inputs must use the supported Manifest Schema and represent the same
Agent and Framework.

Compared item dimensions:

```text
tool
permission
control
runtime_identity
relationship
unknown
```

Compared profile states:

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

## 4. Change representation

Each change contains:

```text
dimension
item_id
added / removed / modified
changed_fields
before_sha256 / after_sha256
before_sources / after_sources
```

For added and removed items, `changed_fields=["item"]`. For modified items,
`changed_fields` contains safe model field names such as:

```text
availability
side_effects
effect
state
authentication
environment
sources
```

The complete before/after Tool, Permission, Control, Identity, Relationship, or
Unknown object is not copied into the Diff. Only canonical SHA-256 fingerprints
and source provenance are retained.

## 5. Completeness

```text
before complete + after complete → Diff complete=true
any incomplete input             → Diff complete=false
```

Visible changes are still returned for incomplete inputs. Consumers must not
treat them as exhaustive.

Coverage transitions also appear as profile changes:

```text
complete → incomplete
incomplete → complete
```

## 6. JSON and Schema

The independent interface version is:

```text
CAPABILITY_DIFF_SCHEMA_VERSION = 0.1.0
```

Public interfaces:

```python
from agentsec.manifests import (
    decode_capability_diff_json,
    encode_capability_diff_json,
    export_capability_diff_json_schema,
    validate_capability_diff_payload,
)
```

Encoding is deterministic UTF-8 JSON with sorted keys, two-space indentation,
and one trailing newline. Validation checks version compatibility before other
payload fields and exposes only safe field paths.

Schema export writes:

```text
capability-diff.schema.json
```

with Draft 2020-12 metadata.

## 7. Current boundary

P2-11 does not:

```text
read source content
execute Agent assets or tools
connect to MCP/network targets
read environment, memory, or credentials
produce risk score or Finding
change CI policy
integrate Capability Diff into the current CLI
call an LLM
```

The Phase 2 capability data path is now structurally complete, but risk rules,
combination-risk analysis, semantic/LLM evidence, CLI presentation, and Demo
integration remain later work.
