# ADR-0097: Manifest Capability Graph Builder

- Status: Accepted
- Date: 2026-08-31
- Task: P3-AG-02
- Scope: deterministic Manifest→graph mapping and the P3-AG-01 endpoint-matrix amendment

## Context

P3-AG-01 (ADR-0093) froze the `agentsec-capability-attack-graph` `0.1.0`
contract but no producer existed. The 2026-08-31 roadmap requires a
reproducible, testable builder that turns one validated `AgentManifest` into
the graph without opening project files or copying raw scanned text.

Wiring the builder against a real Codex Manifest exposed a gap in the frozen
endpoint matrix: the Manifest treats an MCP server as a tool family
(`ManifestToolKind.MCP_SERVER`) whose declarations can carry the `network`
side effect, so a `sends_to` edge from an `mcp_server` node is legitimate —
but ADR-0093 allowed only `agent` and `tool` sources for `sends_to` (and
`writes_to` / `installs`). The matrix needed a reviewed amendment instead of
an ad-hoc bypass.

## Decision

1. Add `ManifestCapabilityGraphBuilder.build(manifest)` in
   `agentsec.attack_graph.builder` producing a validated
   `CapabilityAttackGraph` with `paths=()` (matching stays in P3-AG-03).
2. Register the deterministic mapping:
   - node kinds from `ManifestToolKind` (`skill`, `mcp_server`, else `tool`),
     one AGENT node from `identity.agent_id`, child AGENT and MEMORY nodes
     from relation targets, SECRET / PRODUCTION_TARGET nodes from
     permissions, an `untrusted_input` node per OVERRIDE instruction
     candidate, and shared canonical SYNTHETIC `network` / `memory` sink
     nodes;
   - edges from relation kinds (`delegates_to`, `uses_*`, `reads_memory`,
     `writes_memory`; `persists_memory` maps to `writes_memory`;
     `other` is skipped), permission facts (`reads_secret`, `sends_to`,
     `writes_memory`/`reads_memory`), `sends_to` for tools with the
     `network` side effect, `provides_tool` for MCP server→tool pairs,
     and `overrides_instruction` per OVERRIDE candidate;
   - deterministic merges: nodes merge by (kind, provenance, refs / label)
     and edges merge by (kind, endpoints); both accumulate unioned Evidence
     and fail closed above the 16-source Evidence bound.
3. Evidence stays value-free: each resolved Manifest source reference maps
   to `(asset_path, content_sha256, start_line, end_line)` with a
   whole-file fallback of `(1, max(line_count, 1))`. The builder never
   opens project files, never sets node labels from untrusted text, and
   never emits excerpts.
4. Disabled tools (`availability=disabled`) emit no nodes and their
   `uses_*` edges are dropped; `deny` permissions emit nothing. Unresolved
   `uses_*` targets become MANIFEST_INFERRED nodes carrying the relation
   label; a self-delegation fails closed instead of looping.
5. Bind the graph to the Manifest through
   `canonical_manifest_sha256(manifest)`, byte-compatible with the P3-09
   `canonical_model_sha256` digest, and register
   `ATTACK_GRAPH_BUILDER_VERSION 0.1.0` in the interface provenance registry.
6. Amend the ADR-0093 endpoint matrix: `sends_to` accepts
   `agent|tool|skill|mcp_server` sources, and `writes_to` / `installs`
   accept `tool|skill|mcp_server` sources. The JSON Schema and version
   stay `0.1.0` because the matrix is a validator rule, not a serialized
   field; the amendment is recorded here and in ADR-0093's amendment note.

## Authority boundary

The builder emits only report-only evidence:

```text
report_only=true; blocks=false
finding_authority=false; rule_publication_authority=false
policy_authority=false; ci_authority=false; hard_gate_authority=false
release_authority=false; runtime_verified=false
paths=() (no path is claimed, so reachability stays not_proven)
```

## Consequences

### Positive

- Same Manifest byte-for-byte yields the same graph: content-addressed
  node/edge IDs plus deterministic sorting make builds reproducible and
  diffable.
- Real Codex projects now produce auditable graphs with doubling,
  delegation, memory, secret, network, and MCP exposure chains.
- The matrix amendment keeps the tool families uniform instead of
  silently dropping MCP-side network evidence.
- Unmapped dimensions fail visibly instead of inventing facts.

### Trade-offs

- `agent→production_target` still has no edge kind (ADR-0093 gap); such
  permissions render isolated PRODUCTION_TARGET nodes until a reviewed
  edge-kind extension.
- Runtime identities, DATA, and DEPENDENCY nodes are unmapped in this
  version (no Manifest-derived identity node kind exists yet).
- Canonical `network` / `memory` sink nodes carry no sources by design;
  evidence lives on the edges.

## Rejected alternatives

- Derive reachability directly in the builder: rejected; static
  declarations prove nothing at runtime and matching is P3-AG-03.
- Copy tool/permission names into node labels: rejected; labels are
  untrusted-text exposure and the refs already identify components.
- Build the graph from the inspection instead of the Manifest: rejected;
  the Manifest is the validated, versioned declaration inventory and the
  graph binds to its digest.
- Emit disabled tools and deny permissions as inert nodes: rejected;
  unreachable declarations would inflate and confuse the matcher.
