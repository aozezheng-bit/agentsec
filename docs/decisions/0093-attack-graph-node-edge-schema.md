# ADR-0093: Capability Attack Graph Node and Edge Schema

- Status: Accepted
- Date: 2026-08-31
- Task: P3-AG-01
- Scope: strict value-free Attack Graph node, edge, graph, and static path schemas

## Context

The original Phase 3 plan reserved an Attack Graph track (P3-AG), but the
P3-07/P3-08/P3-09 IDs were consumed by Semantic LLM Shadow work. The
2026-08-31 roadmap erratum renumbered the Attack Graph track as P3-AG-01..07
and confirmed that the existing Manifest `tools`, `permissions`,
`relationships`, Delegation, and Memory material input a graph but do not
constitute one.

Before a Manifest-to-graph builder (P3-AG-02) or a path matcher (P3-AG-03)
can be implemented, the repository needs a strict, reviewable data contract
that fixes node and edge semantics, Evidence binding, determinism, and the
authority boundary. Without it, later tasks could invent graph semantics
incrementally, drift between builder and matcher, or let a graph artifact be
mistaken for runtime reachability evidence.

## Decision

Add the frozen `agentsec-capability-attack-graph` `0.1.0` contract in
`agentsec.attack_graph`:

1. Eleven finite node kinds express the P3-AG path ingredients:
   `untrusted_input`, `tool`, `skill`, `mcp_server`, `agent`, `secret`,
   `data`, `memory`, `network`, `production_target`, `dependency`.
2. Fourteen finite directed edge kinds (`uses_tool`, `uses_skill`, `uses_mcp`,
   `reads_input`, `overrides_instruction`, `reads_secret`, `reads_data`,
   `writes_memory`, `reads_memory`, `writes_to`, `sends_to`, `delegates_to`,
   `installs`, `provides_tool`) with a fixed endpoint-kind matrix validated
   at graph construction.

   Amendment (2026-08-31, ADR-0097 / P3-AG-02): Manifest tool families are
   tool-equivalent sources, so `sends_to` accepts `agent|tool|skill|
   mcp_server` sources and `writes_to` / `installs` accept `tool|skill|
   mcp_server` sources. The matrix is a validator rule, not a serialized
   field, so the Schema stays `0.1.0`.
3. Node, edge, and path identities are attacker-irrelevant content addresses
   (`attack-node-sha256:`, `attack-edge-sha256:`, `attack-path-sha256:`)
   recomputed from canonical JSON during validation; tampered or duplicated
   identifiers fail closed.
4. Evidence is value-free: nodes and edges carry sorted Manifest component
   references plus `(asset_path, asset_sha256, start_line, end_line)` source
   locators only. No raw text, excerpt, URL, credential, or label content
   that could carry an unredacted value; labels are bounded and reject
   control characters.
5. Every path is `path_kind=static_declared_path` with fixed
   `runtime_verified=false`, `reachability=not_proven`, and
   `exploitability=not_proven`; node chains must be contiguous over the
   graph's edges without repeating nodes.
6. The graph is bound to its Manifest provenance
   (`manifest_schema_version`, `manifest_sha256`), sorted deterministically,
   size-bounded (2048 nodes, 8192 edges, 256 paths, 32-hop paths), and fixed
   `report_only=true` with all authority booleans false.
7. One JSON Schema is exported and owned by the versioned
   `ATTACK_GRAPH_SCHEMA_VERSION` product record; the generic reserved
   `ATTACK_GRAPH_VERSION` placeholder remains reserved.

## Authority boundary

```text
report_only=true
blocks=false
finding_authority=false
rule_publication_authority=false
policy_authority=false
ci_authority=false
hard_gate_authority=false
release_authority=false
runtime_verified=false
```

A graph describes statically declared relations. It never proves runtime
reachability, exploitability, or mitigations, and never authorizes any
decision.

## Consequences

### Positive

- Builder (P3-AG-02) and matcher (P3-AG-03) share one frozen vocabulary.
- Content-addressed IDs make graphs reproducible, diffable, and tamper-evident.
- The endpoint matrix rejects semantically impossible edges at construction.
- Value-free Evidence keeps scanned text out of graph artifacts.
- Authority booleans are structurally unfalsifiable by callers.

### Trade-offs

- New node or edge kinds, edge-kind semantic changes, or ID formats require a
  schema version bump and a new ADR (this is deliberate).
- Five-to-six first-version path patterns cannot add new node families later
  without review; the initial set is intentionally conservative.
- Builder, matcher, report, demo, and calibration work stays in P3-AG-02..07.
- The endpoint matrix encodes current Manifest semantics and will need
  reviewed extension for future frameworks.

## Rejected alternatives

- Reuse Manifest models directly as nodes: rejected because the graph must
  bind Evidence value-free and stay independent of Manifest schema evolution.
- Free-form node kinds or extensible edge types: rejected because matcher
  semantics must stay deterministic and reviewable; "extensible" invites
  unreviewed vocabulary growth.
- Claim edge-level runtime reachability states: rejected; static declarations
  prove nothing at runtime, so only the fixed `not_proven` marks are allowed.
- Let the LLM Semantic Track author graph nodes: rejected; the Administra-
  tive/stated graph is derived from the deterministic Manifest and trusted
  parser records, not from model output.
- Implement the builder in this task: rejected; P3-AG-01 is the schema
  contract only, per the one-task-at-a-time discipline.
