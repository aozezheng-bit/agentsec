# ADR-0099: Attack Path Pattern Library and Static Matcher

- Status: Accepted
- Date: 2026-08-31
- Task: P3-AG-03
- Scope: finite static path pattern vocabulary and the deterministic matcher

## Context

P3-AG-01 (ADR-0093) froze the graph contract and P3-AG-02 (ADR-0097)
delivered the Manifest builder, but graphs carry `paths=()` and no path is
ever claimed. The roadmap requires at least five deterministic static
attack-path pattern families with explicit unverified boundaries, and a
matcher that produces them reproducibly from the declared graph before any
report work (P3-AG-04) can start.

The 2026-08-31 roadmap erratum (17.4) names the five required families plus
an optional sixth supply-chain family. The graph vocabulary fixed by
ADR-0093/0097 can express most of them, but two families ("External MCP →
production write", "tool → dependency install") depend on edge kinds
(`writes_to`, `installs`) that the P3-AG-02 builder does not yet emit from
Manifest data. Those patterns must still exist as reviewer-reviewed
vocabulary so the vocabulary is complete, while matching zero paths on
current builder output — an explicit, documented boundary rather than a
silent gap.

## Decision

1. Add `agentsec.attack_graph.patterns` with the strict
   `AttackPathPatternSpec` / `AttackPathStepSpec` contracts
   (`ATTACK_PATH_PATTERN_LIBRARY_VERSION 0.1.0`). A pattern is
   `pattern_id` + start node kinds + ordered steps (allowed next node kinds
   and edge kinds per hop) + optional precondition edge kinds that must
   exist as outgoing edges of the start node. All kind sets must be sorted,
   unique, and non-empty.
2. Ship the reviewed builtin library of seven patterns covering the
   roadmap's five families plus the optional sixth and one transport
   variant:
   - `secret-exfiltration` (agent + reads_secret precondition → tool
     family → network);
   - `injection-tool-execution` (untrusted_input → agent → tool family);
   - `memory-poisoning` (untrusted_input → agent → memory via
     `writes_memory`);
   - `delegation-escalation` (agent → child agent; escalation itself stays
     not_proven because sub-agent capabilities are outside the Manifest);
   - `mcp-external-egress` (agent → mcp_server → tool → network);
   - `mcp-production-write` (agent → mcp_server → tool → production via
     `writes_to`; vocabulary complete, no edges produced yet);
   - `tool-dependency-install` (agent → tool family → dependency via
     `installs`; same boundary note).
3. Add `AttackPathMatcher`: deterministic DFS over declared edges only,
   ordered by pattern ID, then start node order, then edge ID; matched
   paths are content-addressed `attack-path-sha256` values carrying the
   fixed `path_kind=static_declared_path`, `runtime_verified=false`,
   `reachability=not_proven`, `exploitability=not_proven` marks.
4. Fail-closed bounds: `per-pattern ≤ 64` matches
   (`ATTACK_PATH_MAX_MATCHES_PER_PATTERN`) and total matches ≤ the graph's
   256-path bound raise `AttackPathMatchError` instead of silently
   truncating. Custom pattern libraries must pass
   `validate_pattern_library` (tuple, spec-only entries, sorted unique
   pattern IDs) or construction fails.
5. `match_into_graph()` re-emits a fully re-validated
   `CapabilityAttackGraph` (same Manifest binding, nodes, and edges) with
   the matched paths attached, so no authority boolean can drift and every
   path is re-checked against the endpoint matrix and contiguity rules.
6. Register `ATTACK_PATH_PATTERN_LIBRARY_VERSION` in the interface
   provenance registry and export the matcher, specs, library, and errors
   through the public API.

## Authority boundary

```text
report_only=true; blocks=false
finding_authority=false; rule_publication_authority=false
policy_authority=false; ci_authority=false; hard_gate_authority=false
release_authority=false; runtime_verified=false
```

A matched path is a deterministic statement about declared static
relations. It is not a Finding, not an exploitability proof, and carries no
CI/Policy influence. The escalation and production-write reachability
remains `not_proven` by construction.

## Consequences

### Positive

- The five roadmap families are now machine-checkable on real graph
  output; the real project fixture yields delegation, injection,
  memory-poisoning, and exfiltration paths deterministically.
- Matching order and output are fully deterministic and content-addressed,
  so path sets diff cleanly between graph versions.
- Vocabulary for production-write and dependency-install exists now, so a
  future builder extension needs no matcher or schema change.
- Per-pattern and graph-level bounds prevent path explosion into an
  unreadable report or a silent truncation.

### Trade-offs

- Delegation-escalation is a one-hop relation exposure: static Manifests
  cannot see sub-agent capabilities, so "escalation" is not asserted.
- `mcp-production-write` and `tool-dependency-install` match zero paths on
  current builder output; they are vocabulary until ADR-reviewed builder
  extension emits `writes_to` / `installs` edges.
- Preconditions are start-node-bound only; graph-global preconditions were
  rejected as semantically weaker.

## Rejected alternatives

- Emit paths from the builder (P3-AG-02): rejected; the builder's job is a
  faithful declaration graph, matching is a separately reviewed step.
- Free-form pattern DSL or regex over node labels: rejected; patterns must
  be finite, reviewable, and deterministic, mirroring the P1-18 safe-rule
  philosophy.
- Truncate silently at bounds: rejected; unrepresentable results must fail
  visibly per the fail-closed invariant.
- Claim "escalation" from a delegation edge alone: rejected; sub-agent
  capability is outside the Manifest, so the escalation hop stays
  unproven.
