# ADR-0024: Source-Level Configuration Precedence Resolver

- Status: Accepted
- Date: 2026-08-20
- Task: P2-07

## Context

P2-04 discovers Codex `config.toml`, `.rules`, and static MCP configuration
assets. P2-05 turns those assets into a source-backed Agent Manifest, and P2-06
resolves instruction inheritance separately. The project now needs an
explainable configuration precedence stage without confusing source order with
field-level effective values.

A configuration file can contain many unrelated fields. Replacing an entire
lower-precedence file with a higher-precedence file would silently discard
lower-level settings that were not overridden. Conversely, copying raw parsed
TOML, Rules, or MCP values into a new Manifest would create a secret and
untrusted-data boundary. P2-07 therefore must resolve source application order
only and leave field-level extraction/merge to later capability tasks.

## Decision

### Configuration candidates

1. Add a required `configuration` profile to `AgentManifest`.
2. Represent each source once with a sorted tuple of configuration kinds:

```text
framework_config
prefix_rules
mcp_config
```

3. Map source roles to configuration kinds:

```text
framework_config → framework_config
prefix_rules     → prefix_rules
mcp_config       → mcp_config
```

4. A TOML MCP source may carry both `framework_config` and `mcp_config` kinds
   without duplicating its source identity.
5. Retain the Adapter `precedence_rank` and a portable chain key for every
   candidate.

### Precedence order

6. Apply configuration candidates in this source-level order:

```text
User scope before Project scope
Within the same scope: lower precedence rank before higher rank
Ties: root_id, portable path, chain key, configuration kinds
```

7. The Resolver selects all visible source candidates in application order. It
   does not claim that one complete file replaces another complete file.
8. Preserve both:

```text
effective_sources → canonical locator-sorted set
effective_order   → source application/precedence order
```

9. Record one `resolution_trace` step for every candidate with action, reason,
   kinds, rank, and chain key.
10. Fail closed on duplicate candidate source identities.

### Status

11. With candidates and complete Coverage, set `resolved`.
12. With candidates and incomplete Coverage, set `partial` while retaining the
    visible safe source order.
13. With no candidates, preserve `unknown`; no discovered configuration is not a
    global proof that no configuration exists.
14. Reserve `conflict` for malformed/ambiguous candidate input; it emits no
    effective source selection.

### Field-level boundary

15. P2-07 does not merge or interpret individual TOML, Rules, or MCP fields.
16. It does not decide whether a Rules file is trusted/active, whether an MCP
    server is reachable, or whether an environment variable exists.
17. P2-08/P2-09 and later capability stages consume the ordered source model for
    field-level extraction and risk analysis.

### Version impact

18. Increment:

```text
AGENT_MANIFEST_SCHEMA_VERSION: 0.2.0 → 0.3.0
```

19. Keep Package, Domain, Baseline, Diff, Assessment, Rule Pack, and Risk Model
    versions unchanged.

### Security boundary

20. Never read raw configuration values in the Resolver.
21. Never execute Commands, Rules, Skills, Hooks, Plugins, or MCP servers.
22. Never read environment values, resolve URLs, access network, import scanned
    code, or call an LLM.
23. Do not turn configuration source precedence into an authorization or CI
    blocking decision.

## Consequences

### Positive

- Configuration source precedence is explainable without falsely replacing whole
  configuration documents.
- Framework, Rules, and MCP roles remain source-provenance aware.
- Configuration resolution is separate from instruction inheritance.
- Incomplete Coverage remains visible as `partial`.
- Raw values remain outside the Manifest source-level resolver.

### Negative

- P2-07 does not yet produce field-level effective configuration values.
- Consumers must use `effective_order` for precedence semantics rather than
  treating `effective_sources` as an ordered list.
- Unsupported or undiscovered configuration scopes remain `unknown`.
