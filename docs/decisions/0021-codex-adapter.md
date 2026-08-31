# ADR-0021: Explicit-Root, Non-Executing Codex Adapter

- Status: Accepted
- Date: 2026-08-20
- Task: P2-04

## Context

P2-03 defines a neutral `FrameworkAdapter.inspect()` seam, but no production
Adapter discovers real control assets. P2-01 and P2-02 already provide safe
Markdown, TOML, `.rules`, and MCP Parsers. P2-04 must connect these modules to
Codex locations without importing scanned code, loading Skills, executing Rules,
starting MCP servers, reading environment values, or leaking absolute host
paths into framework output.

Codex instruction and Skill discovery depends on the current working directory.
The P2-03 request originally exposed only the project root, optional user home,
and limits, which is not enough to reproduce a root-to-current-directory asset
chain. User Codex configuration also needs an explicit, testable alternative to
implicitly reading `CODEX_HOME` or `Path.home()`.

Official references reviewed for the decision:

```text
https://learn.chatgpt.com/codex/agent-configuration/agents-md
https://developers.openai.com/codex/skills
https://developers.openai.com/codex/rules
https://developers.openai.com/codex/config-reference
https://developers.openai.com/codex/mcp
```

## Decision

### Request and roots

1. Add optional `working_directory` to `FrameworkInspectionRequest`.
2. Default `working_directory` to `project_root` when omitted.
3. Require the selected working directory to be a guarded directory wholly
   inside the canonical project root. Reject direct outside paths and symbolic
   link chains that leave the root, even if a later link returns inside.
4. Add `CodexAdapter(codex_home=...)` as an optional explicit source root.
5. When no explicit Codex home is provided, use `<user_home>/.codex` only when
   `user_home` was explicitly supplied.
6. Do not read `CODEX_HOME`, call `Path.home()`, or infer a system user root.
7. Treat an explicit `codex_home` as its own operator-selected boundary. Treat
   default `<user_home>/.codex` as a contained child of the user-home boundary.

### Discovery

8. Inspect each project-chain directory from project root through working
   directory for:

```text
AGENTS.md
AGENTS.override.md
.codex/config.toml
.codex/rules/*.rules
.agents/skills/*/SKILL.md
```

9. Inspect user Codex home for `AGENTS.md`, `AGENTS.override.md`, `config.toml`,
   and `rules/*.rules`.
10. Inspect `<user_home>/.agents/skills/*/SKILL.md` for user Skills.
11. Preserve both base and Override instruction files when both exist. P2-04 is
    a security-inspection layer; P2-06/P2-07 own final effective selection.
12. Discover project `.codex` configuration and Rules as static assets without
    claiming they are active or trusted at runtime.
13. Defer system, admin-managed, bundled, profile-specific, and plugin
    installation scopes until the inspection request can represent their trust
    roots and activation context.

### Mapping and precedence

14. Map Codex files to the P2-03 neutral roles and reviewed Parser formats.
15. Parse every `config.toml` as a TOML `StructuredDocument` and run the static
    MCP Parser over it.
16. Assign `mcp_config` only when one or more MCP server declarations are
    present and valid; otherwise retain only `framework_config`.
17. Record larger-is-higher precedence hints:

```text
User AGENTS.md                     10
User AGENTS.override.md            20
User config / Rules / Skills       50
Project AGENTS.md                 100 + depth * 10
Project AGENTS.override.md        105 + depth * 10
Project config / Rules / Skills   200 + depth * 10
```

18. Do not merge content, resolve inheritance, or authorize a capability from
    these ranks.

### Filesystem and Coverage

19. Reuse `PathGuard` independently for each explicit source root.
20. Accept internal symbolic links only when every hop remains inside that
    source root. Reject external links and cycles.
21. Revalidate type and size before reading and read at most
    `max_file_size_bytes + 1` bytes.
22. Decode only strict UTF-8 and parse only through the reviewed inert Parsers.
23. Apply one logical depth limit from each explicit root and one global
    selected-asset limit per inspection.
24. At the first asset-count overflow, count one deterministic skipped sentinel,
    emit `asset_limit_exceeded`, and stop discovery.
25. Record container-level Coverage Issues even when hidden asset counts cannot
    be known.
26. Map malformed structured, Rules, or MCP input to `parse_error` without
    copying source or dependency exception text.
27. Return only portable root IDs and relative POSIX paths; do not retain
    absolute host paths in framework result models.

### Non-execution boundary

28. Never execute instructions, Skills, Rules, commands, Hooks, plugins, or
    project code.
29. Never connect to MCP, dereference URLs, inspect network services, or read
    environment-variable values.
30. Never call an LLM in Phase 2 Adapter discovery.
31. Keep `FrameworkInspectionResult` outside the Phase 1 `RuleContext` and
    current Assessment/Baseline/Diff serializers.

## Version impact

P2-04 adds a concrete Python Adapter and one optional Python request field. It
does not serialize framework output into current production formats and does not
change Rule or Risk semantics.

```text
PACKAGE_VERSION             unchanged at 0.1.0
CONFIG_SCHEMA_VERSION       unchanged
DOMAIN_SCHEMA_VERSION       unchanged
BASELINE_SCHEMA_VERSION     unchanged
DIFF_OUTPUT_VERSION         unchanged
ASSESSMENT_OUTPUT_VERSION   unchanged
RULE_PACK_VERSION           unchanged at 0.3.0
RISK_MODEL_VERSION          unchanged
```

P2-05 performed the required Version Impact Review in ADR-0022 and introduced an
independent Agent Manifest Schema version. The Manifest still does not enter
Assessment, Baseline, Diff, Rule, or Risk processing.

## Consequences

### Positive

- Codex Agent, Skill, Rules, configuration, and MCP assets now pass through one
  production Framework Adapter.
- Project and user discovery is reproducible because all roots and the working
  directory are explicit.
- Security review retains both base and Override sources for later drift and
  precedence analysis.
- Path containment, bounded reads, UTF-8, resource limits, parser coherence, and
  Coverage share one tested flow.
- Declared commands, URLs, and environment names remain inert facts.
- Portable output avoids embedding developer home and workspace paths.

### Negative

- P2-04 is not yet wired into `agentsec scan`; callers use the Python API.
- Container-level gaps cannot always identify how many assets were hidden.
- Effective Codex behavior is not resolved, so ranks remain hints rather than
  final authorization facts.
- System, admin, bundled, profile, and installed-plugin scopes remain unknown.
- Static `StructuredDocument` values still require redaction review before any
  future serialization or logging boundary.
