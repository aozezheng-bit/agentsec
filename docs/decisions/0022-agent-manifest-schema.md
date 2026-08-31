# ADR-0022: Independent Agent Manifest 0.1.0 Declaration Schema

- Status: Accepted
- Date: 2026-08-20
- Task: P2-05

## Context

P2-03 defines neutral Framework inspection records and P2-04 produces real Codex
Agent, Skill, Rules, configuration, and MCP source records. The next phase needs
a stable framework-neutral structure before implementing instruction resolution,
configuration precedence, tool association, permission extraction, runtime
identity analysis, delegation, memory, and explicit Unknown generation.

Passing `ParsedMarkdown`, `StructuredDocument`, `ParsedRulesDocument`, or
`ParsedMcpConfiguration` directly to every downstream stage would leak parser
and framework details across the codebase. Serializing those raw parser objects
would also retain attacker-controlled configuration values, including values
that future reports may need to redact.

The existing Domain Schema 0.3.0 describes Phase 1 Assessment objects. Treating
the Agent Manifest as another Domain Schema field would couple a new Phase 2
artifact to frozen Assessment, Baseline, and Diff interfaces.

## Decision

### Artifact meaning

1. Define an Agent Manifest as a versioned, deterministic, source-backed
   declaration inventory for one Agent subject.
2. The Manifest is not an Effective Capability Profile, runtime attestation,
   risk result, authorization decision, or claim that a capability exists.
3. Give the Manifest an independent interface version:

```text
AGENT_MANIFEST_SCHEMA_VERSION = 0.1.0
```

4. Do not increment Domain Schema, Assessment Output, Baseline Schema, Diff
   Output, Rule Pack, or Risk Model versions.

### Top-level structure

5. Require these dimensions in every Manifest:

```text
metadata
identity
sources
instructions
tools
permissions
controls
runtime_identities
relationships
unknowns
coverage
```

6. Keep subject identity separate from runtime identity. Subject identity names
   the logical Agent represented by the Manifest; runtime identities describe
   credential-free principals and authentication methods used by the Agent or
   its tools.
7. Use a local stable `agent_id` rather than an absolute repository or user-home
   path. The default builder identity is `<framework_id>:<subject_root_id>` when
   that value is safe; callers may provide a trusted stable ID.

### Source provenance

8. Represent every source using a portable scope, root ID, relative POSIX path,
   format, sorted roles, SHA-256, byte count, line count, and precedence rank.
9. Represent a source reference as a portable locator plus optional normalized
   field path and optional coherent line range.
10. Require every reference to resolve to a top-level source and require source
    line ranges to fit that source.
11. Do not copy parsed Markdown text, TOML/JSON/YAML scalar values, `.rules`
    literals, MCP commands, arguments, URLs, headers, environment values, or
    parser exception text into the P2-05 Manifest.
12. Preserve only source metadata and future normalized facts. Reporters remain
    responsible for redacting any normalized untrusted names or targets added by
    later tasks.

### Resolution status

13. Give every major dimension an explicit resolution status:

```text
unresolved
partial
resolved
unknown
not_applicable
conflict
```

14. Define `unresolved` as “relevant declaration sources exist but the owning
    Resolver/Extractor has not selected or normalized the final facts.”
15. Define `unknown` as “no sufficient deterministic evidence is currently
    available.” It is not equivalent to disabled, denied, absent, or safe.
16. Require unresolved non-instruction profiles to retain declaration sources
    and no resolved items.
17. Require unresolved instructions to retain base/Override candidates and no
    effective source.
18. Reserve explicit `ManifestUnknown` entries for P2-11 while making the field
    part of Schema 0.1.0 now. Earlier tasks communicate incomplete resolution
    through dimension statuses rather than silently emitting empty resolved
    profiles.

### Capability vocabulary

19. Define typed future item models for:

```text
Tool and availability
Tool side effects
Permission action/effect/resource/scope
Control kind/state
Runtime principal/authentication/environment
Agent/Skill/MCP/tool/memory relationships
Unknown dimension/reason
```

20. Require every normalized tool, permission, control, runtime identity, and
    relationship to retain at least one source reference.
21. Require deterministic ordering and unique stable IDs for all item tuples.
22. Require parent-tool references to resolve within the same tool inventory and
    relationship source Agent IDs to match the Manifest subject.

### Builder boundary

23. Add one `AgentManifestBuilder.build(inspection, ...)` interface that consumes
    a validated `FrameworkInspectionResult`.
24. P2-05 Builder behavior is intentionally source-only:

```text
copy safe source metadata
copy Framework Coverage
create base/Override instruction candidates
identify declaration sources for future dimensions
mark dimensions unresolved or unknown
```

25. Do not inspect parsed values in the P2-05 Builder and do not implement
    P2-06～P2-11 extraction early.
26. Map Framework Coverage codes into the independent Manifest coverage model
    without converting Coverage gaps into Findings, permissions, or risk.

### Serialization and validation

27. Use strict immutable Pydantic models with unknown fields forbidden.
28. Export deterministic Draft 2020-12 JSON Schema with
    `x-agentsec-agent-manifest-schema-version`.
29. Encode JSON with sorted keys, two-space indentation, UTF-8 Unicode, and one
    trailing newline.
30. Validate version compatibility before interpreting the remaining payload.
31. Safe validation errors expose only stable codes and field paths, never
    rejected values.

### Security boundary

32. Manifest construction performs no filesystem reads beyond those already
    completed by the Framework Adapter.
33. It performs no shell, command, Skill, Rules, Hook, plugin, MCP, network,
    environment, model, or LLM operation.
34. It does not enter Phase 1 RuleContext or current Assessment/Baseline/Diff
    output in P2-05.

## Version impact at P2-05

```text
PACKAGE_VERSION                 unchanged at 0.1.0
CONFIG_SCHEMA_VERSION           unchanged
DOMAIN_SCHEMA_VERSION           unchanged at 0.3.0
AGENT_MANIFEST_SCHEMA_VERSION   new at 0.1.0
BASELINE_SCHEMA_VERSION         unchanged
DIFF_OUTPUT_VERSION             unchanged
ASSESSMENT_OUTPUT_VERSION       unchanged
RULE_PACK_VERSION               unchanged at 0.3.0
RISK_MODEL_VERSION              unchanged at 0.4.0
```

The existing `dist/` and frozen Phase 1 Schemas remain unchanged. A future task
that embeds a Manifest in Assessment, Baseline, Diff, policy, or risk output must
perform another Version Impact Review.

## Consequences

### Positive

- Downstream Resolver and capability tasks share one framework-neutral
  vocabulary.
- Empty fields cannot silently imply absence because each dimension has an
  explicit resolution state.
- Raw parser documents and secret-bearing structured values stay outside the
  serialized Manifest.
- Every future normalized fact has a source-provenance contract.
- Manifest compatibility evolves independently from frozen Phase 1 formats.
- The source-only Builder gives P2-06～P2-11 a deterministic starting point.

### Negative

- Schema 0.1.0 is intentionally broad before all extractors exist, so many
  profiles initially remain `unresolved` or `unknown`.
- Tool, permission, control, identity, relationship, and Unknown item semantics
  must remain compatible or increment the Manifest Schema version.
- A local default Agent ID is not a globally unique repository identity; callers
  that aggregate multiple projects should provide a trusted stable Agent ID.
- The committed Phase 1 `schemas/` release directory does not contain the new
  post-release Manifest Schema until a separate release task freezes it.
