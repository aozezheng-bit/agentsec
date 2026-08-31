# ADR-0069: Homi File Precedence and Conflict Model

- Status: Accepted for P2-HOMI-02
- Date: 2026-08-25
- Amendment: ADR-0079 Heartbeat Template / Active Task Classification
- Depends on: ADR-0068 Homi Workspace Adapter
- Scope: static security resolution; not Homi runtime loader attestation

## Context

P2-HOMI-01 discovers six Homi files and preserves their semantic roles in an
adapter-local result. A scanner must now explain which file is authoritative
when declarations conflict, what context may receive each file, and which
static boundaries must never be treated as runtime authority.

Homi's actual runtime loading implementation has not been attested. Therefore
AgentSec must not claim that these ranks are the platform's literal file-load
order.

## Decision

Define a deterministic **security authority precedence** model:

```text
AGENTS.md       rank 100  workspace safety/startup/operation policy
HEARTBEAT.md   rank 90   scheduler definition only
TOOLS.md       rank 80   private environment binding notes
USER.md        rank 70   main-session user context only
SOUL.md        rank 60   persona only
IDENTITY.md    rank 50   public identity presentation only
```

The rank means which declaration wins in a security-relevant static conflict;
it does not grant runtime permission. All roles have
`runtime_authority=false`.

Define context visibility:

```text
AGENTS.md      all contexts
SOUL.md        all contexts (persona only)
IDENTITY.md    public identity surface
USER.md        main session only
TOOLS.md       private runtime binding only
HEARTBEAT.md   scheduler only
```

Define authority domains so a file cannot silently cross roles:

```text
AGENTS.md      safety, startup, memory, external actions, group chat, heartbeat
SOUL.md        persona
IDENTITY.md    identity presentation
USER.md        user context
TOOLS.md       environment binding
HEARTBEAT.md   heartbeat schedule
```

`AGENTS.md` may override lower-role declarations only for the domains it owns.
`SOUL.md` cannot weaken a safety rule. `TOOLS.md` cannot grant a tool.
`USER.md` cannot authorize sharing. `IDENTITY.md` cannot grant runtime
identity. `HEARTBEAT.md` cannot bypass `AGENTS.md` safety policy.

## Deterministic observations

The resolver emits value-minimized observations for:

```text
startup_read_policy_conflict
control_plane_self_modification
heartbeat_activation_path
tools_not_authority
user_profile_main_session_only
identity_not_runtime_authority
empty_heartbeat_disabled
```

A startup conflict between `AGENTS.md` and `SOUL.md` resolves to the workspace
policy for security-sensitive startup loading, but remains visible as a
conflict observation. Self-modification and Heartbeat activation are recorded
as boundary/latent observations rather than silently applied changes.

Missing files produce `partial` resolution; skipped files or incomplete scan
coverage also produce `partial`. A detected conflict produces `conflict`.

## Consequences

Positive:

- file precedence is explicit without pretending to be runtime attestation;
- user context and tool notes receive explicit visibility boundaries;
- conflicts are deterministic, source-located, and safe to report;
- later Homi Capability and Rule layers can consume a stable resolution result;
- the existing neutral Manifest and Codex Adapter contracts remain unchanged.

Deferred:

- Homi-specific Manifest roles and serialized schema version;
- semantic capability extraction from each file;
- actual Homi runtime loader verification;
- LLM semantic analysis and Safe Simulation.

## Authority boundary

Static Homi role policy never authorizes a tool, network request, SSH session,
Camera access, TTS output, memory write, external message, scheduler, OAuth
scope, or production identity. Runtime authority requires a separate reviewed
Runtime Tool Registry or attestation contract.
