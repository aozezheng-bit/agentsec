# ADR-0070: Homi Capability Profile

- Status: Accepted for P2-HOMI-03
- Date: 2026-08-25
- Amendment: ADR-0079 Heartbeat Template / Active Task Classification
- Depends on: ADR-0068 Homi Workspace Adapter and ADR-0069 Homi File Precedence and Conflict Model
- Scope: static profile extraction; not runtime attestation

## Context

P2-HOMI-01 safely discovers the six standard Homi workspace files and P2-HOMI-02
resolves their static security boundaries. The next layer needs a stable input
for cross-file combination rules and report-only demonstrations. It must be
possible to describe what an Agent claims or documents without treating Markdown
as executable configuration or as proof that a tool, scheduler, or permission
is active.

## Decision

Introduce an adapter-local `HomiCapabilityProfile` built by
`HomiCapabilityProfileBuilder`.

The profile has five non-authorizing subprofiles:

```text
capabilities     canonical capability dimensions and bounded states
persona          SOUL.md behavioral signals
identity         IDENTITY.md metadata and avatar classification
user_privacy     USER.md storage/context boundary
tools            TOOLS.md environment-note classifications
heartbeat        HEARTBEAT.md task/disabled/unknown state
```

The six standard files remain the only input. The profile includes the resolved
P2-HOMI-02 policy and observations so later rules can explain cross-file
correlations without rereading or executing source files.

## Evidence and authority rules

1. Static lexical/template declarations use evidence confidence D.
2. Structural facts, such as an empty/comment-only HEARTBEAT.md, use confidence B.
3. Confidence A is reserved for a future independently verified runtime
   attestation and cannot be produced by this builder.
4. `runtime_verified` is always false.
5. `TOOLS.md` is a private environment-notes surface, never a Runtime Tool
   Registry. Tool signals may be `example_only`, `conditional`, or `unknown`,
   but never grant authority.
6. Persona and identity signals are descriptive, not permission-bearing.
7. `USER.md` is main-session-only in the static profile and never authorizes
   sharing in a group context.
8. Unknown/absent signals cannot use the `static_declaration` method; they use
   `runtime_unverified` unless a structural method explains the state.

## Consequences

Positive:

- later Homi combination rules receive a typed, deterministic input;
- source provenance and confidence are explicit and separate from severity;
- missing and incomplete coverage remain visible rather than silently becoming
  absent capabilities;
- example tool notes do not become false positive runtime permissions;
- no remote resource or external tool is contacted during profiling.

Trade-offs:

- lexical matching has limited semantic recall and may produce unknown results;
- the profile deliberately cannot prove actual runtime behavior;
- richer semantic analysis is deferred to later phases and must remain evidence,
  not authorization.

## Rejected alternatives

- **Execute the Homi files:** unsafe because scanned content is untrusted and
  could invoke external actions.
- **Treat every tool note as present runtime access:** would confuse local notes
  with a runtime registry and create unsupported findings.
- **Use an LLM as the profile authority:** would make a non-deterministic
  component responsible for security authorization; LLM analysis may be added as
  candidate evidence later.
- **Collapse unknown into absent:** would hide missing-file and coverage risk.

## Follow-up

P2-HOMI-04 will add deterministic cross-file combination rules over this profile.
It must preserve the same authority boundary and must not turn profile state into
CI blocking without the established gate qualification and policy controls.
