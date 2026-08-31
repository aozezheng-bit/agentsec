# ADR-0068: Homi Workspace Adapter

- Status: Accepted for P2-HOMI-01
- Date: 2026-08-25
- Amendment: ADR-0079 Heartbeat Template / Active Task Classification
- Scope: static discovery and classification only

## Context

Homi Agent workspaces use six conventional files with different semantics:
`AGENTS.md`, `SOUL.md`, `IDENTITY.md`, `USER.md`, `TOOLS.md`, and
`HEARTBEAT.md`. AgentSec already has a framework-neutral Adapter seam and a
safe Markdown collector/parser, but the neutral Manifest vocabulary does not
yet define Homi persona, identity, user-profile, tool-note, or heartbeat roles.

P2-HOMI-01 must add Homi discovery without silently treating a local note as a
runtime permission or changing Codex/Manifest semantics.

## Decision

Add `HomiAdapter` under `agentsec.frameworks`.

The Adapter:

- inspects only the six exact files at the explicitly selected project root;
- uses the existing `PathGuard`, bounded reads, strict UTF-8, SHA-256, and
  Markdown parser;
- never executes file content, follows external symlinks, connects to tools,
  reads credentials, or accesses the network;
- returns the existing neutral `FrameworkInspectionResult` through the
  `FrameworkAdapter` Protocol;
- additionally exposes `inspect_workspace()` with Homi-specific file role and
  state classification;
- classifies each expected file as `present`, `empty`, `example_only`,
  `missing`, or `skipped`;
- treats an empty/comment-only `HEARTBEAT.md` as disabled static configuration;
- marks the current documentation-style `TOOLS.md` template as
  `example_only` using a conservative marker check;
- keeps Homi semantic roles in adapter-local `HomiFileRole` until P2-HOMI-02
  defines precedence and Manifest vocabulary.

For compatibility with the current neutral Framework Adapter and Manifest
builder, inspected Homi Markdown assets use the neutral
`agent_instructions` role in `FrameworkAssetRecord`. The Homi-specific role is
preserved in `HomiWorkspaceInspection.files`. This is intentional and prevents
P2-HOMI-01 from pretending that persona or identity text is already an
instruction or authorization source.

## Consequences

Positive:

- Homi becomes a second Framework Adapter rather than a forked scanner;
- existing path safety, parsers, Manifest pipeline, reports, and tests can be
  reused;
- missing optional files are visible without inventing fake source assets;
- empty Heartbeat is distinguishable from an active schedule;
- example documentation is not treated as verified runtime configuration.

Deferred to P2-HOMI-02 and later:

- effective Homi file precedence and conflict resolution;
- Homi-specific Manifest roles and serialized schema changes;
- tool/runtime attestation;
- Homi deterministic risk rules;
- Safe Simulation and CLI commands;
- real-project Pilot.

## Security boundary

`TOOLS.md` does not grant a tool permission, `IDENTITY.md` does not grant an
identity authority, `USER.md` does not authorize data sharing, and
`HEARTBEAT.md` does not prove that a runtime scheduler is enabled. All such
claims remain static declarations or unknowns until a separately reviewed
runtime contract exists.
