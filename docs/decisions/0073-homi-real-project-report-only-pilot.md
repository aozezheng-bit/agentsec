# ADR-0073: Homi Real-project Report-only Pilot

- Status: Accepted for P2-HOMI-06
- Date: 2026-08-25
- Amendment: ADR-0079 Heartbeat Template / Active Task Classification
- Depends on: ADR-0072 Homi Safe Simulation
- Scope: explicit external workspace reporting; not runtime verification or enforcement

## Context

P2-HOMI-01 through P2-HOMI-05 provide safe static inspection, policy resolution,
capability profiling, cross-file rules, and dry-run simulation. A real project
needs a single controlled orchestration path so developers and security
reviewers can inspect a Homi workspace without manually composing these layers.

The target may be a customer or production-adjacent workspace. It must therefore
be treated as untrusted input, and the report must not leak absolute host paths,
user values, credentials, or tool configuration values.

## Decision

Introduce `DeterministicHomiReportOnlyPilot` and a versioned
`agentsec-homi-report-only-pilot` report.

The Pilot accepts an explicit `HomiPilotRequest` containing:

```text
pilot_id
project_name
owner
target_root
output_root
reviewer_ids
inspection limits
bounded simulation scenario selection
```

The runner performs only:

```text
HomiAdapter.inspect_workspace
HomiWorkspacePolicyResolver.resolve
HomiCapabilityProfileBuilder.build
DeterministicHomiCombinationRuleEngine.run
DeterministicHomiSafeSimulationEngine.simulate
```

It creates JSON/Text artifacts only under a separate controlled output root, and
refuses to overwrite existing artifacts.

## Security boundaries

1. The target root must be an existing non-symlink directory.
2. The output root must be outside the target tree; the target is never used as
   an artifact destination.
3. The Pilot never executes target files, Markdown, code blocks, hooks, skills,
   commands, MCP servers, schedulers, or tools.
4. No network, SSH, OAuth, Camera, TTS, or remote Avatar access is attempted.
5. Absolute target paths and raw source values are excluded from reports.
6. `acceptance_ready` is always false for this layer; human and runtime evidence
   are separate follow-up work.
7. `report_only=true`, `runtime_verified=false`, and `ci_blocked=false` are
   validated as output invariants.

## Status semantics

```text
complete  static six-file inspection and policy resolution have full coverage
partial   missing/skipped/invalid coverage remains visible
```

`complete` is not a statement that the Homi runtime is safe or that a static
Finding is exploitable. It only describes the static analysis run.

## Consequences

Positive:

- real workspaces can be analyzed through one deterministic API;
- the report contains enough provenance for developer and management review;
- output is safe to share internally without copying source secrets;
- P2-HOMI-05 simulation results remain distinct from P2-HOMI-04 Findings;
- no CLI or enforcement dependency is introduced before the report contract is
  reviewed.

Trade-offs:

- the owner must provide the target and controlled output paths explicitly;
- external runtime/human acceptance evidence is not generated automatically;
- the Pilot is one-workspace/one-snapshot in this task; repeated snapshots and
  drift comparison remain future work.

## Rejected alternatives

- **Discover a target path from Homi files:** unsafe because scanned content is
  untrusted and must not define trust boundaries.
- **Write reports into the scanned workspace:** can change the next scan and
  contaminate evidence; output must be separate.
- **Execute Homi to validate the report:** violates the non-execution boundary;
  runtime attestation needs a separate reviewed sandbox contract.
- **Use the Pilot as a CI gate:** report-only evidence must be qualified before
  any enforcement, and Homi runtime evidence is not present here.

## Follow-up

P2-HOMI-07 may package this API as CLI commands. Any CLI must preserve explicit
root separation, no-clobber behavior, value minimization, and report-only flags.
Repeated snapshots, PR/drift evidence, and human adjudication require a future
versioned pilot contract rather than implicit behavior.
