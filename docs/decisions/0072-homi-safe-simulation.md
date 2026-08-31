# ADR-0072: Homi Safe Simulation

- Status: Accepted for P2-HOMI-05
- Date: 2026-08-25
- Amendment: ADR-0079 Heartbeat Template / Active Task Classification
- Depends on: ADR-0071 Homi Cross-file Combination Rules
- Scope: deterministic dry-run planning; not runtime execution or attestation

## Context

P2-HOMI-04 can identify cross-file combinations, but a report needs a more
operational explanation of what a trigger path would look like. For example, a
reviewer should be able to see that a Heartbeat declaration and network access
form a *declared path* without actually running the scheduler or contacting the
network.

A real Homi Agent cannot be treated as a safe test fixture: its Markdown may
contain instructions, tools, credentials, external destinations, or destructive
actions. Therefore P2-HOMI-05 must simulate only the decision logic over the
already bounded Profile.

## Decision

Introduce `DeterministicHomiSafeSimulationEngine` and a versioned
`agentsec-homi-safe-simulation` output.

The engine has a fixed five-scenario catalog:

```text
HOMI-SIM-001  Heartbeat tick + external network read
HOMI-SIM-002  proactive persona + external tool use
HOMI-SIM-003  user-profile update + memory persist
HOMI-SIM-004  control-file update + control-file write
HOMI-SIM-005  Skill discovery + tool discovery
```

The engine accepts only a typed Profile and an optional bounded selection of
these scenarios. It does not accept arbitrary commands, URLs, payloads,
callbacks, executors, or tool clients.

Every output step is explicitly:

```text
mode=dry_run
executed=false
side_effects=false
runtime_verified=false
```

## Outcome semantics

A simulation outcome is a statement about static Profile interpretation:

- `declared_path`: the Profile describes the path;
- `not_declared`: a required capability is not declared;
- `blocked_example_only`: only a template tool example supports the path;
- `blocked_static_boundary`: a static boundary such as an empty Heartbeat blocks
  the path;
- `unknown_coverage`: missing/skipped/Unknown evidence prevents a conclusion.

None of these outcomes means that the action occurred or is exploitable.

## Security boundaries

The implementation must never:

- execute scanned source, code, Markdown, skills, hooks, or commands;
- invoke or connect to any tool, network, scheduler, OAuth identity, or MCP;
- write a file, memory record, message, or external state;
- fetch a remote Avatar;
- copy raw user data, credentials, IPs, URLs, or Secret values;
- convert simulation output into runtime authority, CI blocking, or a Hard Gate.

## Consequences

Positive:

- developers and management can see an actionable story without executing the
  Agent;
- template examples, static boundaries, and Unknown coverage are visible;
- simulation evidence remains separate from static Finding evidence;
- deterministic output is suitable for later report and CLI integration;
- the simulator can be used on hostile or incomplete input safely.

Trade-offs:

- the simulator cannot validate actual tool availability or scheduler behavior;
- declared paths may still be unreachable at runtime;
- the five scenarios are intentionally a small coverage slice and require the
  later real-project pilot before broader adoption.

## Rejected alternatives

- **Run the actual Homi Agent in-process:** violates the scanner's no-execution
  boundary and can cause external side effects.
- **Spawn a shell or container for commands found in Markdown:** would turn
  untrusted content into execution authority and is out of scope.
- **Call real tools in dry-run mode:** tool-specific dry-run semantics are not a
  trusted common contract and could still leak data or perform side effects.
- **Use an LLM to decide whether a path is executable:** non-deterministic and
  not suitable as a security authorization mechanism.

## Follow-up

P2-HOMI-06 may use these steps in a real-project report-only pilot. P2-HOMI-07
may expose the scenario selection and JSON output through CLI commands. Neither
follow-up may remove the explicit non-execution contract without a new ADR and a
separate runtime sandbox/attestation design.
