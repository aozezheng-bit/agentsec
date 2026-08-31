# ADR-0079: Homi Heartbeat Template / Active Task Classification

- Status: Accepted
- Date: 2026-08-26
- Task: P2-EXIT-06-03A
- Amends: ADR-0068, ADR-0069, ADR-0070, ADR-0072, ADR-0073, ADR-0078

## Context

The user-supplied Homi baseline contains a documentation-style `HEARTBEAT.md`:
a fenced example says to keep the file empty and add tasks later, followed by a
Related-documentation link. It contains no concrete scheduled action.

The P2-HOMI-01 Adapter classified every non-empty, non-comment Heartbeat as
`present`. As a result, the baseline emitted `HOMI-COMB-002` and a declared
Heartbeat simulation path. PR-03 then replaced the template with concrete email,
calendar, and weather tasks but produced no semantic drift because both states
were already `present`.

This is a deterministic false-positive/detection-saturation issue. Lowering the
Finding manually would hide the parser defect and corrupt calibration evidence.

## Decision

Introduce a four-way effective Heartbeat classification:

```text
empty/comment-only   HomiFileState.EMPTY       → capability absent
example/documentation HomiFileState.EXAMPLE_ONLY → capability example_only
concrete task content HomiFileState.PRESENT     → capability present
missing/skipped       MISSING/SKIPPED            → capability unknown
```

A Heartbeat is `example_only` only when:

1. at least two reviewed template markers are present;
2. fenced example content is treated as documentation, not an active task;
3. headings, comments, separators, and link-only Related entries are ignored;
4. no actionable line remains outside the documentation scaffolding.

If a concrete task is appended outside the template, the file is `present`.

## Profile and policy behavior

For `example_only` Heartbeat:

```text
heartbeat_schedule            example_only
Evidence Confidence           D
Evidence Method               static_template_classification
tasks_present                 false
api_calls_enabled_by_file     false
runtime_verified              false
```

If AGENTS.md allows editing the Heartbeat, the existing
`heartbeat_activation_path` observation is retained because a disabled template
can be activated later. If no edit path exists, the new
`heartbeat_template_disabled` authority-boundary observation is emitted.

## Finding and simulation behavior

`HOMI-COMB-002` still requires:

```text
heartbeat.state = present
tasks_present = true
active external network/message/MCP declaration
```

The Rule condition and Rule Pack remain `0.1.0`; only the upstream static
classification is corrected.

Safe Simulation now maps Heartbeat template content to:

```text
HOMI-SIM-001 = blocked_example_only
```

Concrete PR-03 tasks map to:

```text
heartbeat_schedule   example_only → present
HOMI-COMB-002        added
HOMI-SIM-001         blocked_example_only → declared_path
```

## Version decisions

```text
Homi Adapter version                 0.1.0 → 0.2.0
Homi Profile model version           new 0.2.0
Homi Pilot report format             0.1.0 → 0.2.0
Homi Safe Simulation model version   0.1.0 → 0.2.0
Homi Combination Rule Pack           remains 0.1.0
```

The Pilot report `0.2.0` adds explicit `adapter_version` and
`profile_model_version` fields. This prevents regenerated evidence from being
confused with pre-calibration output.

## Evidence migration

Pre-calibration baseline and PR evidence is preserved under:

```text
pilots/external-homi-demo/review-history/pre-heartbeat-calibration-20260826/
```

Canonical baseline and all ten PR/Drift artifacts are regenerated. Expected
contracts are updated only for the deterministic consequences of the classifier
change. PR-03 changes from `calibration_required` to `contract_pass`.

## Security constraints

- Heartbeat Markdown remains untrusted and is never executed.
- No scheduler, network, email, calendar, weather, Tool, or callback is invoked.
- Fenced code is parsed only as inert documentation.
- Example-only never grants runtime authority.
- Unknown is not converted to absent.
- Static Confidence remains D; no runtime Confidence A is introduced.
- Findings remain report-only and cannot block CI through this Homi layer.

## Consequences

Positive:

- removes the demonstrated baseline false positive;
- makes real Heartbeat activation visible as capability/Finding/simulation drift;
- preserves template activation-path governance evidence;
- adds explicit Adapter/Profile provenance to Homi Pilot reports;
- keeps historical evidence auditable.

Trade-offs:

- Homi Pilot report consumers must accept format `0.2.0`;
- canonical evidence hashes change;
- template detection remains deterministic and intentionally conservative;
- independent human TP/FP/FN review is still required.

## Rejected alternatives

- **Suppress HOMI-COMB-002 only for this archive:** fixture-specific exception,
  not a classifier fix.
- **Treat all fenced content as inactive:** a real task could be deliberately
  placed in a fence; template markers and outside-task checks are also required.
- **Use an LLM to decide template intent:** non-deterministic evidence cannot own
  the authorization path.
- **Keep old evidence canonical:** would preserve a known false positive as the
  current product demonstration.
