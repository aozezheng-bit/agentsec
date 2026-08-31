# ADR-0078: External Homi PR Snapshot and Drift Evidence Contract

- Status: Accepted
- Date: 2026-08-26
- Amendment: ADR-0079 Heartbeat Template / Active Task Classification
- Task: P2-EXIT-06-03
- Depends on: ADR-0073 and ADR-0077

## Context

P2-EXIT-06-02 collected one user-supplied Homi baseline. The external Pilot exit
contract also requires reviewed PR/change states and evidence that capability
increases, hardening changes, policy changes, and incomplete Coverage remain
visible without executing the target.

Storing extracted `AGENTS.md` snapshots inside the AgentSec repository would
also place untrusted nested instruction files in the development tree. A durable
snapshot format must therefore preserve source bytes without expanding those
files into the active source hierarchy.

## Decision

1. Store every PR snapshot as a deterministic, flat ZIP file.
2. Deploy actual Homi filenames only into an explicit repository-external target
   root for scanning.
3. Compare each snapshot to the SHA-256-pinned P2-EXIT-06-02 baseline report.
4. Emit `agentsec-homi-capability-drift-evidence` `0.1.0` per scenario.
5. Emit `agentsec-external-homi-pr-change-evidence` `0.1.0` as the aggregate.
6. Require each scenario's generated drift to equal a controlled engineering
   expectation contract exactly.
7. Label this review mode `deterministic_scenario_contract`; never represent it
   as independent human TP/FP/FN review.
8. Keep every report `report_only=true`, `runtime_verified=false`,
   `ci_blocked=false`, and `acceptance_ready=false`.

Drift includes:

```text
file state/hash changes
capability state transitions
persona signal transitions
policy observation delta
Finding added/removed/changed-evidence delta
Safe Simulation outcome transitions
baseline/snapshot/report hashes
```

A Finding whose Rule ID remains present but whose evidence/finding ID changes is
reported as `changed_findings`, not silently treated as unchanged.

## Review semantics

A scenario contract pass means deterministic implementation output matches the
predefined engineering expectation. It does not mean:

```text
independent human agreement
runtime exploitability
production reachability
policy acceptance
waiver approval
CI blocking eligibility
Phase 3 entry approval
```

A scenario may pass its contract while being marked `calibration_required`.
PR-03 used that state in the preserved pre-calibration evidence. ADR-0079
corrected the Heartbeat classifier; the canonical PR-03 evidence now produces
the expected capability/Finding/simulation delta and is `contract_pass`.

## Security constraints

- No snapshot content is executed.
- ZIPs must be flat, relative, UTF-8, non-symlink content.
- Target and evidence roots must be explicit, new, and non-overlapping.
- Target hashes are compared before and after scanning.
- Reports must not contain absolute target paths or known source binding values.
- Snapshot generation uses fixed ZIP metadata for deterministic hashes.
- Scenario IDs map to fixed controlled transformation functions; the plan cannot
  inject executable transformations.
- Any expected/actual mismatch fails the entire collection.

## Consequences

Positive:

- ten PR states are replayable without placing untrusted AGENTS.md files in the
  source tree;
- risk additions, removals, evidence changes, policy resolution, and Coverage
  degradation are visible;
- the Heartbeat template saturation issue is preserved as calibration evidence;
- API and CLI output can be compared byte-for-byte;
- later independent Reviewers can label the exact frozen snapshots.

Trade-offs:

- engineering contract review is not final human adjudication;
- Homi-specific drift evidence is not the final generic
  `agentsec-pilot-report` acceptance artifact;
- nine additional scan states, Waiver drill, human labels, and performance
  evidence remain before P2-EXIT-06 can be accepted.

## Rejected alternatives

- **Store extracted snapshot directories in the repository:** would introduce
  nested untrusted AGENTS.md instruction scope.
- **Use only text diff:** would miss capability state, Finding evidence, policy,
  and simulation changes.
- **Count unchanged Rule IDs as no drift:** evidence can materially change while
  the Rule ID remains stable.
- **Call engineering contracts human review:** would create false evidence.
- **Use the aggregate to satisfy P2-EXIT-08A:** the aggregate is intentionally not
  an acceptance-ready `agentsec-pilot-report`.
