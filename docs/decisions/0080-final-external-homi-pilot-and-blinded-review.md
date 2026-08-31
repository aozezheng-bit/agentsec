# ADR-0080: Final External Homi Pilot and Blinded Review Workflow

- Status: Accepted
- Date: 2026-08-26
- Tasks: P2-EXIT-06-04, P2-EXIT-06-05

## Context

P2-EXIT-06-02 and P2-EXIT-06-03 produced one real Homi baseline and ten
engineering-reviewed PR/change snapshots. The formal external Pilot contract
still required 20 total states, all three deterministic drills, independent
human labels, a final replay, and a Phase 3 Entry Readiness decision.

Engineering expectations are useful for deterministic regression, but they are
not independent TP/FP/FN evidence. Copying scanner observations into a human
label file would create circular evidence and falsely satisfy the release gate.

## Decision

Use one AgentSec-controlled 20-state Pilot with:

```text
10 baseline states
10 pull-request states
risky_change drill
incomplete_coverage drill
waiver_lifecycle drill
one protected organization Policy shared by all states
one SHA-256 Policy pin
```

Every state is an inert six-file Homi ZIP derived from the user-supplied export.
Only the controlled `AGENTS.md` state varies; the malformed drill uses invalid
UTF-8 to exercise visible incomplete Coverage. Runtime deployment uses separate,
new target and trust roots.

The shared Policy blocks only `MD-EXEC-001` and `MD-SECRET-001`, carries an
active execution Waiver and an expired secret Waiver, and preserves all
Findings in reports. The collection verifies that an active Waiver removes
blocking without hiding the Finding, while an expired Waiver restores blocking.

Independent review uses a blinded pack containing only:

```text
neutral case manifest
state ZIPs
protected Policy
review instructions
draft submission template
```

The pack excludes the Pilot plan, engineering expectations, scanner outputs,
TP/FP/FN, and implementation reports. A completed submission is SHA-256-bound
to the pack manifest and must cover all 20 cases. Import emits the existing
`agentsec-pilot-human-labels` `0.1.0` contract; it does not change findings,
Policy, Waivers, or CI decisions.

Final acceptance replays all states with the imported labels. Only a complete
20/20 replay with zero failed cases can be passed to the P2-EXIT-08A Entry
Readiness state machine.

## Consequences

- The machine-completable P2-EXIT-06 scope is reproducible and closed.
- Engineering Precision/Recall remains explicitly non-human until review.
- A real independent Reviewer is the only remaining external evidence action.
- Test-only synthetic labels may verify the automation but must never be
  retained or represented as human evidence.
- Entry readiness may become `ready_for_candidate` after a real reviewed replay,
  but `ready_for_release` remains false until candidate acceptance.

## Security boundary

No scanned code, command, Hook, Skill, scheduler, MCP server, or external Tool is
executed. The target cannot select the Policy or labels. LLM output has no role
in labels, Waivers, Allow/Block, or release authorization.
