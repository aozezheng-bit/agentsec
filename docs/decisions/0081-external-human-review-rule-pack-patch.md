# ADR-0081: External Human Review False-negative Rule Pack Patch

- Status: Accepted
- Date: 2026-08-26
- Task: P2-EXIT-06-05A
- Rule Pack: `0.3.0` → `0.3.1`

## Context

The first final Replay using the completed independent external Homi review
produced:

```text
Cases       19/20 passed
Precision   1.00
Recall      0.84
FP          0
FN          4
```

All four false negatives were in the original supplied `baseline-01` Homi
`AGENTS.md`:

```text
MD-EXEC-001
MD-NET-001
MD-SELF-001
MD-TOOL-001
```

The Expert identified direct declarations to check Git state and commit/push,
search the web, update `AGENTS.md`, and use Skills/tools. The independent labels
were complete, hash-bound, and supported by source rationale. Rewriting the
Human Labels to match the implementation would create circular evidence.

## Decision

Preserve the Human Labels and add bounded lexical coverage for the reviewed
phrases while retaining the existing Rule IDs and meanings:

```text
MD-EXEC-001  git status; commit and push your own changes
MD-NET-001   search the web
MD-SELF-001  update AGENTS.md
MD-TOOL-001  Skills provide your tools
```

Increment `RULE_PACK_VERSION` from `0.3.0` to `0.3.1`. This is a patch because
it corrects false-negative implementation coverage without changing Rule IDs,
risk categories, Finding shape, risk scores, Confidence, Policy scope, Waiver
semantics, or CI authority.

Add a regression that replays the exact independently reviewed baseline ZIP and
requires all five Expert-labelled Rule IDs with source Evidence.

## Consequences

- The original independent Review remains authoritative and unchanged.
- The pre-calibration 19/20 report remains an immutable audit record.
- Current source reports carry Rule Pack `0.3.1`.
- Frozen `0.3.0` release artifacts and their calibration evidence remain
  historical records using Rule Pack `0.3.0`.
- The external Pilot must be replayed again before Phase 3 Entry Readiness.

## Authority boundary

This patch does not add LLM authority, runtime proof, new blocking Rules,
automatic Waiver approval, severity changes, or release authorization.
