# ADR-0064: Hard Gate Phase 2 Scope Decision

- Status: Accepted
- Date: 2026-08-25
- Task: P2-EXIT-04
- Source: P2-AUDIT-01 finding F04
- Supersedes: the “3–5 Capability Hard Gates” Phase 2 acceptance criterion for
  the Phase 2 MVP
- Related: ADR-0062 (trusted Gate qualification), P2-CAL-01～04, P2-15A/B

## Context

The Phase 2 requirements table asked for 3～5 combination Capability Hard
Gates with Critical-level test recall and reviewed pilot precision. The
implemented and policy-allow-listed surface supports exactly one qualified
Gate:

```text
HG-CAPCHAIN-001  (execute + secret-access + external network, High floor)
```

`HG-PRODAUTO-001` and `HG-EXTERNALPROD-001` exist only as report-only
candidates: they have corpus coverage and seed adjudication, but no
independent reviewed qualification meeting the Gate promotion thresholds
(20 reviewed positives, 20 eligible negatives/near-misses, precision and
recall thresholds, reviewed Confidence calibration, complete Coverage, no
relevant Unknowns).

The Phase 2 completion audit (F04) required a formal decision before Phase 3:
either formally rescope the Phase 2 MVP acceptance criterion to “one
qualified Gate plus candidate framework”, or implement and qualify at least
two additional Gates. Leaving the table claiming 3–5 while the product
supports one is forbidden.

## Decision

Adopt **Path A — formal one-Gate MVP scope**:

1. The Phase 2 MVP Hard Gate scope is exactly one qualified Gate:
   `HG-CAPCHAIN-001`, qualified through the P2-CAL-04A human-evidence chain
   and pinned in the Qualified Gate Registry (ADR-0062).
2. `HG-PRODAUTO-001` and `HG-EXTERNALPROD-001` are formally **Shadow
   candidates**: they remain named in the calibration corpus, reviewer pack,
   adjudication report, and Gate-candidate documentation, and may be evaluated
   in shadow/report-only form, but they hold no enforcement allow-list entry
   and no floor authority.
3. Promotion of any additional Gate requires the full reviewed evidence chain
   defined by the Hard Gate plan: at least 20 reviewed positives and 20
   eligible negatives/near-misses, independent Reviewer A/B plus adjudication,
   Confidence calibration, a qualification report bound to the registry, and
   shadow/report-only pilot evidence — in line with P2-EXIT-06 external pilot
   results. Gates are not manufactured to satisfy a count.
4. The P2-15A acceptance blocks in `docs/phase2-scope.md`,
   `docs/phase2-integration-plan.md`, and
   `docs/capability-calibration-hard-gate-enforcement-plan.md` are updated to
   reference this decision instead of the historical “3–5 calibrated Gate
   IDs” line.
5. The external requirements table (execution-plan document) records this
   rescope in its P2-15 row so the table no longer claims 3–5 while the
   product supports one.

## Consequences

- The Phase 2 MVP acceptance criterion becomes “one qualified Gate plus a
  governed candidate framework”; the count mismatch identified by F04 is
  closed.
- CI enforcement continues to rely solely on `HG-CAPCHAIN-001` under the
  trusted Policy/Registry chain; no other Gate may enter the allow-list
  without a new qualification record and registry entry.
- Phase 3 scope (LLM evidence, Attack Graph) is unaffected: it still may not
  create Gate authority, downgrade floors, or bypass qualification.
- If the external pilot later reveals that additional Gate patterns are
  needed, they follow Path B with full evidence; this ADR does not block that
  work, it only removes the count obligation from the Phase 2 MVP.
