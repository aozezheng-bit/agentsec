# P2-EXIT-04: Hard Gate Scope Closure

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-EXIT-01, external evidence review
- Decision: Path A — formal one-Gate MVP scope
- ADR: `docs/decisions/0064-hard-gate-phase2-scope-decision.md`

Closed audit finding F04: the Phase 2 table claimed 3～5 combination Hard
Gates while the product supports one qualified Gate. Per the P2-EXIT plan
recommendation, the scope is formally rescoped rather than manufacturing Gate
count without external evidence.

## Decision (Path A)

```text
Phase 2 MVP Hard Gate scope = 1 qualified Gate: HG-CAPCHAIN-001
Shadow candidates retained:  HG-PRODAUTO-001, HG-EXTERNALPROD-001
Promotion of additional Gates requires:
  20 reviewed positives + 20 eligible negatives/near-misses per Gate
  independent Reviewer A/B + adjudication
  Confidence calibration
  qualification report bound to the registry (ADR-0062 chain)
  shadow/report-only pilot evidence (P2-EXIT-06 external pilot)
```

## Changes

```text
docs/decisions/0064-hard-gate-phase2-scope-decision.md      new ADR
docs/phase2-scope.md                                        5.4 rescoped
docs/phase2-integration-plan.md                             5.4 rescoped
docs/capability-calibration-hard-gate-enforcement-plan.md   5.4 rescoped +
                                                            status header updated
tests/test_phase2_calibration_docs.py                       new consistency test
```

The three Gate Candidate IDs remain named everywhere (required by the
calibration handoff documentation guarantees), now with explicit Shadow
candidate status instead of an unmet 3–5 count.

## External requirements table

The authoritative execution-plan requirements table lives in the Yuque plan
document. Its P2-15 row / Phase 2 exit conditions must record this rescope
(“one qualified Gate plus governed candidate framework, per ADR-0064”) so the
table no longer claims 3–5. The repository now carries the formal decision
and all repo-side acceptance criteria are aligned with it.

## Acceptance

```text
P2-EXIT-04 DoD: requirement table and product Gate count are consistent, and
no document still claims 3–5 while the product supports one.
Repo state: all three plan documents rescoped with ADR-0064 reference;
new doc-consistency test pins the rescoped wording and candidate IDs.
tests/test_phase2_calibration_docs.py: 11 passed
```

## Boundaries

- No code, schema, or risk-model change: no version impact.
- No Gate gains or loses authority: enforcement still allows exactly
  HG-CAPCHAIN-001 through the trusted Policy/Registry chain.
- Path B remains available later with full external evidence; this decision
  removes the count obligation from the Phase 2 MVP only.

## Next task

```text
P2-EXIT-05: Documentation/Schema/Version Provenance Consolidation
```
