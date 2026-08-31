# P2-EXIT-06-05: Independent Review Import and Final Acceptance Replay

- Status: Complete
- Date: 2026-08-26
- Parent: P2-EXIT-06
- Depends on: P2-EXIT-06-04
- ADR: `docs/decisions/0080-final-external-homi-pilot-and-blinded-review.md`

## Delivered automation

```text
pilots/external-homi-demo/final-pilot/reviewer-pack/
  - EXPERT-WORKFLOW.zh.md
  - RULE-REFERENCE.zh.md
scripts/import-external-homi-pilot-review.py
scripts/run-external-homi-final-acceptance.py
src/agentsec/external_pilot.py
schemas/pilot/external-pilot-review-submission.schema.json
```

The Reviewer Pack is blinded. It contains neutral case names, state ZIPs, the
shared Policy, instructions, and a SHA-256-bound draft submission. It contains
no engineering expected values, scanner observations, TP/FP/FN, or
implementation report.

## Reviewer workflow

1. A real independent Reviewer works only inside `reviewer-pack/`.
2. The Reviewer inspects each ZIP as text and fills all 20 outcomes.
3. The Reviewer provides a real ID and independence statement.
4. Import validates format, manifest binding, exact case coverage, known sorted
   Rule IDs, Coverage/exit coherence, and non-empty rationales.
5. Import writes `human-evidence/human-labels.json` with mode `0600`.
6. Final acceptance redeploys the snapshots, verifies the Policy pin, replays all
   scans, calculates TP/FP/FN and performance, and runs P2-EXIT-08A.

Commands:

```bash
PYTHONPATH=src .venv/bin/python \
  scripts/import-external-homi-pilot-review.py \
  --submission /controlled/path/review-submission.json

PYTHONPATH=src .venv/bin/python \
  scripts/run-external-homi-final-acceptance.py \
  --target-root /new/external/target \
  --trust-root /new/protected/trust
```

## Automation verification

A non-persistent automated smoke fixture replayed all 20 cases and reached:

```text
pilot status                 complete
cases passed                 20/20
Phase 3 entry state          ready_for_candidate
ready_for_phase3_shadow      true
ready_for_release            false
```

That fixture was deleted immediately and is not human evidence.

## Independent Review completion

The real submission from `codefuse-agentsec-expert-reviewer` passed Manifest,
Submission, Label, Snapshot, and Policy binding checks for all 20 Cases. The
first reviewed Replay found four deterministic false negatives; P2-EXIT-06-05A
preserved the Human Labels, calibrated Rule Pack `0.3.1`, and replayed the same
submission.

Final result:

```text
pilot status                 complete
cases passed                 20/20
FP / FN                      0 / 0
Precision / Recall           1.0 / 1.0
acceptance_ready             true
Phase 3 entry state          ready_for_candidate
ready_for_phase3_shadow      true
ready_for_release            false
```


## Final automation verification record

Executed on 2026-08-26:

| Verification | Result |
|---|---|
| Reviewer Pack blinding | Pass; no expected/observed/TP/FP/FN values |
| Manifest/snapshot/Policy binding | Pass |
| Draft rejection | Pass |
| Label/import digest tamper rejection | Pass |
| Imported Human Evidence three-file closure | Pass |
| Non-persistent final replay smoke | 20/20; `ready_for_candidate` |
| Canonical Entry Review | `ready_for_candidate`; no blocking checks |
| Full repository check | 1298 passed |
| Package hardening | Pass |
| Reproducible build | Pass; byte-identical |

The smoke Reviewer ID explicitly identified automation-only test evidence, and
all smoke submission, labels, reports, target, and trust directories were
deleted after verification.


## Final independent acceptance verification

Executed after P2-EXIT-06-05A on 2026-08-26:

| Verification | Result |
|---|---|
| Independent Reviewer Cases | 20/20 complete and hash-bound |
| Pre-calibration Replay | 19/20; FP=0, FN=4, Recall=0.84 |
| Human-label preservation | Pass; no automatic rewrite |
| Rule Pack patch | `0.3.1` |
| Final reviewed Replay | 20/20; FP=0, FN=0 |
| Precision / Recall | 1.0 / 1.0 |
| Entry Readiness | `ready_for_candidate`; 5/5 checks pass |
| Full repository check | 1301 passed |
| Package hardening | Pass |
| Reproducible build | Pass; byte-identical |
