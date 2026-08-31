# P2-EXIT-08A: Phase 3 Entry Readiness / Candidate Promotion State Machine

- Status: Complete
- Date: 2026-08-26
- Depends on: P2-EXIT-08
- ADR: `docs/decisions/0077-two-stage-phase3-entry-and-candidate-promotion.md`
- Report contract: `agentsec-phase3-entry-review` `0.2.0`

## Problem

P2-EXIT-08 `0.1.0` required `PACKAGE_VERSION=0.4.0` and candidate artifacts in
order to return Go, while its release policy prohibited creating those items
before Go. P2-EXIT-08A removes that circular dependency without weakening the
external Pilot or deterministic authority requirements.

## Delivered

```text
src/agentsec/release_review.py
scripts/run-phase3-entry-review.py
tests/test_phase3_entry_review.py
docs/decisions/0077-two-stage-phase3-entry-and-candidate-promotion.md
```

## Stage 1: Entry readiness

Run:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-phase3-entry-review.py \
  --stage entry_readiness \
  --external-pilot-report /controlled/path/external-pilot-report.json \
  --format json \
  --output /controlled/path/entry-readiness.json
```

Required checks:

```text
authority_boundary
external_pilot_evidence
package_api_and_typing
phase2_task_records
supply_chain_evidence
```

A successful report has:

```json
{
  "review_stage": "entry_readiness",
  "state": "ready_for_candidate",
  "status": "go",
  "acceptance_ready": true,
  "ready_for_candidate_promotion": true,
  "ready_for_candidate_build": true,
  "ready_for_phase3_shadow": true,
  "ready_for_release": false
}
```

Entry readiness does not require `PACKAGE_VERSION=0.4.0` or `dist/0.4.0/`.
It never performs those release actions automatically.

## Stage 2: Candidate acceptance

After an explicit release-owner promotion/build action, run:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-phase3-entry-review.py \
  --stage candidate_acceptance \
  --entry-readiness-report /controlled/path/entry-readiness.json \
  --candidate-verification-report /controlled/path/candidate-verification.json \
  --format json \
  --output /controlled/path/candidate-acceptance.json
```

Required candidate evidence:

```text
approved root-contained 0.2.0 entry-readiness report
PACKAGE_VERSION = 0.4.0
0.4.0 Wheel and sdist
exact matching SHA256SUMS
candidate verification report
rechecked package/supply-chain/authority controls
```

Candidate verification report contract:

```json
{
  "format": "agentsec-candidate-verification-report",
  "format_version": "0.1.0",
  "candidate_version": "0.4.0",
  "status": "complete",
  "acceptance_ready": true,
  "checks": {
    "package_hardening": true,
    "reproducible_build": true,
    "clean_install": true,
    "public_api_import": true,
    "checksums_verified": true
  }
}
```

## CLI exit codes

```text
0 = current stage accepted (`ready_for_candidate` or `candidate_go`)
2 = required evidence pending/failed or candidate still under review
3 = invalid stage/evidence configuration
```

## Security invariants

```text
No scanned Agent content execution
No network or runtime Tool invocation
All approval/evidence JSON paths must remain inside repository root
Control report size <= 1 MiB
Historical 0.1.0 reports cannot authorize 0.2.0 candidate promotion
LLM remains candidate evidence only
Entry readiness grants no release or production authority
Candidate artifacts are hash-verified, not existence-only
```

## Historical pre-human repository result

Before independent Human Evidence was imported, the engineering-only report produced:

```text
review_stage = entry_readiness
state = entry_no_go
status = no_go
blocking_checks = external_pilot_evidence
```

The report now satisfies machine scope and all Drills, but remains
`evidence_pending` because `human_labels_complete=false`. After a real blinded
submission is imported and the final 20/20 replay passes, the same state machine
is expected to return `ready_for_candidate`; a test-only deleted smoke fixture
has verified this transition without creating human evidence.

Unlike the old contract, `candidate_version_promotion` and
`candidate_artifacts` are no longer entry-stage blockers. They are evaluated
only during `candidate_acceptance` after an approved entry-readiness report.

## Verification

Acceptance requires:

```text
P2-EXIT-08A state-transition tests
cross-stage argument rejection
root-contained evidence validation
candidate checksum tamper rejection
bilingual Text and JSON rendering
Ruff / format / Mypy
full Pytest
```

## Completion verification record

Executed on 2026-08-26:

| Verification | Result |
|---|---|
| State-machine targeted tests | 10 passed |
| P2-EXIT-08A/package/docs targeted regression | 21 passed |
| Full test suite | 1269 passed |
| `ruff check src tests scripts` | Pass |
| `ruff format --check src tests scripts` | Pass; 316 files formatted |
| Strict `mypy` | Pass; 289 source files |
| Package hardening verification | Pass |
| Fixed-epoch reproducible build | Pass; Wheel/sdist byte-identical |
| Current `entry_readiness` CLI | Expected exit 2; only `external_pilot_evidence` blocks |
| Current `candidate_acceptance` CLI without approval | Expected exit 2; fail-closed |

P2-EXIT-08A completion-time fixed-epoch development-build hashes:

```text
agentsec-0.4.0.dev0-py3-none-any.whl
6acbd9e982436eba255d5636e09b5a9e2c1a22ec6feeee076ae3fc3c95feae04

agentsec-0.4.0.dev0.tar.gz
8d846176251bcb2382de615ff06e3e8cd1d0819ee57a4ef5f89ce425d4b6e594
```

These temporary reproducibility hashes are verification evidence, not promoted
`dist/0.4.0/` release artifacts. Artifact signatures and SLSA provenance remain
explicitly `not_claimed`.

Later tasks may change the sdist hash as source evidence and documentation are
added; use the latest task/release record for the current development-build hash.

## Historical P2-EXIT-06-04/05 readiness amendment

The Entry Review was replayed on 2026-08-26 with the canonical 20-State
engineering report:

```text
state                         entry_no_go
passing required checks       4/5
external machine scope        complete
engineering cases             20/20 pass
independent human labels      pending
ready_for_phase3_shadow       false
ready_for_release             false
```

The updated rationale explicitly records that machine scope is complete and
that independent human labels plus the final reviewed replay are the only
remaining evidence gap. A deleted automation-only smoke artifact verified the
future transition to `ready_for_candidate`; it cannot authorize promotion.


## Final independent-Pilot Entry decision

After P2-EXIT-06-05A calibration, Entry Readiness was replayed with the accepted
independent external Pilot report:

```text
state                         ready_for_candidate
status                        go
required checks               5/5 pass
blocking checks               none
ready_for_candidate_build     true
ready_for_phase3_shadow       true
ready_for_release             false
```

The earlier `entry_no_go` report is preserved under `docs/reviews/history/`.

## Stage 2 execution record — 2026-08-31

```text
PACKAGE_VERSION        0.4.0
review_stage           candidate_acceptance
state                  candidate_go
status                 go
ready_for_release      true
blocking_checks        none
```

Artifacts and reports are stored under `dist/0.4.0/` and `docs/reviews/`.
Signatures/SLSA, remote publication, and production deployment remain explicitly
not claimed.
