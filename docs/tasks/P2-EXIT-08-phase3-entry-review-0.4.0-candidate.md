# P2-EXIT-08: Phase 3 Entry Review / AgentSec 0.4.0 Candidate

- Status: `Complete; candidate_go`
- Date: 2026-08-26
- Depends on: P2-EXIT-01～07
- Original ADR: `docs/decisions/0076-phase3-entry-review-and-0.4.0-candidate.md`
- Amended by: `docs/decisions/0077-two-stage-phase3-entry-and-candidate-promotion.md`
- Implementation task: `docs/tasks/P2-EXIT-08A-phase3-entry-readiness-candidate-promotion.md`
- Current report contract: `agentsec-phase3-entry-review` `0.2.0`
- Latest JSON: `docs/reviews/phase3-entry-readiness-2026-08-26.json`
- Latest Text: `docs/reviews/phase3-entry-readiness-2026-08-26.md`

## Executive decision

P2-EXIT-08A corrected the original single-stage promotion deadlock. The current
review now evaluates only Phase 3 entry readiness before version promotion or
candidate construction.

Current result:

```text
review_stage = entry_readiness
state = ready_for_candidate
status = go
current_package_version = 0.4.0.dev0
candidate_version = 0.4.0
blocking_checks = []
ready_for_phase3_shadow = true
ready_for_release = false
```

All five required Entry Readiness checks pass. The result authorizes candidate
promotion/build preparation and Phase 3 Shadow-only work, but not release or
production deployment.

The following are no longer entry-readiness blockers:

```text
candidate_version_promotion
candidate_artifacts
candidate_verification
```

They belong exclusively to the later `candidate_acceptance` stage after a valid
`ready_for_candidate` report and explicit release-owner action.

## Two-stage command flow

### 1. Entry readiness

```bash
PYTHONPATH=src .venv/bin/python scripts/run-phase3-entry-review.py \
  --stage entry_readiness \
  --external-pilot-report /controlled/path/external-pilot-report.json \
  --format json \
  --output /controlled/path/entry-readiness.json
```

Required result before promotion/build:

```text
state = ready_for_candidate
ready_for_candidate_promotion = true
ready_for_candidate_build = true
ready_for_phase3_shadow = true
ready_for_release = false
```

### 2. Candidate acceptance

After explicit owner approval, version promotion, candidate build, checksum
creation, clean-install/API verification, and reproducible-build verification:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-phase3-entry-review.py \
  --stage candidate_acceptance \
  --entry-readiness-report /controlled/path/entry-readiness.json \
  --candidate-verification-report /controlled/path/candidate-verification.json \
  --format json \
  --output /controlled/path/candidate-acceptance.json
```

Only this stage can reach:

```text
state = candidate_go
ready_for_release = true
```

## Current entry checks

| Check | Required | Current result |
|---|---:|---|
| `authority_boundary` | Yes | Pass |
| `external_pilot_evidence` | Yes | Pass |
| `package_api_and_typing` | Yes | Pass |
| `phase2_task_records` | Yes | Pass |
| `supply_chain_evidence` | Yes | Pass |

## Candidate-stage checks

```text
entry_readiness_approval
candidate_version_promotion
candidate_artifacts and exact SHA256SUMS
candidate_verification
package_api_and_typing (rechecked)
phase2_task_records (rechecked)
supply_chain_evidence (rechecked)
authority_boundary (rechecked)
release_signature_and_provenance (optional/local not-claimed permitted)
```

## Authority boundary

```text
LLM output = candidate evidence only
LLM output != Allow/Block
LLM output != automatic Rule publication
LLM output != Waiver approval
runtime-unverified evidence != authority
deterministic Rules retain authorization authority
CI blocking requires explicit reviewed Policy
entry readiness != release authorization
candidate acceptance != production deployment or runtime attestation
```

## Current limitations and next action

- No production runtime attestation exists.
- LLM output remains disconnected from deterministic authorization paths.
- Package version remains `0.4.0.dev0` until an explicit release-owner action.
- No `dist/0.4.0/` candidate artifacts have been created.
- `ready_for_candidate` permits Phase 3 Shadow-only implementation but does not
  authorize release.

Next, begin Phase 3 Shadow-only work or, when explicitly approved by the release
owner, perform version promotion/build and run the separate
`candidate_acceptance` stage.

## Stage 2 completion — 2026-08-31

After explicit release-owner approval, the package was promoted to `0.4.0`,
local Wheel/sdist/checksums were created, package hardening, clean install,
public API, checksum, and reproducible-build verification passed, and
`candidate_acceptance` returned `candidate_go` with no blocking checks.

This is local candidate acceptance only. Remote publication, production
deployment, signatures, SLSA provenance, Runtime Attestation, and semantic
authority are not claimed.
