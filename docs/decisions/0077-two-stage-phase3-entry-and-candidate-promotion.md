# ADR-0077: Two-stage Phase 3 Entry and Candidate Promotion

- Status: Accepted
- Date: 2026-08-26
- Task: P2-EXIT-08A
- Amends: ADR-0076
- Scope: Phase 3 entry readiness and AgentSec 0.4.0 candidate acceptance

## Context

ADR-0076 introduced a fail-closed Phase 3 Entry Review. Its original `0.1.0`
contract required all of the following in one review:

```text
external real-project Pilot acceptance
PACKAGE_VERSION = 0.4.0
0.4.0 Wheel/sdist/checksum artifacts
```

The same decision prohibited version promotion and candidate artifact creation
until that review returned Go. This created a circular dependency: the review
could not become Go before candidate promotion, while candidate promotion was
not authorized before Go.

Local tests or implementation completeness do not justify bypassing external
Pilot evidence, and changing `PACKAGE_VERSION` merely to satisfy a check would
create a false release signal.

## Decision

Replace the single-step review with a deterministic two-stage state machine and
bump `agentsec-phase3-entry-review` from `0.1.0` to `0.2.0`.

### Stage 1: `entry_readiness`

Required checks:

```text
authority_boundary
external_pilot_evidence
package_api_and_typing
phase2_task_records
supply_chain_evidence
```

This stage deliberately does not inspect the candidate version or candidate
artifacts. When all required checks pass, the report reaches:

```text
state = ready_for_candidate
status = go
ready_for_candidate_promotion = true
ready_for_candidate_build = true
ready_for_phase3_shadow = true
ready_for_release = false
```

This authorizes an explicit release-owner action to prepare a candidate. It does
not itself edit the version, build artifacts, publish anything, approve runtime
authority, or authorize production release.

### Stage 2: `candidate_acceptance`

This stage requires a root-contained `0.2.0` entry-readiness report in
`ready_for_candidate` state. It rechecks local authority, package, Phase 2, and
supply-chain controls, then checks:

```text
entry_readiness_approval
candidate_version_promotion
candidate_artifacts and SHA-256 consistency
candidate_verification
release_signature_and_provenance (optional/local not-claimed is allowed)
```

The candidate verification artifact uses
`agentsec-candidate-verification-report` `0.1.0` and must explicitly record:

```text
package_hardening
reproducible_build
clean_install
public_api_import
checksums_verified
```

Only a `candidate_go` report sets `ready_for_release=true`.

## State machine

| Review stage | State | Meaning |
|---|---|---|
| `entry_readiness` | `entry_no_go` | Entry evidence is incomplete or failed; promotion and Phase 3 remain blocked |
| `entry_readiness` | `ready_for_candidate` | Candidate promotion/build and Phase 3 shadow-only preparation may proceed after explicit owner action |
| `candidate_acceptance` | `entry_no_go` | No valid approved entry-readiness report was supplied |
| `candidate_acceptance` | `candidate_under_review` | Entry is approved; required candidate evidence is still pending |
| `candidate_acceptance` | `candidate_no_go` | Entry is approved, but candidate evidence failed validation |
| `candidate_acceptance` | `candidate_go` | All required candidate checks pass; local candidate acceptance is ready |

Optional signature/provenance evidence does not block local candidate acceptance,
but production or public release systems must provide it before making signing
or SLSA claims.

## Authority boundary

The state machine preserves these non-negotiable controls:

1. LLM output is candidate evidence only.
2. LLM output cannot Allow/Block, publish Rules, or approve Waivers.
3. Runtime-unverified evidence cannot grant authority.
4. Deterministic Rules and reviewed Policy retain authorization authority.
5. CI blocking requires an explicit Policy path.
6. Entry readiness authorizes only candidate preparation and Phase 3
   shadow-only work.
7. Version promotion and artifact construction remain explicit release-owner
   actions.
8. Candidate acceptance does not claim deployment, remote publication, runtime
   attestation, artifact signing, or SLSA provenance.

## Security and validation constraints

- Review artifacts must resolve inside the selected repository/control root.
- Review artifacts are bounded to 1 MiB and parsed only as JSON data.
- Scanned Agent content is never executed.
- Candidate artifact hashes are recalculated locally and compared with the exact
  `SHA256SUMS` set.
- A malformed, stale, cross-root, oversized, or inconsistent evidence artifact
  fails closed.
- A historical `0.1.0` review cannot authorize candidate promotion under the
  `0.2.0` contract.

## Consequences

Positive:

- removes the promotion deadlock without weakening external-evidence gates;
- separates entry authorization from release acceptance;
- permits audited Phase 3 shadow-only work without granting release authority;
- makes pending candidate construction distinguishable from candidate failure;
- preserves machine-readable, deterministic, root-contained evidence.

Trade-offs:

- release automation must run two explicit review commands;
- historical `0.1.0` reports remain records but cannot be reused as approvals;
- a separate candidate verification report must be generated during candidate
  construction;
- release owners still perform explicit version promotion and artifact creation.

## Rejected alternatives

- **Make candidate version/artifacts optional in the original single review:**
  this would blur entry readiness and release acceptance.
- **Automatically change `PACKAGE_VERSION` after entry checks pass:** version
  promotion is an explicit release action, not an inferred scanner decision.
- **Accept a Boolean CLI approval flag:** an unbound Boolean has no provenance or
  replayable evidence.
- **Let an LLM decide whether evidence is sufficient:** authorization remains
  deterministic and policy-controlled.
