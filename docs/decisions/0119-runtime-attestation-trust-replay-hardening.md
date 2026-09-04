# ADR-0119：Runtime Attestation Trust / Replay Hardening

- **Status**：Accepted for `RISK-07`
- **Date**：2026-09-04
- **Scope**：Runtime Attestation ingestion, trust verification, replay protection, and RISK-06 reconciliation binding

## Context

RISK-06 accepted an external Runtime Attestation after structural validation and Snapshot/Context/RISK-04 hash binding. A hostile or misconfigured producer could still submit a self-declared `verification_status=verified` artifact. That declaration is not an issuer identity, cryptographic proof, freshness proof, or non-replay guarantee.

## Decision

1. Add a versioned Trusted Runtime Issuer Registry. Registry records issuer/key metadata and an environment-variable name, never secret values.
2. Require `issuer + key_id + signature_algorithm + issued_at + expires_at + nonce + signature` in Runtime Attestation 0.2.
3. Support `hmac_sha256` as a dependency-free baseline. Keep signing and verification detached from scanned workspace content. A future KMS/Ed25519 adapter may extend this contract.
4. Verify active issuer/key, algorithm, HMAC, attestation age, issuer validity window, clock skew, and external declaration status.
5. Persist only hashed nonce/attestation markers in a 0600 symlink-safe replay Store with exclusive lock and atomic replacement.
6. Bind Trust Decision `verification_id` and exact Attestation SHA-256 into Evidence Reconciliation. No Trust Decision means `runtime_verified=false` and Confidence D.
7. Keep all outputs `report_only=true`, `policy_authority=false`, and `ci_blocked=false`.

## Confidence contract

- Trust failure or missing trust input → `unverified`, Confidence D.
- Trusted signature/freshness/non-replay with partial/conflicting static reconciliation → Confidence B.
- Trusted signature/freshness/non-replay with complete, conflict-free reconciliation → Confidence A.

Confidence describes evidence quality. It does not describe Severity, exploitability, permission, identity, or CI authority.

## Consequences

### Positive

- Self-declared runtime verification cannot establish trusted evidence.
- Key rotation and revocation are explicit.
- Replayed attestations are visible and rejected.
- Secret values, raw nonce, user data, URLs, and runtime logs stay out of reports.
- Homi Bundle can show Trust and Reconciliation as separate evidence layers.

### Trade-offs

- HMAC key distribution still requires external organizational secret management.
- Replay state is local to a configured Store and must be retained consistently across runs.
- Missing Registry produces a report rather than a hard command failure because this phase remains report-only.

## Rejected alternatives

- **Trust `verification_status` alone**：not cryptographic and trivially forgeable.
- **Read keys from Workspace**：would let untrusted Agent assets define their own trust root.
- **Store raw nonce or logs**：unnecessary sensitive retention.
- **Use current time without bounded skew/age**：allows stale/future evidence.
- **Let Trust result block CI or grant permission**：violates AgentSec authority boundary.
