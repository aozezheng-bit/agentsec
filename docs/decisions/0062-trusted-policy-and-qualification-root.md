# ADR-0062: Trusted Policy and Qualification Root

- Status: Accepted
- Date: 2026-08-25
- Task: P2-EXIT-01
- Source: P2-AUDIT-01 finding F01
- Capability CI Policy Schema: `0.1.0` → `0.2.0`
- Capability CI Report Output: `0.3.0` → `0.4.0`
- New contract: Qualified Gate Registry Schema `0.1.0`

## Context

`capability enforce` previously accepted Gate authority from a fixed
repository-relative qualification report path. The check validated only a few
top-level fields (`format`, `schema_version`, `gate_id`, and
`qualification.status`). A minimal forged JSON file added by the same PR being
evaluated could therefore obtain Gate authority, and there was no approved
digest pin or full evidence-binding verification.

Phase 2 exit requirements (P2-EXIT-01) demand that a PR-created qualification
artifact cannot gain Gate authority unless it matches a separately approved
registry and digest, and that missing or invalid trust evidence fails closed
with exit `3`.

## Decision

1. Introduce a strict `agentsec-qualified-gate-registry` schema `0.1.0`
   contract with a bounded, safe YAML loader:
   - UTF-8, regular-file, `O_NOFOLLOW` read with a 2 MiB size limit;
   - YAML aliases, anchors, and tags are forbidden;
   - duplicate keys and unknown fields are rejected;
   - every Gate entry pins `qualification_report_path`,
     `qualification_artifact_id`, `qualification_sha256`,
     `evidence_mode=human`, `qualification_status=accepted`, and
     `allowed_floor=high`.
2. The Capability CI Policy contract moves to `0.2.0`. A policy that lists
   any `fail_on.qualified_gates` entry must carry a `qualification` trust
   binding with an explicit `registry_path` and an approved
   `registry_sha256` pin. Listing Gates without this binding is a Policy
   error.
3. Gate qualification is verified through the full evidence-binding chain:
   - the registry SHA-256 must equal the policy pin;
   - the qualification report is loaded only from the registry entry's
     pinned path, which must remain inside the registry directory, use no
     symlink, and stay within the size limit;
   - the report byte SHA-256 must equal the registry pin;
   - duplicate JSON keys are rejected;
   - `format`, `schema_version`, Gate ID, Rule binding
     (`HG-CAPCHAIN-001` → `CAP-CHAIN-001`), evidence mode, completion
     status, accepted qualification, empty blocking reasons, passing
     checks, and safe policy flags are all required;
   - the report `artifact_id` is recomputed from canonical bytes with the
     artifact ID removed and must equal both the report value and the
     registry pin.
4. Trust evidence is never auto-discovered from scanned project content.
   The registry path comes only from the explicit policy binding.
5. Any missing, truncated, forged, tampered, or mismatched trust artifact
   fails closed. Under an active `enforce` policy this returns
   `configuration_error` exit `3`; report-only policies continue to record
   `not_qualified` Gates without authority.
6. The enforcement report (`agentsec-capability-ci-enforcement`) moves to
   `0.4.0` and records registry provenance (`registry_id`,
   `registry_version`, pinned SHA-256) when a registry was supplied.

## Interim organizational Policy boundary

Organization Policy YAML `0.2.0` has no qualification registry binding field.
Until P2-EXIT-02 introduces the trusted CI control plane and the planned
Organization Policy Schema `0.3.0`, `capability enforce` with an
organization YAML policy that lists Capability Gates fails closed with exit
`3`. Organization Policy scan decisions (`scan --policy`) are unaffected.

## Consequences

- Minimal forged, truncated, or mutated qualification artifacts cannot obtain
  Gate authority.
- Gate authority now requires separately approved registry content plus a
  digest pin in the reviewed policy.
- P2-EXIT-02 must provide the protected trust source (separate checkout,
  protected digest, or signature) so that the policy pin itself cannot be
  changed by the target PR alone.
- LLM output, runtime-unverified evidence, and D-confidence evidence remain
  excluded from Gate authority.

## P2-EXIT-02 Implementation Addendum (2026-08-25)

- Organization Policy Schema advances `0.2.0 → 0.3.0` and gains an optional
  `capability.qualification` binding (`registry_path` and approved
  `registry_sha256`). Organization Policies that list Capability Gates
  without this binding remain invalid, which closes the interim fail-closed
  transition introduced by P2-EXIT-01 through the same verified registry
  chain.
- The CLI gains explicit trust controls for `scan` and `capability enforce`:
  - `--trust-root PATH` separates the trust artifact root (Mode A: separate
    trusted policy checkout). Relative `--policy` paths resolve inside the
    trust root; escaping paths, symlinked roots, and non-directory roots are
    rejected with exit `3`;
  - `--expect-policy-sha256` pins the loaded Policy digest (Mode B:
    immutable digest supplied by protected CI configuration);
  - `--expect-registry-sha256` pins the qualification registry digest on the
    Capability enforcement path;
  - any digest mismatch, or trust options supplied without an explicit
    Policy, fails closed with exit `3`.
- Reports record trust provenance. Capability CI Report Output advances
  `0.4.0 → 0.5.0` with a `trust` block (trust mode, policy digest pin and
  verification state, registry digest pin and verification state).
  Organization Assessment Report Output advances `0.2.0 → 0.3.0` with the
  same provenance wrapper. Decision semantics are unchanged.
- Repository-local Policy remains available as an explicitly labeled
  lower-trust mode (`trust_mode=repository_local`) with documented
  prerequisites (CODEOWNERS, branch protection, change approval); protected
  runs report `trust_mode=external_trust_root`.
- Trust artifacts are never auto-discovered from scanned project content;
  Waivers are protected through the Policy digest pin because they are
  embedded in the pinned Policy artifact.
