# Trusted CI Control Plane

- Task: `P2-EXIT-02`
- Status: Complete
- Completion date: 2026-08-25
- Decision: `docs/decisions/0062-trusted-policy-and-qualification-root.md`
  (P2-EXIT-02 addendum)
- Organization Policy Schema: `0.2.0 → 0.3.0`
- Organization Assessment Report Output: `0.2.0 → 0.3.0`
- Capability CI Report Output: `0.4.0 → 0.5.0`

## Problem

Phase 2 CI previously read the workflow, runner, Policy, Waivers, and Gate
qualification from the same pull-request checkout being evaluated. A target PR
could therefore modify the controls that judge it: relaxing the Policy,
creating a Waiver, or forging a qualification artifact.

## Supported trust modes

```text
Mode A  external_trust_root
        Policy/Waiver/Qualification artifacts are checked out from a
        separate protected repository into --trust-root. The relative
        --policy path resolves inside the trust root and may not escape it.

Mode B  digest pinning
        --expect-policy-sha256 (scan and capability enforce) and
        --expect-registry-sha256 (capability enforce) carry SHA-256 pins
        supplied by protected CI configuration (variables or secrets). Any
        mismatch fails closed with exit 3.

repository_local
        The default lower-trust mode: Policy is loaded from an explicit path
        without a trust root or digest pin. Reports record
        trust_mode=repository_local so reviewers can see the boundary.
```

Modes A and B compose: the recommended production setup checks out the
security-policy repository (Mode A) and pins the Policy digest from a
protected variable (Mode B).

## CLI surface

```bash
agentsec scan PROJECT \
  --policy organization-policy.yaml \
  --trust-root ../security-policy-repo \
  --expect-policy-sha256 <approved digest>

agentsec capability enforce PROJECT \
  --policy organization-policy.yaml \
  --trust-root ../security-policy-repo \
  --expect-policy-sha256 <approved digest> \
  --expect-registry-sha256 <approved registry digest>
```

Behavior:

- trust options without an explicit `--policy` fail with exit `3`;
- escaping policy paths, symlinked trust roots, missing roots, and
  non-directory roots fail with exit `3`;
- invalid digest-pin syntax (not 64 lowercase hex chars) fails with exit `3`;
- digest mismatches fail with exit `3` before any scan analysis runs;
- trust artifacts are never auto-discovered from scanned project content.

## Report provenance

Organization Assessment Output `0.3.0` records:

```text
trust.trust_mode                repository_local | external_trust_root
trust.policy_digest_pinned      whether --expect-policy-sha256 was supplied
trust.policy_digest_verified    whether the pin matched the loaded Policy
trust.expected_policy_sha256    the approved pin (when supplied)
```

Capability CI Output `0.5.0` additionally records registry digest pinning:

```text
trust.registry_digest_pinned    whether --expect-registry-sha256 was supplied
trust.registry_digest_verified  whether the pin matched the loaded registry
trust.expected_registry_sha256  the approved pin (when supplied)
```

Text reports render a `Trust mode:` line with the digest verification state.

## Waivers

Waivers are embedded in the Policy artifact, so a protected Policy digest pin
also protects Waiver authority: a mismatched, missing, or mutated Policy (and
therefore any Waiver inside it) cannot participate in a decision. Capability
Gate waivers additionally cannot bypass qualification, coverage, or Unknown
checks.

## Organization Policy capability Gates (Schema 0.3.0)

Organization Policies may again authorize Capability Gates through the same
verified registry chain introduced by P2-EXIT-01:

```yaml
capability:
  qualified_gates:
    - HG-CAPCHAIN-001
  qualification:
    registry_path: evidence/qualified-gate-registry.yaml
    registry_sha256: "<approved digest>"
```

Policies that list Capability Gates without a qualification binding remain
invalid and fail closed with exit `3` at load time.

## Repository governance prerequisites

Digest pins only hold when the pinned values and workflow cannot be changed by
the target PR alone. The following controls are required for Mode A/B to be
meaningful:

- the security-policy repository (or protected branch/directory holding the
  Policy) has CODEOWNERS requiring security-team review;
- branch protection enforces required reviews, status checks, and blocks
  force-pushes and deletions;
- workflow files and `.github/` changes require the same protected review;
- protected CI variables or secrets hold the approved digests and restricted
  write access; fork pull requests cannot read them;
- the P2-29 runner preserves the exit code before uploads and enforces it in
  a final `if: always()` step (no `continue-on-error` masking).

Repository-local Policy remains available for experiments under the explicit
`repository_local` trust mode and is labeled as such in every report. It must
not be presented as a protected CI decision.

## CI examples

- `docs/examples/ci/github-actions.yml`: repository-local lower-trust mode.
- `docs/examples/ci/github-actions-trusted.yml`: Mode A + Mode B with two
  checkouts (`persist-credentials: false` on the trust checkout) and a
  protected digest variable.
- `docs/examples/ci/gitlab-ci.yml`: repository-local mode with always-uploaded
  artifacts.

`scripts/validate-ci-examples.py` statically validates the workflows and
replays the decision matrix, including:

```text
trusted-pin-block      correct digest pin keeps the blocking decision (exit 1)
trusted-pin-mismatch   wrong digest pin fails closed (exit 3)
trusted-root-block     Mode A trust root keeps the blocking decision (exit 1)
```

The CI runner `scripts/run-agentsec-ci.sh` honors `AGENTSEC_TRUST_ROOT` and
`AGENTSEC_EXPECT_POLICY_SHA256` environment variables.

## Boundaries

- LLM output, runtime-unverified evidence, and D-confidence evidence still
  hold no Gate or CI authority;
- trust verification never executes scanned content, connects to MCP servers,
  accesses the network, or reads environment/secret values;
- P2-EXIT-02 does not sign artifacts; Mode C (signed bundles) and package
  provenance are tracked by P2-EXIT-07.
