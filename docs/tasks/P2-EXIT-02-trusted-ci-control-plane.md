# P2-EXIT-02: Trusted CI Control Plane

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-EXIT-01
- Decision: `docs/decisions/0062-trusted-policy-and-qualification-root.md`
  (P2-EXIT-02 implementation addendum)
- Organization Policy Schema: `0.2.0 → 0.3.0`
- Organization Assessment Report Output: `0.2.0 → 0.3.0`
- Capability CI Report Output: `0.4.0 → 0.5.0`

Closed the P0 audit finding F02: CI previously read Workflow, Runner, Policy,
Waiver, and Qualification from the same PR checkout being evaluated. Trust
artifacts are now loaded from an explicit protected trust root or verified
against protected digest pins, and every report records the trust mode and
verification state.

## Delivered

```text
src/agentsec/trust.py                          trust primitives (import-light)
src/agentsec/organization_policy.py            Schema 0.3.0 + capability.qualification
src/agentsec/policy/ci_enforcement.py          trust provenance in CI decisions
src/agentsec/cli/scan.py                       --trust-root / --expect-policy-sha256
src/agentsec/cli/capability.py                 trust options + registry digest pin
src/agentsec/reporting/organization_policy.py  OrganizationTrustProvenance (0.3.0)
schemas/policy/organization-policy.schema.json regenerated (frozen)
schemas/policy/organization-assessment-report.schema.json regenerated (frozen)
policies/*.yaml, policies/ci/*.yaml            upgraded to 0.3.0 with binding
docs/examples/ci/github-actions-trusted.yml    Mode A + Mode B workflow example
scripts/run-agentsec-ci.sh                     AGENTSEC_TRUST_ROOT / expected digest env
scripts/validate-ci-examples.py                trusted workflow validation + replays
tests/test_trusted_ci_control_plane.py         12 trust-control tests
docs/trusted-ci.md                             modes, prerequisites, guidance
```

## Trust modes

```text
Mode A  external_trust_root   separate protected policy checkout (--trust-root)
Mode B  digest pinning        --expect-policy-sha256 / --expect-registry-sha256
repository_local              explicit lower-trust mode, labeled in reports
```

Mode A and Mode B compose. Target PR files alone can no longer disable
enforcement, create a Waiver, or qualify a Gate, because:

- Policy digests pinned from protected CI configuration must match;
- Waivers live inside the pinned Policy artifact;
- Gate qualification flows through the P2-EXIT-01 registry chain whose digests
  are themselves pinned by the Policy and optionally by `--expect-registry-sha256`;
- trust artifacts are never auto-discovered from scanned project content;
- trust option misuse, digest mismatches, escaping paths, and unsafe roots all
  fail closed with exit `3` before analysis.

## Acceptance

```text
Ruff check: passed
Ruff format: passed
Mypy strict: passed
Pytest: see final report (12 new trust-control tests, full suite green)
CI replay: 9/9 passed, including trusted-pin-block (exit 1),
           trusted-pin-mismatch (exit 3), trusted-root-block (exit 1)
```

## Boundaries

- Mode C signed bundles and package/artifact signatures are P2-EXIT-07 scope.
- The repository has no Git provenance; approval is expressed through reviewed
  digest pins carried by protected CI configuration.
- Organization Policy scan decisions are deterministic and unchanged in
  semantics; only provenance and Gate trust plumbing advanced.
- LLM output and runtime-unverified evidence still hold no Policy, Waiver, or
  Gate authority.

## Next task

```text
P2-EXIT-03: Integrated Agentic Score CLI/Report
```
