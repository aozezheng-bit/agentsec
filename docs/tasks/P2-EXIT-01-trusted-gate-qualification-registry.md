# P2-EXIT-01: Trusted Gate Qualification Registry

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-AUDIT-01 (finding F01)
- Decision: `docs/decisions/0062-trusted-policy-and-qualification-root.md`
- Capability CI Policy Schema: `0.1.0 → 0.2.0`
- Capability CI Report Output: `0.3.0 → 0.4.0`
- New contract: Qualified Gate Registry Schema `0.1.0`

Closed the P0 trust-root gap identified by the Phase 2 completion audit: a
repository-relative minimal forged qualification artifact can no longer obtain
Capability Gate authority. Gate authority now flows through an explicitly
pinned Qualified Gate Registry whose full evidence-binding chain is verified.

## Delivered

```text
src/agentsec/policy/qualification_registry.py
schemas/policy/qualified-gate-registry.schema.json
calibration/p2-15a-capchain-40/human-evidence/qualified-gate-registry.yaml
policies/capability-ci-policy.json (schema 0.2.0)
policies/capability-ci-enforce-example.json (schema 0.2.0 + registry binding)
tests/test_qualified_gate_registry.py (21 tests)
docs/decisions/0062-trusted-policy-and-qualification-root.md
```

## Design

```text
Capability CI Policy (pinned registry_sha256)
→ Qualified Gate Registry (bounded no-follow strict YAML)
→ pinned qualification report digest
→ duplicate-key-safe JSON parse of the report
→ Gate/Rule binding, status, checks, boundary flags
→ recomputed artifact_id matched against the registry pin
→ Gate authority (accepted) or fail closed
```

- No trust artifact is ever auto-discovered from scanned project content.
- Organization YAML Policy `0.2.0` cannot carry a registry binding yet, so
  `capability enforce` with Capability Gates listed there fails closed with
  exit `3` until P2-EXIT-02 delivers the trusted CI control plane.
- LLM, runtime-unverified, and D-confidence evidence remain excluded from
  Gate authority; report-only policies keep no blocking power.

## Required tests (plan section "Tests")

```text
minimal forged qualification rejected          PASSED
truncated qualification rejected               PASSED
wrong evidence artifact ID rejected            PASSED
wrong qualification SHA-256 rejected           PASSED
wrong Gate ID or Rule ID rejected              PASSED
wrong floor rejected                           PASSED
report symlink rejected                        PASSED
registry symlink rejected                      PASSED
duplicate keys rejected (registry + report)    PASSED
valid pinned qualification accepted            PASSED
missing registry fails closed                  PASSED
registry digest mismatch fails closed          PASSED
unbound Gate list rejected at policy load      PASSED
forged qualification fails closed under enforce PASSED
valid registry blocks matched Gate (engine)    PASSED
valid registry report-only keeps exit 0        PASSED
frozen schema consistency                      PASSED
repository registry binds real evidence        PASSED
```

## Acceptance

```text
Ruff check: passed
Ruff format: passed — 803 files
Mypy strict: passed — 260 source files
Pytest: 1175 passed (21 new P2-EXIT-01 tests)
CLI smoke: enforce example policy registry binding verified live
```

## Boundaries

- This task does not sign artifacts, add remote trust sources, or change
  Organization Policy Schema; P2-EXIT-02 owns the protected CI control plane.
- The repository currently remains a local workspace without Git provenance;
  approval of the registry continues to be expressed through the reviewed
  policy digest pin until protected CI variables or signed bundles exist.
- No runtime capability verification, no LLM authority, and no global safety
  claim is introduced.

## Next task

```text
P2-EXIT-02: Trusted CI Control Plane
```
