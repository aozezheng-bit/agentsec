# P2-EXIT-05: Documentation, Schema, and Version Provenance Consolidation

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-EXIT-03, P2-EXIT-04
- No code behavior change; no version bump

Consolidated documentation, schema ownership, and version provenance so the
repository has exactly one authoritative source for current facts, closing
audit findings F06 (stale/contradictory docs) and F07 (incomplete
`current_versions()` coverage).

## Delivered

```text
docs/current-architecture.md          single authoritative architecture page
docs/current-release-status.md        single authoritative release/status page
src/agentsec/provenance.py            interface provenance registry +
                                      schema_file_ownership() + markdown
                                      renderer
schemas/README.md                     central schema ownership layout
scripts/export_release_schemas.py     now exports all 39 frozen schemas
                                      (added qualified-gate-registry,
                                      agentic-assessment, score-context);
                                      regeneration is byte-identical
README.md                             current status/command/release surface,
                                      documentation map, release status;
                                      stale 0.2.0 claims replaced (history
                                      clearly marked)
docs/tasks/P2-15A-QUAL-01-....md      Superseded banner: qualification v1 → v2
tests/test_provenance_registry.py     7 registry/schema-ownership tests
tests/test_current_docs.py            5 current-state consistency tests
```

## Provenance registry properties

- Every public interface version is classified exactly once:
  product_version_vector / report_family_version_vector /
  historical_and_immutable / fixture_only_or_internal / reserved_phase3.
- All 64 registry interfaces covered; every `*_VERSION` constant in
  `agentsec.versioning` plus module-scoped constants (Pilot, CVSS adapter,
  calibration reviewer pack, vulnerability contracts) verified in tests.
- Eight Phase 3 interfaces reserve version slots without capability or
  authority: semantic analyzer, model provider ID, model ID, prompt, semantic
  output schema, rule-candidate workflow, attack graph, runtime attestation.
- Every record states that version records grant no authorization authority;
  tests enforce `grants_authority is False` for all interfaces.
- Schema ownership map is byte-complete with `schemas/**/*.schema.json`
  (39 files), enforced by test.

## Acceptance

```text
Ruff / Mypy / Pytest: see final project gate (full suite green)
docs link resolution and historical-log tests: passed
export_release_schemas.py regeneration: BYTE-IDENTICAL to frozen schemas
```

## Boundaries

- Historical phase plans and task logs keep their original content (marked as
  history through the README pointer); they are no longer treated as current
  fact sources.
- P2-EXIT-07 owns package API, lockfile/SBOM, and reproducible-build hardening;
  the `agentsec.policy` import cycle was closed by moving `ExitCode` below CLI
  initialization.

## Next task

```text
P2-EXIT-06: External Real-project Report-only Pilot
```
