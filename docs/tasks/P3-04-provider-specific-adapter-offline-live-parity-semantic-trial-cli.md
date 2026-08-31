# P3-04: Provider-Specific Adapter, Offline/Live Parity, and Semantic Trial CLI

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-01～P3-03
- ADR: `docs/decisions/0085-provider-specific-adapter-parity-trial-cli.md`

## Delivered

- `src/agentsec/semantic/provider_specific.py`
- `src/agentsec/semantic/trial.py`
- `src/agentsec/cli/semantic.py`
- `SemanticParityHarness` and parity report
- protected Config/Case/Response Schemas
- `agentsec semantic trial`
- atomic Text/JSON semantic evaluation report output
- tests in `tests/test_semantic_p3_04.py`

## Authority

```text
shadow_only=true
report_only=true
policy_authority=false
release_authority=false
provider_promotion_authority=false
runtime_verified=false
```

## Verification

Completion verification on 2026-08-31:

```text
P3-04 regression tests             25 passed
Full Pytest                        1342 passed
Ruff check/format                 pass
Strict Mypy                       pass; 309 source files
Package hardening                 pass
Reproducible build                byte_identical=true
Artifact signature                not_claimed
SLSA provenance                   not_claimed
```

The final build hashes are recorded in `docs/current-release-status.md`.
