# RISK-01：Operation Context Contract

- Status: Complete
- Date: 2026-09-03
- Scope: versioned static Operation Context input contract

## Objective

Define the strict input contract that represents an Agent operation without
turning a capability declaration into a Finding or granting runtime authority.

## Delivered

- `src/agentsec/risk/context.py`
  - action, target, data classification, sharing, and retention enums;
  - trigger, purpose, authorization, reversibility, scope, and frequency enums;
  - strict `DataScope`, `AuthorizationContext`, and `ControlEffectiveness` models;
  - source-bound, value-minimized `OperationEvidence`;
  - immutable `OperationContext` and `OperationContextSet` models;
  - deterministic Evidence IDs and canonical context SHA-256;
  - deterministic JSON encoding and Schema export.
- `schemas/risk/operation-context.schema.json`
- `docs/decisions/0115-operation-context-contract.md`
- public exports in `agentsec.risk` and `agentsec.api`;
- version/provenance registration for `OPERATION_CONTEXT_SCHEMA_VERSION`;
- release Schema exporter wiring and Schema ownership documentation;
- `tests/test_operation_context.py`.

## Authority boundary

The contract is evidence input only. `runtime_verified=false`,
`runtime_authority=false`, and report-only behavior are literal contract
values. RISK-01 does not calculate Severity/Risk Score, execute source content,
call an LLM/Provider, or grant a tool permission.

## Validation highlights

- `complete` rejects unknown primary context dimensions;
- `needs_context`/`unknown` require an unknown primary dimension;
- Evidence paths are relative and Evidence IDs bind to source metadata;
- approval state fields reject contradictory combinations;
- operation and Evidence records are deterministic and sorted/unique;
- raw source text and secret values are not part of the contract.

## Verification

```text
RISK-01 tests: 11 passed
Provenance/version tests: 27 passed
Ruff check: passed
Ruff format check: passed
Mypy strict (affected modules): passed
Schema exporter: passed
```

## Deferred to later tasks

- RISK-02: Homi template/latent/active classification;
- RISK-03: Operation Context extraction from Adapter/Manifest evidence;
- RISK-04: context-aware deterministic Rules;
- RISK-05: residual and drift risk scoring.
