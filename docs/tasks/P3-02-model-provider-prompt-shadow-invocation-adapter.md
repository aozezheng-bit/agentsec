# P3-02: Model Provider / Prompt / Shadow Invocation Adapter

- Status: Complete
- Date: 2026-08-26
- Depends on: P3-01
- ADR: `docs/decisions/0083-offline-provider-prompt-shadow-invocation-adapter.md`
- Mode: Shadow-only, offline fixture replay

## Objective

LLM output is candidate evidence only.

No live Provider is enabled.

Implement the first complete semantic invocation path without adding a live
Provider, SDK, credential, network transport, billing, or policy authority.

## Delivered source

```text
src/agentsec/semantic/prompt.py
src/agentsec/semantic/provider.py
src/agentsec/semantic/invocation.py
src/agentsec/semantic/schema.py
src/agentsec/semantic/__init__.py
src/agentsec/api.py
src/agentsec/provenance.py
scripts/export_release_schemas.py
scripts/verify-package-hardening.py
```

## Delivered Schemas

```text
schemas/semantic-analysis/semantic-prompt-envelope.schema.json
schemas/semantic-analysis/semantic-provider-request.schema.json
schemas/semantic-analysis/semantic-provider-response.schema.json
schemas/semantic-analysis/semantic-shadow-invocation-result.schema.json
```

## Delivered tests

```text
tests/test_semantic_invocation.py
tests/test_semantic_contract.py
tests/test_provenance_registry.py
tests/test_package_hardening.py
tests/test_current_docs.py
```

## Implemented behavior

- fixed Prompt version and trusted instruction channel;
- canonical untrusted data channel containing only P3-01 semantic input;
- exact Model Output Schema binding;
- deterministic Prompt and Provider request IDs;
- approved offline Provider/Model identities;
- no-tool/no-write/no-network/no-billing Provider capability declaration;
- bounded input/output character, token, timeout, attempt, fallback, and cost
  policy;
- input-budget validation before invocation;
- Provider exception isolation and stable error codes;
- response identity, completion, output, token, cost, and timeout validation;
- P3-01 strict output validation and Candidate Evidence generation;
- deterministic offline replay;
- final Shadow Invocation identity and tamper validation;
- no raw Prompt/response retention in the final result;
- frozen Schema export and central provenance ownership;
- public package API and package-hardening smoke coverage.

## Authority boundary

```text
operating_mode          shadow_only
candidate_evidence_only true
report_only             true
runtime_verified        false
blocks                  false
policy_authority        false
raw_payloads_retained   false
```

## Explicit non-goals

```text
live model Provider
LLM SDK dependency
API credential or environment-secret loading
network transport
external endpoint configuration
billable invocation
retry or model fallback
semantic CLI command
semantic Finding/Rule publication
CI or Policy influence
Hard Gate or Waiver authority
runtime attestation
model-quality acceptance claim
```

## Verification

Completion verification executed on 2026-08-26:

```text
Semantic Invocation tests                      13 passed
Focused semantic/provenance/docs/package tests 50 passed
Ruff check                                     pass
Ruff format                                    pass; 1023 files
Strict configured Mypy                         pass; 302 source files
Full Pytest                                    1332 passed
Package hardening                              pass
Reproducible Wheel/sdist                       byte_identical=true
Wheel SHA-256                                  eb62300571a898e63d80339dd0e337f9007d36cdfd050cd9e5f736378539a808
sdist SHA-256                                  external final build output (not embedded)
Artifact signature                             not_claimed
SLSA provenance                                not_claimed
```

## Limitations

- Only the approved in-memory fixture Provider is enabled.
- The outer synchronous timeout cannot terminate a non-returning implementation;
  this is acceptable only for the offline fixture boundary.
- Token counts are Provider-supplied operational metadata.
- No real-model Precision/Recall, hallucination, latency, cost, or retention
  evidence is produced.
- No CLI or report command calls the Adapter.

## Next task

```text
P3-03: Live Provider Shadow Trial / Semantic Evaluation Harness
```
