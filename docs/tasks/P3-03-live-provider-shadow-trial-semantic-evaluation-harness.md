# P3-03: Live Provider Shadow Trial / Semantic Evaluation Harness

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-01, P3-02
- ADR: `docs/decisions/0084-live-provider-shadow-trial-semantic-evaluation.md`
- Mode: Shadow-only; live transport opt-in only

## Objective

Add a controlled live Provider seam and a deterministic semantic-quality
Evaluation Harness without giving LLM output any Policy, CI, Gate, Rule,
Waiver, runtime, or release authority.

## Delivered source

```text
src/agentsec/semantic/live.py
src/agentsec/semantic/evaluation.py
src/agentsec/semantic/invocation.py
src/agentsec/semantic/provider.py
src/agentsec/semantic/schema.py
src/agentsec/semantic/__init__.py
src/agentsec/api.py
src/agentsec/provenance.py
scripts/export_release_schemas.py
```

## Delivered Schema

```text
schemas/semantic-analysis/semantic-evaluation-report.schema.json
```

P3-03 also extends the P3-02 Provider metadata contract with explicit
`https_json` transport and separate `transport_network_access` state.

## Delivered tests

```text
tests/test_semantic_p3_03.py
tests/test_semantic_invocation.py
tests/test_provenance_registry.py
tests/test_current_docs.py
```

## Implemented behavior

- HTTPS-only live Provider configuration;
- no endpoint userinfo credentials;
- credential environment-name validation;
- credential lookup only at transport boundary;
- no credential in config, result, error, or evaluation report;
- explicit `allow_live_provider=true` plus exact approved Provider/Model
  binding requirement;
- injected transport for deterministic tests;
- bounded stdlib HTTPS JSON transport;
- no redirects and no inherited proxy use;
- bounded response bytes and timeout;
- separate model network-tool authority from transport network access;
- unchanged P3-01/P3-02 Prompt, Evidence, and output validation;
- `shadow_provider` invocation provenance for live transport;
- labeled `SemanticEvaluationCase` and `SemanticEvaluationHarness`;
- TP/FP/FN, Precision/Recall/F1, Evidence Binding Accuracy, Coverage Rate,
  invocation failure and safe error reporting;
- value-free evaluation report with no Policy or release authority;
- Chinese/English/mixed language labels in the evaluation contract;
- frozen evaluation Schema, provenance ownership, package API, and hardening
  coverage.

## Authority boundary

```text
operating_mode          shadow_only
candidate_evidence_only true
report_only             true
runtime_verified        false
blocks                  false
policy_authority        false
release_authority       false
raw_payloads_retained   false
```

## Explicit non-goals

```text
Provider-specific SDK or production API contract
Default network or credential behavior
Credential storage or secret manager integration
Automatic retry or fallback
Semantic Finding/Rule publication
Policy/CI/Hard Gate/Waiver authority
Runtime verification or exploitability proof
Provider promotion or quality acceptance
Trial CLI and production deployment
```

## Verification

Completion verification on 2026-08-31:

```text
P3-03 live/evaluation tests                  6 passed
Combined semantic regression tests            57 passed
Ruff check                                    pass
Ruff format                                   pass; 1031 files
Strict configured Mypy                        pass; 305 source files
Full Pytest                                   1339 passed
Package hardening                             pass
Reproducible Wheel/sdist                      byte_identical=true
Wheel SHA-256                                 external final build output (not embedded)
sdist SHA-256                                 external final build output (not embedded)
Artifact signature                            not_claimed
SLSA provenance                               not_claimed
```

## Limitations

- No endpoint, credential, or live Provider is configured in the repository.
- Tests inject a transport and perform no network I/O.
- The generic transport expects an `output_json` response envelope; a real
  Provider requires a separate reviewed adapter.
- Outer synchronous timeout cannot terminate a non-returning Provider.
- No quality threshold or Provider promotion decision is made.

## Next task

```text
P3-04: Provider-Specific Adapter, Offline/Live Parity, and Semantic Trial CLI
```
