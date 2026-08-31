# ADR-0084: Live Provider Shadow Trial and Semantic Evaluation Harness

- Status: Accepted
- Date: 2026-08-31
- Task: P3-03
- Scope: opt-in HTTPS Shadow transport and value-free semantic evaluation

## Context

P3-01 defines the semantic Authority Boundary. P3-02 provides Prompt/data
separation, offline Provider replay, and bounded invocation contracts. The next
risk is connecting a real Provider: credentials, endpoints, network transport,
retention, cost, timeout, output envelopes, and model quality must be controlled
before any semantic output is observed in a production-like trial.

## Decision

Implement:

1. an explicit `LiveSemanticProviderConfig` containing no credential values;
2. a `LiveSemanticProvider` using an injected transport or a bounded stdlib
   HTTPS JSON transport;
3. explicit `allow_live_provider=true` opt-in plus an exact trusted
   `(provider_id, model_id)` binding in the existing Shadow Adapter;
4. HTTPS-only endpoint validation without endpoint credentials;
5. environment-variable credential lookup only at the transport boundary;
6. no redirect and no inherited proxy behavior in the default transport;
7. bounded response bytes and timeout;
8. no raw request/response retention in final artifacts;
9. a labeled `SemanticEvaluationHarness` with Precision/Recall/F1, Evidence
   Binding Accuracy, Coverage, and safe failure metrics;
10. strict evaluation report authority flags fixed to report-only/no-release.

The Provider remains Shadow-only. Its transport may use network access, but the
model has no Tools, filesystem-write, MCP, Skill, Hook, or model-network
authority. Deterministic Rules and reviewed Policy remain the only decision
authority.

## Explicit non-goals

```text
Provider-specific production SDK
Provider promotion or quality acceptance
semantic Finding publication
Rule publication
Hard Gate or CI authority
runtime attestation
credential storage or secret-manager integration
automatic retries or fallback
production release approval
```

## Security trade-offs

- The default stdlib transport is generic and requires a Provider-specific JSON
  envelope; production use needs a separate reviewed adapter.
- Outer synchronous timeout cannot terminate a non-returning implementation;
  transport-owned cancellation is required before release use.
- Environment credentials reduce config leakage but rely on the caller's secret
  injection and process isolation.
- Evaluation metrics are evidence for review, not enforcement thresholds.

## Rejected alternatives

- **Invoke a model from default scan:** would silently add network/credential
  behavior and violate the no-network default.
- **Store API keys in a config artifact:** increases disclosure and artifact
  substitution risk.
- **Let live output bypass P3-01:** allows model output to become authority.
- **Use model-reported scores or Confidence:** conflicts with P3-01 boundary.
- **Declare a Provider qualified from one trial:** confuses quality evidence with
  authorization and requires separate review/release state.
