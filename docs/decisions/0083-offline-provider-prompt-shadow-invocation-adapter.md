# ADR-0083: Offline Provider, Prompt, and Shadow Invocation Adapter

- Status: Accepted
- Date: 2026-08-26
- Task: P3-02
- Scope: deterministic offline fixture replay; no live Provider transport

## Context

P3-01 established the semantic input/model-output/result contracts and an
immutable no-authority boundary. It intentionally did not define how trusted
input becomes Provider channels, how Provider identity and capabilities are
approved, how timeout/token/cost limits are represented, or how one invocation
is replayed and bound to the P3-01 validator.

Introducing a live SDK or network transport at the same time as those controls
would make Provider behavior, prompt construction, data retention, and semantic
quality difficult to separate. AgentSec therefore needs an offline invocation
stage before any live model trial.

## Decision

P3-02 activates only one Provider and Model identity:

```text
SEMANTIC_MODEL_PROVIDER_ID  offline-fixture
SEMANTIC_MODEL_ID           agentsec-semantic-fixture-v1
```

They identify an in-memory deterministic replay fixture, not an external model
service. No SDK, API credential, endpoint, network connection, or billable
invocation is added.

### Prompt envelope

Use a versioned `SemanticPromptEnvelope` with physically separate channels:

- a fixed trusted system channel owned by AgentSec;
- canonical `SemanticAnalysisInput` JSON in the untrusted data channel;
- the exact constrained `SemanticModelOutput` JSON Schema;
- recomputable Input, system-prompt, output-Schema, and complete Prompt hashes.

Scanned content can appear only in the data channel and remains bounded,
sanitary, `instruction_authority=false` Evidence from P3-01.

### Provider contract

A `SemanticModelProvider` Protocol exposes only:

- fixed capability metadata;
- one synchronous bounded `invoke` method.

P3-02 accepts only metadata declaring:

```text
transport                    in_memory_fixture
structured_output_supported true
timeout_enforced             true
model_tools_enabled          false
model_filesystem_write       false
model_network_access         false
billable_invocation          false
raw_request_retained         false
raw_response_retained        false
```

Any different Provider/Model identity or capability declaration fails before
invocation.

### Invocation limits

Each invocation carries trusted limits for:

- total Provider input characters;
- Provider output characters;
- input/output tokens;
- elapsed timeout;
- cost, fixed to zero;
- one attempt only;
- no fallback.

Input size is checked before Provider invocation. Output size, tokens, cost,
completion state, request identity, Provider identity, and observed elapsed time
are checked before P3-01 contract validation.

The synchronous Adapter cannot terminate an arbitrary blocking implementation.
That limitation is acceptable only because P3-02 approves the in-memory fixture
Provider. A future live Provider Adapter must enforce its deadline inside the
transport as well as through the outer elapsed-time check.

### Shadow invocation output

`SemanticShadowInvocationResult` stores only:

- content-addressed Prompt/request/response/invocation identities;
- approved Provider metadata;
- bounded usage counts;
- trusted limits;
- the validated P3-01 `SemanticAnalysisResult`.

It does not retain raw Provider request or response payloads. Its policy fields
are immutable:

```text
operating_mode          shadow_only
candidate_evidence_only true
report_only             true
runtime_verified        false
blocks                  false
policy_authority        false
raw_payloads_retained   false
```

## Security properties

- prompt injection remains in the untrusted data channel;
- Provider identity and capabilities are allow-listed by trusted code;
- no Tool, filesystem-write, network, Skill, Hook, MCP, or external-content
  access is enabled;
- no billable or retried invocation is possible;
- dependency exceptions are converted to stable errors without copying messages;
- malformed, secret-bearing, authority-claiming, or Evidence-forging model
  output is rejected by the P3-01 contract;
- deterministic Rules and reviewed Policy remain the only CI authority.

## Consequences

Positive:

- Provider and Prompt seams are testable without credentials or network access;
- prompt construction, Provider transport, and semantic validation are separate
  deep modules;
- offline replay is deterministic and content-addressed;
- a later live Provider must satisfy explicit capability, budget, retention, and
  contract checks.

Trade-offs:

- P3-02 does not measure real model quality, latency, cost, or availability;
- token counts are Provider-supplied usage metadata and remain non-authoritative;
- the outer timeout check cannot stop an uncooperative synchronous Provider;
- no semantic CLI command or production report integration is added.

## Rejected alternatives

- **Add a live SDK immediately:** mixes trust-boundary construction with network,
  credential, retention, and dependency review.
- **Put scanned text in the system prompt:** lets untrusted content cross the
  instruction channel.
- **Accept arbitrary Provider IDs:** bypasses the Phase 3 entry allow-list.
- **Retry or fallback automatically:** increases cost and makes replay/output
  provenance ambiguous.
- **Persist raw Prompt/response payloads:** unnecessarily retains sensitive
  source-derived data and untrusted model text.
