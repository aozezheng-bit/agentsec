# P3-03 Live Provider Shadow Trial / Semantic Evaluation Harness

- Task: `P3-03`
- Status: Complete
- Date: 2026-08-31
- Mode: `shadow_only`
- Live Provider: opt-in only; no endpoint or credential is configured in the repository
- ADR: `docs/decisions/0084-live-provider-shadow-trial-semantic-evaluation.md`

## 1. Purpose

P3-03 adds the controlled seam for trying a real semantic Provider without
allowing model output to influence security decisions. It also adds a labeled
Evaluation Harness to measure semantic quality and Evidence binding before any
Provider can be considered for production use.

The implementation has two deliberately separate paths:

```text
Offline Fixture Provider → replay/evaluation
Explicit HTTPS Live Provider + env credential → Shadow trial/evaluation
```

Both paths end in the unchanged P3-01/P3-02 contract chain. Neither path can
Allow, Block, change Severity, lower Evidence Confidence, approve a Waiver,
publish a Rule, or authorize a release.

LLM output is candidate evidence only.

## 2. Live Provider boundary

`LiveSemanticProviderConfig` contains only non-secret configuration:

```text
endpoint_url
credential_env
provider_id
model_id
timeout_ms
max_response_bytes
user_agent
```

Rules:

- endpoint must be HTTPS;
- endpoint cannot contain userinfo credentials;
- credential is referenced by an uppercase environment-variable name only;
- credential value is read only at the transport boundary;
- credential values are never stored in config, response models, reports, or
  error strings;
- live invocation is impossible unless the caller explicitly sets
  `allow_live_provider=true` **and** supplies an exact trusted
  `(provider_id, model_id)` binding in `approved_live_bindings`;
- no live Provider is instantiated by default;
- no live endpoint, credential name, or Provider selection is checked in.

The built-in stdlib transport sends one POST request with:

- trusted fixed System Prompt;
- canonical sanitized P3-01 Data Channel;
- exact Model Output Schema;
- analysis/model identifiers.

The transport uses HTTPS, disables inherited proxy use, rejects redirects, sets
a bounded timeout, bounds response bytes, and accepts only a JSON response with
`output_json`, `input_tokens`, and `output_tokens` fields. The actual model
response is immediately passed to the P3-01 validator and is not retained in the
final report.

The model itself has no AgentSec Tools, filesystem-write, network-tool, Skill,
Hook, MCP, runtime identity, Policy, or release authority. Transport network
access is recorded separately from model tool network access.

## 3. Shadow trial rules

A trial is Shadow-only when all of the following hold:

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

A Provider must also satisfy:

- explicit Provider/Model allow-list selection by trusted caller configuration;
- structured output support;
- timeout enforcement declaration;
- no model Tool, filesystem-write, or model-network capability;
- no automatic retry or fallback;
- zero configured billing budget in the current implementation;
- request/response raw-payload retention disabled.

The synchronous Adapter performs an outer elapsed-time check, but it cannot
terminate an uncooperative Python Provider after the call has started. A live
transport therefore must enforce cancellation/deadlines internally as well.
This is a release blocker for any production Provider integration.

## 4. Evaluation Harness

`SemanticEvaluationHarness` consumes labeled
`SemanticEvaluationCase` values. Each case contains:

- a stable case/Analysis ID;
- language label (`zh`, `en`, or `mixed`);
- the same bounded `SemanticAnalysisInput` that enters the Provider;
- reviewer-provided expected semantic judgments;
- opaque expected Evidence IDs.

The Harness runs cases through a `SemanticShadowInvocationAdapter` and emits
only bounded, value-free results.

### 4.1 Metrics

The report calculates:

```text
TP / FP / FN
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 × Precision × Recall / (Precision + Recall)
Evidence Binding Accuracy
Complete Coverage Rate
Invocation success / failure counts
```

Semantic matching compares the bounded triple:

```text
(kind, category, disposition)
```

Evidence Binding Accuracy separately compares the exact ordered opaque Evidence
ID tuple for semantically matched judgments. This keeps model semantic quality
separate from Evidence provenance quality.

Failures are recorded by stable safe error code. Raw Provider errors, Prompt,
source text, endpoint, credentials, and model output are not copied into the
report.

### 4.2 Report authority

`semantic-evaluation-report.schema.json` fixes:

```text
report_only          true
policy_authority     false
release_authority    false
runtime_verified     false
```

The report is an evaluation artifact, not a qualification report. It cannot
promote a Provider, qualify a Gate, change a Rule, or enable CI blocking.

## 5. Running an offline evaluation

Use the Python API:

```python
from agentsec.semantic import (
    SemanticEvaluationHarness,
    SemanticShadowInvocationAdapter,
    OfflineFixtureSemanticProvider,
)

# Build labeled SemanticEvaluationCase values from sanitized contract inputs.
report = SemanticEvaluationHarness().evaluate(
    cases,
    SemanticShadowInvocationAdapter(
        provider=OfflineFixtureSemanticProvider(output=model_output)
    ),
)
```

Offline replay is the required first step because it verifies Prompt/data
separation, contract validation, metric calculations, and report reproducibility
without credentials or network activity.

## 6. Running an opt-in Live Shadow trial

A caller must construct the live Provider explicitly in protected runtime code:

```python
from agentsec.semantic import (
    LiveSemanticProvider,
    LiveSemanticProviderConfig,
    SemanticShadowInvocationAdapter,
)

provider = LiveSemanticProvider(
    LiveSemanticProviderConfig(
        endpoint_url="https://approved.example.invalid/semantic",
        credential_env="AGENTSEC_PROVIDER_TOKEN",
        provider_id="approved-shadow-provider",
        model_id="approved-shadow-model",
    )
)
adapter = SemanticShadowInvocationAdapter(
    provider=provider,
    allow_live_provider=True,
    approved_live_bindings=(("approved-shadow-provider", "approved-shadow-model"),),
)
```

The example endpoint is deliberately non-routable documentation text. The
repository does not configure or call it.

Before a real trial, the operator must independently approve:

- Provider and Model identity;
- endpoint ownership and TLS validation;
- credential scope and secret-manager injection;
- data residency and retention terms;
- provider-side logging/training behavior;
- transport cancellation and response-size limits;
- request rate, concurrency, and cost budgets;
- Chinese/English handling;
- offline replay parity;
- reviewer-approved semantic evaluation set.

The current code does not claim that these organizational approvals exist.

## 7. Minimum release-quality evaluation evidence

P3-03 provides the measurement mechanism, not a quality acceptance claim. A
future Provider trial should publish at least:

- separate Chinese, English, and mixed-language slices;
- positive, negative, and near-miss cases;
- semantic Precision/Recall/F1;
- exact Evidence binding accuracy;
- complete/partial Coverage and omission counts;
- Provider failure, timeout, truncation, filtering, and budget counts;
- repeatability across identical input and Prompt versions;
- hallucinated authority-field rejection counts;
- secret/location/control-character rejection counts;
- reviewer adjudication and confidence notes.

No metric threshold is promoted into CI or Policy by this task. Any future
threshold or Provider promotion requires a separate reviewed ADR and release
state transition.

## 8. Current limitations

- The repository contains no live endpoint or credential configuration.
- No network call is executed by tests or default CLI paths.
- The stdlib transport assumes a Provider-specific response envelope with
  `output_json`; a production Provider adapter must document and test its exact
  API contract before use.
- The outer synchronous timeout cannot stop a non-returning Provider; the live
  transport must implement deadline cancellation.
- Token counts and zero cost are operational metadata, not security evidence.
- No semantic candidate is published as a Finding or Rule.
- No runtime verification, exploitability proof, Hard Gate qualification, CI
  block, Waiver, or release approval is possible.

## 9. Next task

```text
P3-04: Provider-Specific Adapter, Offline/Live Parity, and Semantic Trial CLI
```

P3-04 is complete: the provider-specific structured JSON adapter, protected
trial configuration, Offline/Live parity, and `agentsec semantic trial` CLI are
available while preserving the Shadow-only boundary. The next task is P3-05.
