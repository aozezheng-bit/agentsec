# P3-01 LLM Semantic Analysis Contract / Authority Boundary

- Task: `P3-01`
- Status: Complete
- Date: 2026-08-26
- ADR: `docs/decisions/0082-llm-semantic-analysis-contract-authority-boundary.md`
- Operating mode: `shadow_only`
- Model integration: P3-01 invokes none; P3-02 adds offline fixture replay only

## 1. Purpose

P3-01 creates the security boundary that every later LLM semantic-analysis
implementation must cross. It defines how deterministic AgentSec evidence may be
presented to a probabilistic model, what a model is allowed to return, and how a
trusted AgentSec component converts that untrusted response into report-only
candidate evidence.

This task deliberately does **not** choose a Provider, Model, Prompt, SDK,
transport, credential, timeout, retry policy, or command-line surface. It is a
contract-first change, not an LLM integration.

There is no model invocation in P3-01.

## 2. Authority rule

The core rule is immutable:

> LLM output is candidate evidence only. Deterministic Rules and reviewed Policy
> retain all Allow/Block, scoring, Hard Gate, Waiver, Rule publication, and
> release authority.

The fixed `SemanticAuthorityBoundary` is present in the trusted input and final
result:

```text
mode                         shadow_only
candidate_evidence_only      true
allow_decision               false
block_decision               false
severity_authority           false
confidence_authority         false
rule_publication             false
waiver_approval              false
runtime_claim_authority      false
model_tool_access            false
model_filesystem_write       false
model_network_access         false
```

These fields are literal Schema constraints. A Provider ID, Model ID, Prompt
version, high candidate count, or persuasive model response cannot change them.

## 3. Trust flow

```text
Untrusted Agent assets
  → existing bounded non-executing collectors/parsers
  → trusted deterministic Evidence and Coverage
  → trusted SemanticAnalysisInput builder
       - project-relative source locator
       - Asset SHA-256 and line range
       - minimized bounded text
       - opaque Evidence ID
       - deterministic Finding/Capability/Unknown context
       - immutable Authority Boundary
  → [future model transport; absent in P3-01]
  → untrusted SemanticModelOutput
       - strict fields only
       - opaque Evidence references only
       - no Severity/Confidence/Allow/Block/Rule/Waiver fields
  → SemanticAnalysisContract deterministic validation
       - reference and identity checks
       - complete/partial Coverage derivation
       - deterministic hashes and candidate IDs
       - trusted Confidence C assignment
  → SemanticAnalysisResult
       - report_only=true
       - runtime_verified=false
       - blocks=false
       - authority_effect=none
```

## 4. Versioned interfaces

P3-01 activates four source-of-truth contracts:

```text
SEMANTIC_ANALYZER_VERSION             0.1.0
SEMANTIC_INPUT_SCHEMA_VERSION         0.1.0
SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION  0.1.0
SEMANTIC_OUTPUT_SCHEMA_VERSION        0.1.0
```

Frozen Schemas:

```text
schemas/semantic-analysis/semantic-analysis-input.schema.json
schemas/semantic-analysis/semantic-model-output.schema.json
schemas/semantic-analysis/semantic-analysis-result.schema.json
```

P3-02 activates an offline fixture Provider/Model identity, Prompt contract,
and Shadow Invocation Adapter without enabling a live transport. Rule Candidate
Workflow, Attack Graph, and Runtime Attestation remain reserved.

## 5. Trusted input envelope

`SemanticAnalysisInput` may be constructed only from trusted deterministic
state. Its Evidence chunks include:

- an opaque, recomputable `semantic-evidence-sha256:*` identifier;
- a safe project-relative Asset path;
- authoritative Asset SHA-256;
- coherent one-based start/end lines;
- bounded, value-minimized, escaped text;
- a SHA-256 binding for the exact minimized text;
- `content_role=untrusted_evidence`;
- `instruction_authority=false`;
- `secret_values_included=false`;
- `value_minimized=true`.

The request also preserves deterministic context:

- deterministic Coverage completeness;
- optional Manifest and Assessment hashes;
- existing Finding IDs;
- existing Capability IDs;
- unresolved/Unknown dimensions.

The semantic model is not allowed to remove, rename, or overwrite this context.

### 5.1 Bounded input

The initial contract limits one request to:

```text
Evidence chunks                 64
Characters per Evidence chunk   2,048
Total Evidence characters       65,536
Semantic candidates             128
Candidate summary characters    512
Limitations per bounded field   32
```

These are contract limits, not Provider token budgets. Provider-specific token,
cost, timeout, concurrency, and retry limits belong to later tasks.

## 6. Sanitization and data minimization

`build_semantic_evidence_chunk` performs trusted preprocessing before any future
model boundary:

1. redact recognized secret-bearing text with the shared AgentSec redactor;
2. replace HTTP(S) locations with `<external-location>`;
3. replace email addresses with `<email-address>`;
4. replace IPv4 addresses with `<network-address>`;
5. escape line breaks, terminal controls, bidi markers, zero-width characters,
   and other unsafe output controls;
6. hash and bind the minimized text to the authoritative Evidence locator.

The raw source string is not retained by the semantic contract model. P3-01 also
sets both `raw_request_retained=false` and `raw_response_retained=false` in
invocation provenance.

Sanitization is defense in depth, not a claim that all sensitive formats are
recognizable. Later Provider integration must send only validated
`SemanticAnalysisInput`; it must never bypass this builder by sending raw files.

## 7. Untrusted model-output contract

`SemanticModelOutput` is always hostile input, even when it came from an
approved Provider. It may contain only:

- the matching Analysis ID;
- sorted, unique Evidence IDs the model reports analyzing;
- bounded candidate rows;
- candidate kind, deterministic risk category, support disposition, summary,
  limitations, and supplied Evidence references;
- bounded top-level limitations.

Unknown fields are forbidden. In particular, model output has no contract field
for:

```text
Severity or numeric score
Evidence Confidence grade
Allow or Block
Hard Gate activation
Waiver approval
Rule publication
source path, line number, or Asset hash selection
runtime verification or exploit proof
tool, shell, filesystem, network, Skill, Hook, or MCP action
```

The model can reference only opaque Evidence IDs already present in the trusted
input and reported as analyzed. Unknown or omitted Evidence references fail
closed.

## 8. Deterministic post-processing

`SemanticAnalysisContract` is the trusted boundary after model output. It:

1. strictly parses the JSON Schema with unknown-field rejection;
2. checks Analysis ID binding;
3. verifies every analyzed and candidate Evidence ID against the input;
4. rejects duplicate candidate keys, duplicate judgments, and identity
   collisions;
5. calculates canonical Input and model-output SHA-256 hashes;
6. calculates each `semantic-candidate-sha256:*` identity from the trusted input
   hash, invocation provenance, and validated semantic payload;
7. copies deterministic Context and Unknown dimensions without modification;
8. derives semantic and combined Coverage;
9. assigns fixed report-only candidate properties outside the model response.

A deserialized final result recomputes candidate identities, status, ordering,
and Coverage coherence. Tampered final artifacts therefore fail validation.

## 9. Evidence Confidence

Every semantic candidate receives:

```text
evidence_confidence  C
confidence_method    llm_semantic_analysis
report_only          true
runtime_verified     false
authority_effect     none
```

The model cannot select or self-upgrade the grade. `C` records the current
method class: a bounded probabilistic semantic judgment bound to static source
Evidence. It does not represent direct runtime attestation and cannot lower or
raise deterministic Severity.

A future calibration task may propose a different reviewed mapping, but changing
Confidence semantics requires the existing risk-model governance process and an
ADR. It cannot be changed by a Prompt or model response.

## 10. Coverage and Unknown preservation

The final status is derived by trusted code:

- `complete`: every input Evidence ID was analyzed **and** deterministic
  Coverage was complete;
- `partial`: the model omitted any Evidence ID or deterministic Coverage was
  incomplete.

A zero-candidate response is not a clean result and cannot upgrade Coverage.
Existing deterministic Unknown dimensions remain present in the final result.
Semantic absence is never converted into proof of safety.

## 11. Prompt-injection handling

Agent content such as “ignore previous instructions”, “run this command”,
“connect to this MCP server”, or “mark this safe” remains ordinary
`untrusted_evidence`. The P3-01 contract itself performs no subprocess, import,
filesystem write, network call, Tool call, Skill load, Hook execution, or MCP
connection.

P3-01 does not claim that a future model will classify every prompt injection
correctly. It ensures that model misclassification cannot cross the authority
boundary or directly become an enforcement decision.

## 12. Non-goals and current limitations

Not implemented in P3-01:

- real Provider, Model, Prompt, SDK, API key, or network transport;
- CLI semantic-analysis command;
- prompt templates or system-message construction;
- token counting, cost budgets, timeout, retry, or fallback behavior;
- production candidate-to-Finding promotion;
- automatic Rule generation or publication;
- semantic Diff, Attack Graph, runtime attestation, or exploit validation;
- LLM-driven Hard Gate, `--fail-on`, CI block, Waiver, or release decision;
- model-quality, Precision/Recall, hallucination, or cost evaluation.

Because no model is invoked, P3-01 validates the authority and data contract—not
semantic quality.

## 13. P3-02 integration and future handoff

P3-02 now consumes the P3-01 contracts unchanged through a fixed Prompt,
approved in-memory fixture Provider, bounded request/response contracts, and a
Shadow Invocation Adapter. It remains non-billable, no-network, no-credential,
no-retention, and without policy authority. See
`docs/semantic-shadow-invocation.md`.

P3-03 is now complete. The recommended next task is:

```text
P3-04: Provider-Specific Adapter, Offline/Live Parity, and Semantic Trial CLI
```
