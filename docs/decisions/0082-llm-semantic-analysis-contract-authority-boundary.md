# ADR-0082: LLM Semantic Analysis Contract and Authority Boundary

- Status: Accepted
- Date: 2026-08-26
- Task: P3-01
- Scope: Shadow-only semantic candidate evidence; no model integration

## Context

Phase 3 Entry Readiness is `ready_for_candidate`, so Shadow-only semantic work
may begin. The repository still has no approved LLM Provider, Model, Prompt,
transport, credential, runtime Tool, or production authority path.

Untrusted Agent files can contain prompt injection, secrets, endpoints, control
characters, self-asserted severity, fake runtime claims, and instructions to
suppress Findings. Passing raw files to a model or accepting a free-form model
response would let attacker-authored text redefine the scanner task, invent
Evidence locations, or influence Policy.

P3-01 must establish the contract before any model SDK or network client is
introduced.

## Decision

Implement four versioned interfaces:

```text
Semantic Analyzer Contract       0.1.0
Semantic Analysis Input Schema   0.1.0
Semantic Model Output Schema     0.1.0
Semantic Analysis Output Schema  0.1.0
```

Keep these Phase 3 interfaces reserved and unconfigured:

```text
Semantic Provider ID
Semantic Model ID
Semantic Prompt Version
Rule Candidate Workflow
Attack Graph
Runtime Attestation
```

### Trusted input envelope

Only a trusted deterministic builder may construct semantic input. It contains:

- bounded, project-relative Evidence locators;
- authoritative Asset SHA-256 and line ranges;
- value-minimized and control-escaped text;
- deterministic Finding IDs and Unknown dimensions;
- explicit incomplete-Coverage state;
- a fixed Shadow-only Authority Boundary.

Untrusted text is always marked `instruction_authority=false` and
`content_role=untrusted_evidence`. A model can read the text as data but cannot
change its path, hash, line range, or Evidence ID.

### Untrusted model output

The model-output Schema accepts only:

- one matching Analysis ID;
- bounded candidate rows;
- candidate kind, category, disposition, summary, limitations;
- references to opaque Evidence IDs supplied in the input;
- the Evidence IDs the model claims to have analyzed.

It has no fields for Severity, score, Confidence grade, Allow/Block, Waiver,
Rule publication, Evidence location, runtime proof, or tool action. Unknown
fields fail validation.

### Deterministic post-processing

A trusted validator:

- verifies every Evidence reference against the input;
- rejects duplicate semantic candidates and forged identifiers;
- computes Input, model-output, and candidate SHA-256 identities;
- assigns Evidence Confidence `C` and method `llm_semantic_analysis` outside the
  model response;
- preserves deterministic Finding IDs and Unknown dimensions unchanged;
- derives partial status when deterministic Coverage is incomplete or Evidence
  was omitted;
- emits a fixed report-only, runtime-unverified, non-blocking result.

### Authority Boundary

The following values are immutable literals in both input and final output:

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

No model version, Provider ID, Prompt version, candidate count, or semantic
result can grant authority.

## Security properties

- No model, SDK, network, subprocess, Tool, Skill, Hook, MCP, or filesystem-write
  integration is added in P3-01.
- Raw Agent files are not part of the contract; only bounded sanitized chunks
  are permitted.
- Secrets, URLs, email addresses, and network addresses are minimized before
  semantic input.
- Model text must already be value-minimized and free of unsafe control
  characters or validation fails.
- A zero-candidate model response cannot turn incomplete deterministic Coverage
  into a complete result.
- Deterministic Rules and reviewed Policy remain the only CI authority.

## Consequences

Positive:

- later Provider integration has a strict typed seam;
- prompt injection remains untrusted data;
- semantic candidates are traceable to deterministic Evidence;
- model output cannot silently acquire enforcement authority;
- schemas and version provenance exist before transport or credentials.

Trade-offs:

- P3-01 does not prove model quality or invoke a model;
- sanitized chunks may lose details needed for some semantic judgments;
- Evidence Confidence C describes probabilistic semantic method, not runtime
  verification;
- Provider, Prompt, evaluation corpus, cost, timeout, and retry policies remain
  later tasks.

## Rejected alternatives

- **Free-form model prose:** cannot be safely validated or bound to Evidence.
- **Let the model return source paths/lines:** allows Evidence spoofing.
- **Let the model assign Severity/Confidence:** enables attacker-driven risk
  manipulation and confidence inflation.
- **Allow Shadow output to affect `--fail-on`:** violates Phase 3 entry policy.
- **Introduce an SDK now:** Provider selection and dependency review are outside
  this contract-first task.
