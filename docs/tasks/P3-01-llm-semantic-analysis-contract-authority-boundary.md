# P3-01: LLM Semantic Analysis Contract / Authority Boundary

- Status: Complete
- Date: 2026-08-26
- Depends on: P2-EXIT-08A `ready_for_candidate`
- ADR: `docs/decisions/0082-llm-semantic-analysis-contract-authority-boundary.md`
- Mode: Shadow-only

## Objective

Create the strict data and authority seam required before any LLM Provider,
Model, Prompt, SDK, transport, credential, or network invocation is integrated.
LLM output is candidate evidence only. Deterministic Rules and reviewed Policy
retain all decision and CI authority.

## Delivered interfaces

```text
SEMANTIC_ANALYZER_VERSION             0.1.0
SEMANTIC_INPUT_SCHEMA_VERSION         0.1.0
SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION  0.1.0
SEMANTIC_OUTPUT_SCHEMA_VERSION        0.1.0
```

Reserved and unconfigured:

```text
SEMANTIC_MODEL_PROVIDER_ID
SEMANTIC_MODEL_ID
SEMANTIC_PROMPT_VERSION
RULE_CANDIDATE_WORKFLOW_VERSION
ATTACK_GRAPH_VERSION
RUNTIME_ATTESTATION_VERSION
```

## Delivered files

```text
src/agentsec/semantic/__init__.py
src/agentsec/semantic/models.py
src/agentsec/semantic/contract.py
src/agentsec/semantic/schema.py
src/agentsec/api.py
src/agentsec/provenance.py
schemas/semantic-analysis/semantic-analysis-input.schema.json
schemas/semantic-analysis/semantic-model-output.schema.json
schemas/semantic-analysis/semantic-analysis-result.schema.json
scripts/export_release_schemas.py
scripts/verify-package-hardening.py
tests/test_semantic_contract.py
tests/test_provenance_registry.py
tests/test_package_hardening.py
tests/test_current_docs.py
docs/semantic-analysis-contract.md
docs/threat-model.md
docs/current-architecture.md
docs/current-release-status.md
schemas/README.md
README.md
CHANGELOG.md
```

## Implemented behavior

- bounded sanitized Evidence input;
- project-relative source paths, authoritative Asset SHA-256, line ranges, and
  opaque recomputable Evidence IDs;
- shared secret redaction plus URL, email, IP, newline, and control minimization;
- explicit `content_role=untrusted_evidence` and
  `instruction_authority=false`;
- strict untrusted model-output Schema with unknown-field rejection;
- opaque Evidence references only in model output;
- no model-owned source location, Severity, score, Confidence, Allow/Block,
  Waiver, Rule publication, Hard Gate, or runtime-proof fields;
- deterministic Input/output hashes and semantic candidate IDs;
- trusted Evidence Confidence `C` and method `llm_semantic_analysis` assignment;
- deterministic Finding/Capability/Unknown context preservation;
- complete/partial Coverage derivation that cannot be upgraded by zero
  candidates or omitted Evidence;
- fixed report-only, runtime-unverified, non-blocking result;
- immutable no-tools/no-write/no-network Authority Boundary;
- frozen Schema export and package/provenance ownership integration.

## Authority Boundary

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

The boundary is represented with literal Schema constraints and cannot be
changed by model text, Provider metadata, or candidate content.

## Explicit non-goals

```text
Provider or Model selection
Prompt implementation
LLM SDK dependency
network transport or credential configuration
real model invocation
semantic CLI command
semantic candidate promotion to Finding
automatic Rule publication
Attack Graph
runtime attestation
LLM-driven CI blocking or Hard Gate
Waiver approval
Severity or Confidence downgrade
model-quality or cost evaluation
```

There is no real model invocation in P3-01.

## Verification

Completion verification executed on 2026-08-26:

```text
Focused semantic/provenance/package/docs tests  36 passed
Ruff check                                      pass
Ruff format                                     pass; 1013 files
Strict configured Mypy                         pass; 298 source files
Full Pytest                                     1318 passed
Package hardening                              pass
Reproducible Wheel/sdist                       byte_identical=true
Wheel SHA-256                                   161d9d7a13ef42b770bac3646fdb89b4252dd0433612b83b76e98877ae59b7ff
sdist SHA-256                                   external final build output (not embedded)
Artifact signature                              not_claimed
SLSA provenance                                 not_claimed
```

## Limitations

- The contract proves authority isolation and deterministic binding, not model
  semantic quality.
- No live Provider security, retention, residency, timeout, token, cost, retry,
  or fallback behavior is evaluated.
- Sanitization recognizes the current shared secret patterns and selected
  location classes; novel sensitive formats remain a residual risk.
- Confidence `C` is a fixed trusted method grade and is not runtime attestation.
- Semantic candidates do not enter Policy, CI, release, or production Rule
  publication paths.

## Next task

```text
P3-02: Model Provider / Prompt / Shadow Invocation Adapter
```

P3-02 must consume the P3-01 contracts unchanged, remain Shadow-only, and add
Provider isolation, request construction, bounded invocation controls, offline
fixture replay, and evaluation hooks without acquiring policy authority.
