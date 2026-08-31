# ADR-0090: Trusted Semantic Input Builder and Semantic Analyze CLI

- Status: Accepted
- Date: 2026-08-31
- Task: P3-09
- Scope: End-to-end developer entry point for Phase 3 Shadow-only semantic analysis

## Context

P3-01 through P3-08 provide typed semantic contracts and an aggregate Shadow
Pipeline, but callers still need to construct trusted input and compose the
pipeline manually. A CLI that accepts raw source or trusts model locations would
bypass the established trust boundary.

## Decision

Add `TrustedSemanticInputBuilder` and `agentsec semantic analyze PROJECT`.

The builder consumes:

- bounded Framework Adapter inspection records;
- deterministic Agent Manifest state;
- authoritative asset hashes and parser line ranges;
- deterministic Coverage and Unknowns.

It emits only sanitized, bounded `SemanticAnalysisInput` Evidence. The CLI then
runs `SemanticShadowPipeline` and emits Text or JSON through the hardened
`ReportArtifactWriter`.

Offline fixture mode is the default. A bounded, strict `SemanticModelOutput`
fixture may be supplied for deterministic local demonstrations. Live HTTPS mode
requires all of:

```text
--provider live_https
--allow-live
HTTPS endpoint
credential environment-variable name
Provider ID
Model ID
approved Provider/Model binding
```

## Authority boundary

```text
report_only=true
finding_authority=false
rule_publication_authority=false
policy_authority=false
ci_authority=false
runtime_verified=false
blocks=false
```

The command does not add semantic output to `--fail-on`, Organization Policy,
Hard Gates, or CI decisions.

## Consequences

Positive:

- developers can run the complete Shadow chain with one CLI command;
- default local execution is offline and reproducible;
- model input is derived from trusted deterministic source records;
- report artifacts receive the same safe overwrite and schema validation as other
  AgentSec outputs.

Trade-offs:

- the default offline fixture emits no candidates unless a bounded response
  fixture is supplied;
- the CLI currently performs Framework inspection and Manifest analysis as
  separate deterministic operations;
- live Provider quality, retention, residency, cost, and cancellation remain
  governed by P3-03/P3-05 and are not solved by the CLI.

## Rejected alternatives

- Accept raw source text directly on the command line: rejected because it
  bypasses trusted source provenance and sanitization.
- Enable live model calls by default: rejected because it would add network,
  credential, cost, and retention risk.
- Let semantic results affect CI: rejected because LLM output remains candidate
  evidence only.
