# ADR-0089: Semantic Shadow Pipeline Integration

- Status: Accepted
- Date: 2026-08-31
- Task: P3-08
- Scope: Reusable application-layer composition of the Phase 3 Shadow contracts

## Context

P3-01 through P3-07 provide separate contracts for semantic input validation,
Provider invocation, evaluation, promotion, Finding integration, calibration,
and Rule replay. Consumers otherwise have to compose those pieces themselves,
which increases the risk of skipping a trust-boundary check or treating one
child artifact as authoritative.

## Decision

Add `SemanticShadowPipeline` and
`SemanticShadowPipelineReport` `0.1.0`. The pipeline:

1. accepts only a validated `SemanticAnalysisInput`;
2. invokes the supplied `SemanticShadowInvocationAdapter`;
3. integrates the resulting candidates with pre-existing Findings through the
   P3-06 trusted Evidence matcher;
4. creates review-required Rule Candidate proposals through the P3-06 workflow;
5. emits one content-addressed, strict, report-only aggregate.

The pipeline does not load project paths, execute target code, publish Rules,
create Findings, modify Findings, score output, activate Gates, or affect Policy
or CI.

## Authority boundary

```text
finding_authority=false
rule_publication_authority=false
severity_authority=false
policy_authority=false
ci_authority=false
runtime_verified=false
blocks=false
```

## Consequences

Positive:

- callers receive one typed end-to-end Shadow result;
- child report hashes and authority flags are validated together;
- missing trusted Evidence remains visibly unmatched;
- the future CLI/platform adapter has a narrow integration seam.

Trade-offs:

- the pipeline does not itself construct semantic input from a project; that
  remains the responsibility of a trusted deterministic collector/builder;
- a live Provider can still require separate endpoint, credential, retention,
  cost, and cancellation review;
- the aggregate report is quality/triage evidence, not a production decision.

## Rejected alternatives

- Put semantic output directly into the deterministic assessment: rejected
  because it would bypass the authority boundary.
- Let the pipeline load and execute project files: rejected because scanned
  content is untrusted.
- Add a CLI that accepts arbitrary raw source in this task: rejected; CLI input
  trust-root and artifact-writer behavior require a separate review.
