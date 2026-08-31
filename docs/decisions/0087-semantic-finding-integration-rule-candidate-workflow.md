# ADR-0087: Semantic Finding Integration and Rule Candidate Workflow

- Status: Accepted
- Date: 2026-08-31
- Task: P3-06
- Scope: Shadow-only semantic candidate triage and deterministic Rule proposal intake

## Context

P3-01 through P3-05 establish a strict semantic contract, Provider seam,
Shadow invocation/evaluation, and controlled Provider promotion. A semantic
candidate is useful for triage, but it must not become an actionable Finding or
an automatically published Rule. Directly trusting model-supplied Finding IDs,
paths, line numbers, Severity, or Rule families would create a spoofing and
authority-escape path.

## Decision

Implement two immutable, report-only contracts:

- `SemanticFindingIntegrationReport` `0.1.0`;
- `SemanticRuleCandidateReport` `0.1.0`.

### Finding integration

The integrator receives the semantic result, existing deterministic Findings,
and the trusted `SemanticEvidenceChunk` set. It compares only trusted data:

```text
normalized asset path
asset SHA-256 == Finding content SHA-256
line-range overlap
Finding category == candidate category
static file/diff evidence source
```

Exact locator equality is `duplicates`; overlapping evidence is `supports`;
a `not_supported` semantic candidate is a report-only `contradicts` signal. Any
missing or non-matching evidence becomes `unmatched`. Integration never creates,
updates, deletes, re-scores, re-confidences, or gates a Finding.

### Rule candidates

A finite, trusted category-to-family mapping supplies the proposal family. The
candidate ID and proposal ID are content-addressed and deterministic. Proposals
start in `review_required`; explicit human review may mark them
`accepted_for_implementation` or `rejected`. Reviewer identity is retained.
No workflow method publishes or mutates a Rule Pack.

## Authority boundary

The following are immutable or fixed false:

```text
finding_authority=false
severity_authority=false
policy_authority=false
ci_authority=false
automatic_publication=false
deterministic_rule_authority=false
```

Semantic output remains candidate evidence only. Deterministic Rules and
reviewed Policy retain all authorization authority.

## Consequences

Positive:

- semantic triage can point engineers to an existing Finding without trusting
  model-authored source locations;
- exact Evidence binding is reproducible and explainable;
- Rule discovery is useful without silently changing the production Rule Pack;
- duplicate and contradiction signals remain visible for later human review.

Trade-offs:

- callers that do not provide the trusted Evidence chunks receive `unmatched`;
- static overlap cannot prove runtime behavior;
- accepting a proposal is an engineering queue transition, not a security
  decision;
- adding new semantic categories requires a trusted mapping change and review.

## Rejected alternatives

- Let the model return a Finding ID or source location: rejected because it is
  spoofable and can bind a candidate to unrelated evidence.
- Convert every semantic candidate directly to a Finding: rejected because this
  would bypass deterministic Rule validation and severity/confidence policy.
- Generate a Rule Pack entry automatically: rejected because model output is not
  a reviewed, tested, versioned deterministic Rule.
- Use semantic output in `--fail-on` or Policy: rejected because Shadow output
  has no CI or authorization authority.
