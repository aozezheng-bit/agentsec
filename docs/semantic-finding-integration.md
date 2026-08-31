# P3-06 Semantic Finding Integration / Rule Candidate Workflow

- Status: Complete
- Date: 2026-08-31
- Interface versions: Semantic Finding Integration `0.1.0`; Rule Candidate Workflow `0.1.0`
- Implementation: `src/agentsec/semantic/integration.py`
- Tests: `tests/test_semantic_p3_06.py`

## 1. Purpose

P3-06 connects Shadow-only semantic analysis to the deterministic result set
without allowing a model response to become a Finding, a score, a Gate, a CI
block, or a published Rule. It provides two report-only outputs:

1. **Semantic Finding Integration Report** — links semantic candidates to
   already materialized deterministic Findings when trusted Evidence proves a
   conservative relationship.
2. **Semantic Rule Candidate Report** — turns semantic candidates into bounded,
   review-required development proposals. A proposal is not a Rule Pack entry.

The workflow is useful for triage and engineering feedback while preserving the
Phase 2 authority boundary.

## 2. Deterministic Evidence association

The model only returns opaque Evidence IDs. The caller must provide the trusted
`SemanticEvidenceChunk` objects that were used to construct the semantic input
and the existing `Finding` objects. A relationship is eligible only when all of
the following hold:

- semantic and deterministic Evidence use the same normalized project-relative
  `asset_path`;
- the semantic `asset_sha256` equals the Finding Evidence
  `content_sha256`;
- the line ranges overlap;
- the Finding category equals the semantic candidate category; and
- the deterministic Evidence is file- or diff-backed, not a runtime attestation.

Exact path/hash/line equality is reported as `duplicates`. A same-file,
same-hash, overlapping-range relationship is `supports`. A `not_supported`
semantic candidate that overlaps an existing deterministic Finding is reported
as `contradicts`; it does not delete, downgrade, or alter that Finding. If
trusted Evidence is missing, unknown to the integration input, or fails any
comparison, the result is `unmatched`.

The report can contain more than one link for a candidate when multiple existing
Findings independently match. Links are sorted and unique. No excerpt or raw
source text is copied into the integration report.

## 3. Rule Candidate workflow

`SemanticRuleCandidateWorkflow.propose()` creates a content-addressed proposal
ID from the semantic result digest, candidate ID, and category. Rule family names
come from a finite trusted mapping; model text cannot create a new Rule family.
Every proposal starts as:

```text
status                      review_required
automatic_publication       false
deterministic_rule_authority false
```

An explicit reviewer may transition a proposal to
`accepted_for_implementation` or `rejected`. The reviewer identity is retained
in the proposal for auditability. These transitions mean only that engineering
review may proceed. A later implementation still requires deterministic Rule
code, positive/negative fixtures, replay tests, Rule Pack review, provenance
updates, and an explicit release process.

There is no method that publishes a Rule, mutates an installed Rule Pack, changes
Policy, activates a Hard Gate, or changes CI behavior.

## 4. Authority and threat boundaries

The following remain fixed in both reports:

```text
report_only=true
automatic_rule_publication=false
policy_authority=false
ci_authority=false
finding_authority=false
severity_authority=false
```

Semantic output cannot supply Finding IDs, Evidence paths, line numbers, hashes,
Severity, score, Evidence Confidence, runtime proof, Allow/Block, Waiver
approval, or Rule publication authority. Deterministic Findings and reviewed
Policy remain authoritative.

## 5. Example flow

```text
SemanticAnalysisInput + trusted Evidence chunks
        ↓
SemanticAnalysisContract
        ↓
SemanticAnalysisResult (candidate evidence only)
        ├── SemanticFindingIntegrator
        │       ↓
        │   report-only Finding links
        └── SemanticRuleCandidateWorkflow
                ↓
            review_required Rule proposals
                ↓ explicit human review
            accepted_for_implementation / rejected
                ↓ later deterministic engineering work
            never automatic publication
```

## 6. Known limitations

- Semantic integration is static Evidence association, not runtime reachability
  or exploitability proof.
- A semantic contradiction is a review signal, not permission to suppress a
  deterministic Finding.
- Rule proposals do not measure model quality; P3-05 Provider quality and Human
  Review remain the promotion evidence source.
- The current interface accepts the trusted Evidence chunks as a separate
  argument so model output cannot author locations. Callers must pass the exact
  chunks used for the analysis; otherwise the safe result is `unmatched`.
