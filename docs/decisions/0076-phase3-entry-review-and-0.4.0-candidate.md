# ADR-0076: Phase 3 Entry Review and 0.4.0 Candidate

- Status: Amended by ADR-0077; historical `0.1.0` fail-closed contract
- Date: 2026-08-25
- Depends on: ADR-0075 Package API and Supply-chain Hardening
- Scope: Phase 3 entry governance and candidate promotion; not LLM implementation
- Amendment: ADR-0077 separates entry readiness from candidate acceptance and supersedes the `0.1.0` promotion flow.

## Context

P2-EXIT-01 through P2-EXIT-07 implement the Phase 2 control plane, scoring and
report contracts, Homi pipeline, external Pilot contract, and package hardening.
Phase 3 would introduce semantic/LLM capabilities and therefore needs an
explicit Go/No-Go review before any model SDK, prompt, semantic Rule, or runtime
attestation path is added.

The current source tree remains `0.4.0.dev0`, and P2-EXIT-06 external evidence
is implementation-ready but not supplied. Promoting the version or publishing a
0.4.0 artifact before those conditions are met would create a false release
signal.

## Decision

Introduce a deterministic `agentsec-phase3-entry-review` `0.1.0` report and
require it to be Go before candidate promotion.

Required checks cover:

```text
Phase 2 task records
Package API and py.typed
Exact locks / SBOM / license evidence
Authority boundary
External Pilot evidence
Candidate version promotion
Candidate artifacts
```

Signature/provenance is tracked as an optional pending check because local
reproducibility cannot manufacture a release-system signature.

The current decision is:

```text
NO-GO
```

because external Pilot acceptance, version promotion, and candidate artifacts
are pending.

## Non-negotiable Phase 3 authority boundary

1. LLM output is candidate evidence only.
2. LLM output cannot Allow or Block.
3. LLM output cannot publish Rules automatically.
4. LLM output cannot approve Waivers.
5. LLM output cannot downgrade Severity or Evidence Confidence.
6. Runtime-unverified evidence cannot grant authority.
7. Deterministic Rules and reviewed Policy retain authorization authority.
8. CI blocking requires an explicit Policy path and qualified Gate.
9. Version promotion is a release action, never an inference from model output.

## Candidate promotion policy

The package must remain on `0.4.0.dev0` while any required check is pending or
failed. A future Go decision may explicitly promote the package to the approved
candidate/release version and then build artifacts. The review tool must not edit
`versioning.py`, create release artifacts, or publish anything automatically.

## Consequences

Positive:

- Phase 3 entry cannot be inferred from implementation completeness alone;
- missing external evidence produces an explicit No-Go rather than a silent
  exception;
- LLM authority boundaries are checked before SDK integration;
- version/artifact promotion is separated from local test success;
- the review is deterministic and reproducible in clean processes.

Trade-offs:

- the project remains on a development package version until external evidence is
  supplied;
- local signatures and hosted provenance remain a release-system responsibility;
- a human still needs to review the generated Entry Review and external Pilot
  report.

## Rejected alternatives

- **Promote to 0.4.0 because all local tests pass:** local tests do not replace
  external Pilot evidence or release review.
- **Treat implementation-ready external Pilot code as external evidence:** code
  is not a scan of a real external project and cannot establish TP/FP/FN.
- **Begin LLM integration before Go:** would allow semantic components to shape
  the security boundary before governance approval.
- **Let the review auto-edit the package version:** release promotion requires an
  explicit owner/release action and must be auditable.

## Follow-up

Supply reviewed external Pilot evidence, rerun the review, and obtain a Go
result. Then perform a separate candidate build/install/artifact review before
considering a 0.4.0 Phase 3 candidate.
