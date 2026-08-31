# P3-08 Semantic Shadow Pipeline Integration

- Status: Complete
- Date: 2026-08-31
- Interface: Semantic Shadow Pipeline Report `0.1.0`
- Implementation: `src/agentsec/semantic/p3_08.py`
- Tests: `tests/test_semantic_p3_08.py`

## 1. Purpose

P3-08 composes the Phase 3 semantic building blocks into one reusable
application-layer pipeline:

```text
trusted SemanticAnalysisInput
  → SemanticShadowInvocationAdapter
  → SemanticAnalysisResult
  → Semantic Finding Integration
  → Rule Candidate proposal generation
  → aggregate Shadow report
```

The pipeline is intended for AgentSec library consumers and future CLI/platform
integration. It does not replace the deterministic Agent Analysis Pipeline and
does not turn semantic output into an enforcement decision.

## 2. API

```python
pipeline = SemanticShadowPipeline(shadow_adapter)
report = pipeline.run(
    semantic_input,
    findings=existing_deterministic_findings,
    evidence=trusted_semantic_evidence_chunks,
)
```

The optional Finding and Evidence inputs are passed to the P3-06 read-only
integrator. If trusted Evidence is not supplied, semantic candidates safely
remain `unmatched`.

The report contains:

- the validated `SemanticShadowInvocationResult`;
- report-only Finding integration links;
- review-required Rule Candidate proposals;
- a deterministic pipeline SHA-256 digest;
- fixed authority-boundary fields.

## 3. Authority boundary

```text
report_only=true
finding_authority=false
rule_publication_authority=false
severity_authority=false
policy_authority=false
ci_authority=false
runtime_verified=false
blocks=false
```

The pipeline cannot create or modify Findings, publish a Rule, activate a Hard
Gate, change Policy, block CI, or claim runtime verification. Deterministic Rules
and reviewed Policy remain the only authority for security decisions.

## 4. Determinism and tamper detection

The aggregate digest is calculated from the validated invocation, integration
report, and Rule Candidate report. Reconstructing the report with a modified
child report or authority flag fails strict validation. Child result hashes must
match the invocation's validated `SemanticAnalysisResult`.

## 5. Data handling

P3-08 accepts only a validated `SemanticAnalysisInput` and the typed outputs of
existing P3-01 through P3-07 modules. It does not read arbitrary paths, execute
scanned files, invoke target-project code, or retain raw source in the aggregate
report. Provider network behavior remains governed by P3-02/P3-03 adapter
configuration; the default fixture path is in-memory and non-billable.

## 6. Scope note

P3-08 is an orchestration/API integration task. A dedicated production
`agentsec semantic analyze` command and platform-specific Homi wiring remain
separate delivery tasks so that their input loading, trust-root, artifact
writer, and CLI enforcement semantics can be reviewed independently.
