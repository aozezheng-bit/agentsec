# External Pilot Acceptance Record (Template)

- Status: `implementation_ready / evidence_pending`
- Evidence mode: `external_repository`
- Pilot ID: `external-agent-project-pilot`
- Target repository: **to be supplied by project owner**
- Protected trust root: **to be supplied by security owner**
- Security reviewer: **to be assigned**

## Required evidence checklist

- [ ] Real Agent repository identified and read-only access approved.
- [ ] Target root and protected trust root are different non-symlink directories.
- [ ] Protected Policy SHA-256 is recorded in the controlled execution record.
- [ ] At least 20 total scan states completed.
- [ ] At least 10 pull-request scan states completed.
- [ ] Risky-change exercise completed.
- [ ] Incomplete-Coverage exercise completed.
- [ ] Waiver lifecycle exercise completed.
- [ ] Independent human TP/FP/FN labels cover every case.
- [ ] JSON and SARIF artifacts are valid for every case.
- [ ] Performance p50/p95/max recorded.
- [ ] Coverage and Unknown distribution recorded.
- [ ] Developer feedback recorded without secrets or source excerpts.
- [ ] No LLM output influenced the labels, severity, Policy, Waiver, or CI.

## Acceptance rule

Acceptance is allowed only when the generated report has
`status=complete`, `metrics.acceptance_ready=true`, no failed scan case, and
the evidence package is reviewed by the project owner and security reviewer.
No external evidence may be inferred from the checked-in internal Pilot.
