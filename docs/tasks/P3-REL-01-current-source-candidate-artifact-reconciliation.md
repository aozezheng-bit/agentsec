# P3-REL-01：Current Source / Candidate Artifact Reconciliation

- Status: Complete
- Date: 2026-08-31
- Mode: local release candidate; no publication authority
- Preserved candidate: `dist/0.4.0/`
- Reconciled candidate: `dist/candidates/0.4.0-p3-rel-01/`

## Objective

Reconcile the current source tree with a new installable candidate without
mutating the previously accepted `dist/0.4.0/` artifacts. This closes the gap
where the source tree contains P3-AG and P3-AG-09 while the preserved 0.4.0
candidate predates those modules.

## Deliverable

Run:

```bash
.venv/bin/python scripts/reconcile-candidate-artifacts.py
```

The command writes the following files under the new candidate directory:

```text
agentsec-0.4.0-py3-none-any.whl
agentsec-0.4.0.tar.gz
SHA256SUMS
reconciliation-report.json
reconciliation-report.md
```

The historical `dist/0.4.0/` directory is preserved and its artifact digests
are recorded in the reconciliation report for comparison.

## Checks

The reconciliation command verifies:

- every current `src/agentsec/**/*.py` module is present in the Wheel and sdist;
- every current JSON Schema is present in the sdist;
- Attack Graph modules and `risk/attack_path_score.py` are in the Wheel;
- P3-AG-09 documentation, Schema, and reconciliation tooling are in the sdist;
- Wheel metadata version and `agentsec` console entry point are correct;
- two fixed-epoch builds are byte-identical after sdist normalization;
- the installed Wheel can run `version`, root help, Attack Graph help, Score help,
  `agentsec attack-graph`, and `agentsec score --attack-path-report` offline.

## Security boundary

- The previous candidate is never overwritten.
- Builds use `--no-index`, with no live Provider, MCP connection, or network call.
- Smoke tests invoke only inert static analysis over repository fixtures; scanned
  Agent content is never executed.
- Artifact signatures and SLSA provenance remain `not_claimed`.
- Reconciliation proves package/source consistency, not runtime capability,
  exploitability, Provider quality, or production readiness.

## Acceptance

P3-REL-01 is accepted when the report has `status=reconciled`, all artifact and
CLI smoke checks are true, `reproducible_build.byte_identical=true`, and the
preserved candidate remains unchanged. Candidate promotion to a release still
requires the existing release review and owner approval process.
