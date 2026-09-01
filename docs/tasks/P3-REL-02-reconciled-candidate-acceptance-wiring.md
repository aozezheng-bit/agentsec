# P3-REL-02：Reconciled Candidate Acceptance Wiring

- Status: Complete
- Date: 2026-08-31
- Depends on: P2-EXIT-08A, P3-REL-01
- Mode: local candidate acceptance; no publication authority

## Objective

Wire the P3-REL-03 source-reconciled Candidate into the existing deterministic
Candidate Acceptance State Machine without changing the preserved historical
`dist/0.4.0/` artifacts.

## Usage

```bash
PYTHONPATH=src .venv/bin/python scripts/run-phase3-entry-review.py \
  --repository-root . \
  --stage candidate_acceptance \
  --entry-readiness-report docs/reviews/phase3-entry-readiness-2026-08-26.json \
  --reconciled-candidate-report \
    dist/candidates/0.4.0-p3-rel-01/reconciliation-report.json \
  --release-provenance-bundle \
    dist/candidates/0.4.0-p3-rel-01/provenance-bundle.json \
  --format json \
  --output docs/reviews/phase3-reconciled-candidate-acceptance-2026-08-31.json
```

When a valid reconciliation report is supplied, candidate acceptance uses the
Candidate directory declared by that report and verifies the Wheel, sdist,
SHA256SUMS, artifact digests, source/package checks, fixed-epoch reproducibility,
and installed CLI smoke results. The older `--candidate-verification-report`
path remains supported for legacy acceptance fixtures.

## Fail-closed rules

- The reconciliation report must be an accepted P3-REL-03 report with package
  version `0.4.0`.
- The declared Candidate directory must be root-contained, regular, and not a
  symbolic link.
- `SHA256SUMS` and report artifact hashes must match the actual Wheel and sdist.
- All reconciliation artifact checks and installed CLI smoke checks must be true.
- `dist/0.4.0/` cannot be used as the reconciliation output and remains preserved.
- Missing, malformed, stale, or tampered reconciliation evidence produces a
  non-go Candidate Acceptance state.

## Authority boundary

Candidate acceptance only records local release evidence. It does not claim
remote publication, signatures, SLSA provenance, runtime attestation, runtime
capability, exploitability, production deployment, or CI authority.
