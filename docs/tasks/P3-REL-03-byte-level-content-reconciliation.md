# P3-REL-03：Byte-level Content Reconciliation

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-REL-01, P3-REL-02
- Mode: local report-only candidate verification; no publication authority
- Candidate directory: `dist/candidates/0.4.0-p3-rel-01/`

## Objective

Upgrade source/package reconciliation from file-presence and digest checks to
per-file byte-level verification. A candidate is accepted only when the bytes
of every shipped control file that has a source counterpart are identical to
the current source tree. This prevents a stale, substituted, or tampered module,
Schema, or release metadata file from being hidden behind a valid artifact-level
SHA-256 checksum.

## Scope

The verifier compares, without printing file contents:

- every `src/agentsec/**/*.py` file against its Wheel member;
- every `src/agentsec/**/*.py` file against the corresponding sdist
  `src/agentsec/**/*.py` member;
- every `schemas/**/*.json` file against the corresponding sdist Schema member;
- `pyproject.toml` and `MANIFEST.in` against the corresponding sdist metadata
  members.

Archive members are read as inert bytes. Scanned Agent content is never
executed. Duplicate Wheel or sdist member names fail closed.

## Report contract

`reconciliation-report.json` remains a versioned
`agentsec-candidate-artifact-reconciliation-report` and is now emitted as
`format_version: 0.2.0`, `task_id: P3-REL-03`. It contains:

- `artifact_checks.checks.wheel_content_matches_source`;
- `artifact_checks.checks.sdist_content_matches_source`;
- `artifact_checks.checks.schemas_match_source`;
- `artifact_checks.checks.metadata_matches_source`;
- a root `content_checks` object, mirrored under `artifact_checks`, with the
  four Boolean match results and bounded mismatch path lists;
- no source text, secret value, or absolute local path.

The mismatch lists are empty for a successful Candidate. They identify only
relative archive member paths, which keeps failure evidence useful without
leaking content.

## Candidate Acceptance integration

The Phase 3 Candidate Acceptance State Machine now requires:

- reconciliation format `0.2.0` and task `P3-REL-03`;
- all artifact inclusion and content-match checks to be `true`;
- all content mismatch lists to be empty;
- the root and nested `content_checks` contracts to agree;
- the existing source inventory, artifact digest, checksum, reproducibility,
  and offline CLI smoke checks to remain valid.

Changing an archive member and then recomputing its outer artifact checksum does
not make the Candidate acceptable: the byte-level reconciliation evidence must
be regenerated from the current source and pass again.

## Verification

The implementation includes regression tests for:

- successful byte-level Wheel/sdist reconciliation;
- a tampered Wheel Python module;
- a tampered sdist Schema;
- Candidate Acceptance rejection when the byte-level content contract is stale
  or inconsistent;
- preservation of the historical `dist/0.4.0/` Candidate.

Typical commands:

```bash
.venv/bin/python scripts/reconcile-candidate-artifacts.py --force
PYTHONPATH=src .venv/bin/python scripts/run-phase3-entry-review.py \
  --repository-root . \
  --stage candidate_acceptance \
  --entry-readiness-report \
    docs/reviews/phase3-entry-readiness-2026-08-26.json \
  --reconciled-candidate-report \
    dist/candidates/0.4.0-p3-rel-01/reconciliation-report.json \
  --format json
```

This task does not claim signatures, SLSA provenance, runtime capability,
exploitability, Provider quality, CI blocking, or production deployment.
