# P2-32: Internal MVP Release

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-31
- Package: `0.3.0`

Released the complete local AgentSec internal MVP as a versioned Wheel and
source distribution while preserving accepted 0.1.0 and 0.2.0 artifacts.

## Acceptance

```text
Ruff check: passed
Ruff format: passed — 796 files
Mypy strict: passed — 258 source files
Pytest: 1154 passed
Release-focused tests: 25 passed
Artifact acceptance tests: 9 passed
CI example replay: 6/6 passed
Pilot replay: 8/8 passed
Rule/Score calibration replay: complete
Scoring replay: 7/7 exact match
Non-editable offline Wheel installation: passed
Wheel/sdist/checksum inspection: passed
```

## Artifacts

```text
dist/0.3.0/agentsec-0.3.0-py3-none-any.whl
dist/0.3.0/agentsec-0.3.0.tar.gz
dist/0.3.0/SHA256SUMS
```

## Boundary

This is a local internal MVP release. No Git tag, signed source provenance,
remote package publication, remote CI execution, production deployment,
runtime exploit proof, or global Agent safety claim is made.
