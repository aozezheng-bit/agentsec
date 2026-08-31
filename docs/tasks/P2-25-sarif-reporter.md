# P2-25: SARIF Reporter

- Status: Complete
- Completion date: 2026-08-25
- Depends on: P2I-03, P2I-04, P2-23, P2-24
- Decision: `docs/decisions/0055-sarif-2.1.0-reporter.md`
- Reporter version: `0.1.0`
- SARIF version: `2.1.0`

## Goal

Provide a safe deterministic SARIF 2.1.0 representation of current AgentSec
Findings and Overall Score for CI code-scanning ingestion without changing risk,
Coverage, Hard Gate, policy, or exit-code semantics.

## Delivered

```text
src/agentsec/reporting/sarif.py
src/agentsec/reporting/__init__.py
src/agentsec/versioning.py
src/agentsec/cli/scan.py
src/agentsec/cli/capability.py
src/agentsec/cli/app.py
src/agentsec/cli/manifest.py
src/agentsec/artifacts/storage.py
tests/test_sarif_reporting.py
docs/sarif-report.md
docs/decisions/0055-sarif-2.1.0-reporter.md
```

## Implemented behavior

- [x] strict one-run AgentSec SARIF 2.1.0 subset;
- [x] deterministic JSON codec and safe decoder;
- [x] Phase 1 Assessment renderer;
- [x] Capability Assessment renderer;
- [x] Overall Score renderer;
- [x] stable Rule descriptor and Result indexing;
- [x] versioned Finding/Manifest partial fingerprints;
- [x] project-relative URI and line-region locations;
- [x] Severity-to-SARIF mapping;
- [x] Confidence, Correlation, score, CVSS/CVE/CWE, Gate, Coverage, and version
  properties;
- [x] `agentsec scan --format sarif`;
- [x] `agentsec capability assess --format sarif`;
- [x] `.sarif` Capability artifact output with safe no-clobber/force behavior;
- [x] incomplete analysis preserves existing exit `2` and valid partial SARIF;
- [x] no Evidence excerpt, secret, token, credential, URL value, Header,
  environment value, or raw source value in SARIF;
- [x] CI blocking remains disabled.

## Acceptance examples

```bash
agentsec scan demos/release-agent/risky-drift \
  --format sarif > /tmp/agentsec-scan.sarif

agentsec capability assess demos/capability-drift-agent/risky-drift \
  --agent-id capability-drift-agent \
  --format sarif \
  --output /tmp/agentsec-capability.sarif
```

Expected behavior:

```text
complete analysis + Findings → exit 0
incomplete analysis          → exit 2 with valid partial SARIF
existing output              → exit 4 unless valid same-kind --force
```

## Explicitly not included

```text
--fail-on
SARIF-derived CI blocking
organization Policy or waiver evaluation
runtime Tool/OAuth/Permission validation
runtime exploitability proof
LLM semantic analysis
SARIF CodeFlow/ThreadFlow/Fix objects
SARIF for Manifest/Diff/Impact/Enforcement
Overall Score CLI
remote schema or vulnerability lookup
```

## Verification

Required completion gate:

```bash
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/mypy src tests
PYTHONPATH=src .venv/bin/python -m pytest -q
```

Final observed results on 2026-08-25:

```text
Targeted SARIF/CLI/artifact/documentation regression: 127 passed
Ruff check: passed
Ruff format check: passed — 266 files
Mypy strict: passed — 246 source files
Pytest: 1101 passed
Manual Scan SARIF: 9 Rules / 10 Results / valid SARIF 2.1.0
Manual Capability SARIF: 16 Rules / 17 Results / valid SARIF 2.1.0
```

The format gate also normalized the previously unformatted P2-24
`scripts/run-scoring-replay.py`; this was a formatting-only prerequisite for a
clean repository-wide check.
