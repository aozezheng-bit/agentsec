# P2-EXIT-07: Package API / Supply-chain Hardening

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-EXIT-03, P2-EXIT-05, P2-HOMI-07
- ADR: `docs/decisions/0075-package-api-supply-chain-hardening.md`

## Objective

Harden the AgentSec package boundary before Phase 3 dependencies or LLM SDKs are
introduced. The work covers clean imports, a supported public API, PEP 561 type
metadata, exact lockfiles, license/SBOM evidence, and byte-reproducible Wheel and
sdist verification.

## Delivered

### Package/API

```text
src/agentsec/api.py
src/agentsec/exit_codes.py
src/agentsec/py.typed
pyproject.toml
MANIFEST.in
docs/package-api.md
```

`agentsec.api` is the curated public Python surface. Stable `ExitCode` lives in
`agentsec.exit_codes`, below CLI initialization. `agentsec.cli.exit_codes` keeps
compatibility re-exports for existing callers.

This closes the clean-process import cycle:

```text
import agentsec.policy
from agentsec.api import ...
```

Both now work without importing or partially initializing the CLI application.

### Dependency/build evidence

```text
requirements/runtime.lock
requirements/dev.lock
supply-chain/sbom.cdx.json
supply-chain/license-inventory.json
supply-chain/lockfiles.sha256
supply-chain/build-provenance.json
supply-chain/README.md
```

Runtime and development locks contain exact versions. The build backend is
pinned in `pyproject.toml`:

```text
setuptools==84.0.0
wheel==0.45.1
```

The SBOM is CycloneDX 1.5 and the license inventory is generated from the lock
entries with deterministic package URLs and reviewed fallback license mapping.

### Reproducible build verifier

```text
scripts/generate-supply-chain-evidence.py
scripts/verify-package-hardening.py
scripts/verify-reproducible-build.py
```

The reproducible verifier builds isolated source copies twice with a fixed
`SOURCE_DATE_EPOCH`, compares Wheel bytes, normalizes setuptools sdist tar/gzip
metadata to the same epoch, and compares sdist bytes. It emits artifact hashes
but makes no signature or SLSA claim.

### Distribution governance

The source manifest retains source, schemas, demos, scripts, and tests for the
reviewable development release, but excludes duplicated blinded reviewer and
human-evidence packs from general sdists:

```text
calibration/reviewer-pack
calibration/confidence-review-20
calibration/p2-15a-capchain-40
calibration/pilot-review-100
calibration/confidence-reviews.json
calibration/adjudication-reviews.json
```

Frozen `dist/0.2.0` and `dist/0.3.0` acceptance artifacts are historical and are
not rewritten by this task.

## Commands

```bash
PYTHONPATH=src .venv/bin/python scripts/generate-supply-chain-evidence.py
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
PYTHONPATH=src .venv/bin/python scripts/verify-reproducible-build.py \
  --source-date-epoch 1700000000
```

The last command must produce both:

```text
agentsec-0.4.0.dev0-py3-none-any.whl
agentsec-0.4.0.dev0.tar.gz
```

with `byte_identical=true`.

## Security posture

This task does not claim:

- artifact signatures;
- SLSA provenance;
- a remote trusted build service;
- dependency vulnerability-free status;
- production release approval.

Those claims require the release system and independent verification. The checked
in evidence explicitly records `not_claimed` for signatures and SLSA.

## Verification

```text
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/mypy
.venv/bin/pytest -q tests/test_package_hardening.py
.venv/bin/pytest -q
```

## Next task

```text
P2-EXIT-08 Phase 3 Entry Review / 0.4.0 Candidate
```
