# AgentSec Package and Supply-chain Evidence

This directory contains checked-in, value-free release evidence for the AgentSec
0.4.x development line:

```text
sbom.cdx.json              CycloneDX 1.5 component inventory
license-inventory.json     package/license metadata inventory
lockfiles.sha256           hashes of the exact requirements locks
build-provenance.json      policy and build-command provenance contract
```

The lockfiles are exact-version constraints for runtime and development/build
environments. They do not by themselves provide artifact signatures or a SLSA
claim. A release must run the reproducible-build verifier and publish artifact
hashes/signatures through the release system before claiming signed provenance.

Regenerate the static inventory from the lockfiles with:

```bash
PYTHONPATH=src .venv/bin/python scripts/generate-supply-chain-evidence.py
```

Verify package API, lockfile, SBOM, and license evidence with:

```bash
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
```
