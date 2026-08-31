# ADR-0075: Package API and Supply-chain Hardening

- Status: Accepted for P2-EXIT-07
- Date: 2026-08-25
- Depends on: ADR-0066 policy intent, P2-EXIT-05 provenance consolidation
- Scope: package boundary and local build evidence; not signed release provenance

## Context

Before adding Phase 3 LLM SDKs or other dependencies, AgentSec needs a package
boundary that can be imported without CLI side effects, consumed by strict type
checkers, and rebuilt from exact dependency/tool inputs. The audit identified an
`agentsec.policy` import-order cycle, missing `py.typed`, no exact lockfiles, no
SBOM/license inventory, and no byte-reproducible Wheel/sdist evidence.

## Decision

### Public API

Expose a curated API from `agentsec.api` and move process exit codes to the
CLI-independent `agentsec.exit_codes` module. Keep compatibility imports from
`agentsec.cli.exit_codes`, but do not make policy modules import the CLI.

Ship `src/agentsec/py.typed` and declare it in package data and the source
manifest.

### Dependencies

Maintain exact lockfiles:

```text
requirements/runtime.lock
requirements/dev.lock
```

Pin build backend requirements in `pyproject.toml`:

```text
setuptools==84.0.0
wheel==0.45.1
```

The lockfiles are local reproducibility evidence, not a signature or an
attestation that the public package registry is trustworthy.

### SBOM and licenses

Generate deterministic CycloneDX 1.5 and license-inventory JSON from the lock
entries. Each component has an exact version, PURL, scope, and license ID. Any
future package without a reviewed license mapping must be marked
`LicenseRef-ReviewRequired` rather than silently omitted.

### Reproducible builds

Build two isolated copies using a fixed `SOURCE_DATE_EPOCH`. Compare Wheel bytes
and normalize sdist tar member/gzip metadata to the same epoch before comparing
sdist bytes. Emit artifact SHA-256 values. Do not claim signatures or SLSA
provenance from local byte comparison alone.

### Distribution contents

Keep source, schemas, demos, scripts, and tests in the reviewable development
sdist. Exclude duplicated blinded reviewer/human-evidence packs and private
review JSON from general distribution. Historical frozen release directories
remain immutable.

## Consequences

Positive:

- `agentsec.policy` can be imported in a clean process;
- downstream type checkers can use shipped annotations;
- exact dependency inputs and license scope are reviewable;
- two-build byte comparison catches nondeterministic package output;
- sensitive reviewer evidence is not silently copied into general sdists.

Trade-offs:

- lockfiles must be deliberately refreshed and reviewed when dependencies change;
- the license inventory contains policy mappings that require maintenance;
- local reproducibility is not equivalent to a signed remote provenance claim;
- source sdists remain intentionally reviewable and therefore larger than a
  wheel-only distribution.

## Rejected alternatives

- **Import CLI from policy to reuse ExitCode:** recreates the policy-first import
  cycle and triggers application initialization.
- **Use unconstrained `pip freeze` as the public API contract:** captures local
  editable paths and unrelated environment packages.
- **Claim an SBOM is a vulnerability scan:** component inventory and license
  evidence are separate from vulnerability assessment.
- **Use current wall-clock timestamps in package archives:** prevents byte-level
  reproducibility.
- **Ship blinded Reviewer packs in every sdist:** leaks internal evidence and
  increases distribution scope without runtime value.

## Follow-up

P2-EXIT-08 must review the package API, lockfiles, SBOM, license mappings,
reproducible-build report, clean install, and any release-system signature before
accepting the 0.4.0 Phase 3 candidate.
