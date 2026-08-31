# ADR-0061: AgentSec Internal MVP Release 0.3.0

- Status: Accepted
- Date: 2026-08-25
- Task: P2-32
- Package version: `0.2.0` → `0.3.0`

## Context

Since the accepted 0.2.0 Phase 2 Integration release, AgentSec has added
Capability Impact, calibrated Capability Gates, CVSS enrichment and scoring,
Agentic Technical/Drift/Governance/Overall scores, scoring replay, SARIF,
explicit `--fail-on`, Organization Policy, expiring Waivers, CI examples, an
internal Pilot, and Pilot-driven Rule/score calibration.

These are substantial additive package, CLI, report, Policy, and release
surfaces. Rebuilding them under Package `0.2.0` would make the preserved 0.2.0
artifact indistinguishable from the current source.

## Decision

1. Release the current local internal MVP as Package `0.3.0`.
2. Preserve `dist/0.2.0/` and create a new immutable `dist/0.3.0/` directory.
3. Retain the independently calibrated versions:

   ```text
   Markdown Rule Pack 0.3.0
   Risk Model 0.4.0
   Capability Rule Pack 0.2.0
   Capability Risk Model 0.1.0
   ```

4. Include Policy, Waiver, SARIF, Pilot, Calibration, schemas, CI examples,
   demos, tests, and acceptance evidence in the sdist.
5. Verify a non-editable offline Wheel install and exercise report-only Scan,
   Organization Policy blocking, active Waiver allowance, SARIF, Manifest, and
   Capability commands.
6. Accept `--fail-on critical` as a supported deterministic threshold. The
   Critical decision path is covered by synthetic trusted Assessment tests;
   current static Markdown profiles do not manufacture Critical severity merely
   to demonstrate blocking.
7. Do not claim Git provenance, signed artifacts, remote package publication,
   production deployment, remote CI execution, runtime exploitability, or
   global Agent safety.

## Consequences

The Package version now identifies the complete internal MVP feature set while
Rule and Risk versions remain truthful about unchanged calibrated semantics.
The release is usable for controlled internal static scanning and CI policy
pilots, but runtime attestation and external production calibration remain
future work.
