# ADR-0032: Phase 2 Integration Package Release 0.2.0

- Status: Accepted
- Date: 2026-08-20
- Task: Phase 2 Integration Hardening / Release Review
- Package version: `0.1.0` → `0.2.0`
- Serialized Schema/Output versions: unchanged
- Enforcement: report-only, unchanged

## Context

AgentSec 0.1.0 is the accepted local Phase 1 Markdown PoC. The source tree now
also contains the completed P2-01 through P2-11 and P2I-01 through P2I-05
integration chain:

```text
JSON/YAML/TOML and specialized Rules/MCP Parsers
Codex Framework Adapter
Agent Manifest and deterministic resolvers/extractors
Explicit Unknowns and Capability Diff
AgentAnalysisPipeline
six deterministic Capability Rules
Manifest/Capability Text and JSON reports
Manifest and Capability CLI
restricted local Artifact I/O
bilingual Capability Drift Demo
```

Those additions are a substantial backward-compatible expansion of the installed
package and command surface. Keeping `PACKAGE_VERSION = 0.1.0` would make the
Phase 1 wheel indistinguishable from the Phase 2-capable source distribution.
The independently versioned Manifest, Capability Diff, Capability Assessment,
Capability Rule, and Capability Risk contracts have already received their own
ADRs and do not change during this release review.

Release hardening also identified two diagnostic/I/O boundaries to strengthen:
malicious extra JSON field names could enter public validation field paths, and
existing report replacement validation should retain no-follow behavior at the
actual file-open operation.

## Decision

1. Publish the integrated local package as:

   ```text
   PACKAGE_VERSION = 0.2.0
   ```

   This is a pre-1.0 minor package increment because new public CLI commands,
   modules, report APIs, parsers, and artifacts are added without removing the
   Phase 1 command surface.
2. Keep these independently versioned interfaces unchanged:

   ```text
   CONFIG_SCHEMA_VERSION = 0.1.0
   DOMAIN_SCHEMA_VERSION = 0.3.0
   AGENT_MANIFEST_SCHEMA_VERSION = 0.3.0
   CAPABILITY_DIFF_SCHEMA_VERSION = 0.1.0
   CAPABILITY_RULE_PACK_VERSION = 0.1.0
   CAPABILITY_RISK_MODEL_VERSION = 0.1.0
   CAPABILITY_ASSESSMENT_OUTPUT_VERSION = 0.1.0
   BASELINE_SCHEMA_VERSION = 0.1.0
   DIFF_OUTPUT_VERSION = 0.1.0
   ASSESSMENT_OUTPUT_VERSION = 0.2.0
   RULE_PACK_VERSION = 0.3.0
   RISK_MODEL_VERSION = 0.4.0
   ```

3. Freeze the existing Phase 1 Domain, Baseline, and Assessment Schemas without
   altering their meaning. Add release copies of the already-versioned Phase 2
   Agent Manifest, Capability Diff, and Capability Assessment Schemas.
4. Preserve all Phase 1 commands and behavior. Additive Phase 2 commands are:

   ```text
   agentsec manifest
   agentsec capability assess
   agentsec capability diff
   agentsec capability rules list
   ```

5. Keep Capability Findings report-only:

   ```text
   hard_gate = false
   ci_blocking_enabled = false
   exit 1 remains reserved
   ```

6. Replace unsafe JSON validation location parts with `<field>` unless they are
   bounded identifiers or numeric indexes. Rejected payload values and malicious
   keys must not enter diagnostics.
7. Open existing report replacement candidates with `O_NOFOLLOW` where available
   and verify regular-file metadata after open. `--force` remains limited to an
   existing valid artifact of the same kind and format.
8. Store 0.2.0 build artifacts under `dist/0.2.0/` so the accepted 0.1.0 files at
   `dist/` remain preserved and distinguishable.
9. Build scripts derive the release version from the source of truth rather than
   embedding `0.1.0`.
10. Verify a non-editable local wheel install without requiring external network
    access, then exercise both Phase 1 and Phase 2 command paths.
11. Include release notes, known limitations, acceptance evidence, frozen Phase 2
    Schemas, and the bilingual Capability Drift Demo in the source distribution.
12. Do not claim a Git tag, signed commit, remote package publication, production
    deployment, or CI enforcement. This remains a local internal MVP release.

## Consequences

### Positive

- Package identity now distinguishes the Phase 1 PoC from the integrated Phase 2
  CLI.
- Existing Phase 1 automation remains available.
- Machine consumers can continue to reason from independent Schema/Output/Rule/
  Risk versions.
- Public validation diagnostics and report replacement reads have stronger
  disclosure and symlink-race resistance.
- 0.1.0 artifacts remain preserved while 0.2.0 receives its own checksums and
  acceptance record.
- The installed wheel can run Manifest, Capability Assessment, Capability Diff,
  and Rule inventory commands offline.

### Negative

- Pre-1.0 package consumers must explicitly review and adopt 0.2.0.
- The package still contains two analysis product families: Phase 1 Markdown
  Assessment and Phase 2 Manifest/Capability Assessment.
- Capability Rule Pack size remains six rather than the planned 20–30 Rules.
- Capability Change Impact, Capability Hard Gates, SARIF, policy configuration,
  waivers, signing, and runtime verification remain future work.
- The local workspace still lacks Git and remote publication provenance.
