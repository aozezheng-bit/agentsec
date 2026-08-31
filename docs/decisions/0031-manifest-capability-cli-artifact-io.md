# ADR-0031: Manifest and Capability CLI with Restricted Artifact I/O

- Status: Accepted
- Date: 2026-08-20
- Task: P2I-04
- Package version: `0.1.0` source tree (unchanged pending a release task)
- Agent Manifest Schema: `0.3.0` (unchanged)
- Capability Diff Schema: `0.1.0` (unchanged)
- Capability Assessment Output: `0.1.0` (unchanged)

## Context

P2I-01 through P2I-03 provide a complete static Agent analysis Pipeline,
deterministic Capability Rules, and Text/JSON renderers. They are usable only
through Python APIs. Developers need a stable CLI path that can build a Manifest,
assess current capabilities, compare two saved Manifests, and inspect the
Capability Rule inventory.

CLI integration adds new trust boundaries. Before/after Manifest files are
untrusted local inputs. Output paths may target symbolic links, unrelated files,
or the input artifacts themselves. A convenience `--force` option must not
become an arbitrary overwrite primitive. Errors must not copy rejected JSON,
secret-bearing field names, dependency diagnostics, Commands, URLs, environment
values, or credentials.

The current Capability Rules remain report-only. Merely exposing them through a
CLI must not activate risk-based exit code `1` or CI blocking.

## Decision

1. Add the command surface:

   ```text
   agentsec manifest PROJECT
   agentsec capability assess PROJECT
   agentsec capability diff --before BEFORE.json --after AFTER.json
   agentsec capability rules list
   ```

2. `manifest` and `capability assess` accept explicit:

   ```text
   --working-directory
   --user-home
   --codex-home
   --agent-id
   --format text|json
   --language en|zh
   --output
   --force
   ```

   User and Codex home roots are never inferred from process environment by the
   application core.
3. `capability diff` compares only two saved, compatibility-validated Agent
   Manifest JSON files in its first release. It does not combine live scanning
   and historical comparison into one command.
4. CLI functions translate arguments, call application services, select
   renderers, and emit or persist output. They do not rebuild Manifest, Rule, or
   Diff semantics inline.
5. Add `DeterministicManifestCapabilityDiffEngine` as the application seam over
   `CapabilityDiffer`.
6. Add `AgentManifestFileReader` with:

   ```text
   .json-only input
   regular-file requirement
   final-component no-follow behavior
   hard byte limit before JSON decode
   strict UTF-8
   compatibility-first Manifest validation
   safe stable errors without payload content
   ```

7. Add one restricted `ReportArtifactWriter` for Manifest, Capability
   Assessment, and Capability Diff Text/JSON output:

   ```text
   validate generated content against the selected artifact kind
   require .json for JSON and .txt for Text
   create parent directories with restrictive defaults
   reject final symbolic links and non-files
   mode 0600 temporary and final files
   fsync and atomic no-clobber creation
   no overwrite by default
   --force only for an existing valid artifact of the same kind and format
   reject output that equals a protected input artifact
   bounded existing-file reads before replacement
   ```

8. Writing to `--output` produces no success text on stdout. Without `--output`,
   stdout contains exactly the requested report. Operational errors use stderr.
9. Text output supports reviewed English and Simplified Chinese. Canonical JSON
   behavior is language-independent; Capability Assessment JSON retains both
   trusted localized texts.
10. Reuse stable process values and add `ARTIFACT_ERROR` as an alias of numeric
    code `4`:

    ```text
    0 complete report-only result
    2 incomplete Manifest Coverage, Rule execution, or Capability Diff
    3 invalid option combination such as --force without --output
    4 invalid/incompatible input artifact or unsafe output operation
    5 required analysis failure
    64 CLI usage error through the installed runner
    ```

11. Findings alone continue to return `0`. Exit `1` remains reserved for a
    future explicitly configured policy gate.
12. Help and every report repeat that static declaration analysis does not prove
    runtime reachability, authorization, exploitation, or global Agent safety.
13. No Agent Manifest, Capability Diff, Capability Assessment, Rule Pack, Risk
    Model, or Phase 1 serialized contract changes in P2I-04. The source package
    version remains unchanged until a separate release/version task publishes
    the Phase 2 command surface.

## Consequences

### Positive

- The complete Phase 2 static analysis path is now usable from a terminal and
  automation without writing Python integration code.
- JSON can be redirected cleanly or written atomically to a private artifact.
- Saved Manifests are bounded and compatibility-validated before comparison.
- `--force` cannot replace arbitrary unrelated files or either Diff input.
- Complete, incomplete, invalid-artifact, and required-failure outcomes are
  machine-distinguishable.
- English and Chinese presenter paths use the same deterministic analysis.
- Report-only policy remains unchanged.

### Negative

- The first Capability Diff CLI requires two pre-generated Manifest files.
- Text artifacts require a `.txt` filename and JSON artifacts require `.json`.
- `--force` rejects legacy or manually edited files that are not valid artifacts
  of the same kind and format.
- Artifact input/output is local only; signing, remote storage, provenance
  attestation, and retention policy remain future work.
- The new command surface is not included in the frozen Phase 1 `dist/` files;
  a later release task must rebuild and verify distribution artifacts.
