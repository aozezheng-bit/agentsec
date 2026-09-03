# AgentSec 0.4.0 Homi Recalibration Candidate

- Created: 2026-09-03
- Base: Git `HEAD` at creation time (`366ec44`)
- Candidate branch: `codex/homi-release-candidate-20260903`
- Candidate type: clean local, committed, report-only verification candidate
- Remote publication: disabled
- Homi publication: disabled

## Included

This candidate includes the Homi adapter/profile/pilot/diff/bundle path, the
build fingerprint and recalibration Sidecars, the Homi Skill wrapper, Homi
focused tests, the Chinese capability-drift demo script, the regenerated
release artifacts, and the P3-HOMI recalibration ADR/task records.

## Excluded

The following remain outside this candidate tree:

- semantic Pilot / Provider experiment changes;
- unrelated Phase 3 feedback corpus edits;
- unreviewed mutation-demo implementation script and repaired-agent fixture;
- any credentials, local environment files, or remote Homi state.

## Verification identity

The candidate has Git metadata and a clean commit. The packaging pipeline must
pass the reviewed commit through `AGENTSEC_BUILD_COMMIT`; the runtime fingerprint
must report `build_commit=unavailable` when no trusted build identity is injected
and must never guess a commit from the scanned Homi Workspace.
