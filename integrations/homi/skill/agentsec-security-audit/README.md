# AgentSec Security Audit Skill

This is the Homi/OpenClaw integration wrapper for the AgentSec CLI. It keeps orchestration and presentation guidance in `SKILL.md`; deterministic analysis remains in the installed `agentsec` package.

## Install

Install a pinned AgentSec wheel in the Homi runtime, then copy or mount this directory under the workspace's `skills/` directory:

```text
<workspace>/skills/agentsec-security-audit/
```

## Quick test

```bash
commands/scan.sh /path/to/homi-workspace
commands/report.sh /path/to/homi-workspace /tmp/agentsec-homi-report
commands/manifest.sh /path/to/homi-workspace
```

The commands are read-only with respect to the target workspace and delegate all analysis to AgentSec.

## Report artifacts

`agentsec homi report` produces a paired set of machine and human artifacts:

```text
homi-pilot-report.json  # stable machine-readable contract
homi-pilot-report.md    # Markdown review summary
homi-pilot-report.html  # self-contained browser-viewable report
```

The HTML is suitable for opening directly in Homi or a local browser. It is
built from the same report object as JSON/Markdown, so the three formats share
the same Findings, capability states, Unknown counts, and authority flags.

For before/after reports:

```text
commands/homi-diff.sh before.json after.json html /tmp/homi-drift.html
```

The Capability Diff JSON artifact follows the strict
`schemas/capability-diff.schema.json` contract included in this Skill. Its
`authority` object is fixed to report-only semantics; it cannot be used as a
runtime attestation, authorization, or CI-blocking decision.
