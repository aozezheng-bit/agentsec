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
