# AgentSec

AgentSec is an evidence-backed security diagnostics CLI for Agent control
assets and Homi/OpenClaw-style workspaces.

## Included in this code distribution

- deterministic Markdown/TOML/YAML/JSON analysis;
- Agent Manifest and Capability assessment;
- baseline and Capability Diff;
- deterministic findings, scoring, Hard Gate and policy interfaces;
- report-only Attack Graph and Semantic Shadow interfaces;
- Homi Workspace Adapter and `agentsec-security-audit` Skill.

Internal calibration corpora, pilot evidence, review records, release archives,
and private project documentation are intentionally not included in this code
repository.

## Install

```bash
python -m pip install .
agentsec --version
```

## Homi Skill

Install or copy:

```text
integrations/homi/skill/agentsec-security-audit/
```

under the Homi Agent workspace:

```text
<workspace>/skills/agentsec-security-audit/
```

Run a read-only Homi scan:

```bash
agentsec homi scan /path/to/homi-workspace \
  --format json \
  --language zh
```

Generate paired JSON and Markdown reports:

```bash
agentsec homi report /path/to/homi-workspace \
  --output-dir /tmp/agentsec-homi-report \
  --language zh \
  --force
```

## Security boundary

AgentSec treats scanned content as untrusted input. It does not execute
scanned code, Hooks, Skills, Plugins, Commands, or MCP servers. It does not
read credential values or prove runtime reachability. Homi integration is
report-only by default:

```json
{
  "report_only": true,
  "runtime_verified": false,
  "ci_blocked": false
}
```

## Development

```bash
python -m pytest -q
ruff check src tests scripts
ruff format --check src tests scripts
mypy src
```

This repository contains the code distribution only. Organization-specific
calibration, review, pilot, and release evidence must be maintained separately.
