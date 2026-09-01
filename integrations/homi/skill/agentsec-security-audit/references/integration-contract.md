# Homi Integration Contract

## Runtime model

Homi invokes the Skill; the Skill invokes the version-pinned `agentsec` console script; AgentSec emits a report. The Skill is not an Agent and does not replace the Homi Gateway, Model, Memory, or Skills runtime.

```text
Homi Agent / Gateway
        |
        v
agentsec-security-audit Skill
        |
        v
agentsec homi scan/report
        |
        v
JSON / Markdown / SARIF report
```

## Input contract

The host should provide:

- an explicit workspace root;
- an operation: `scan`, `report`, `capability`, `diff`, `score`, or `attack-graph`;
- an optional validated baseline for `diff`;
- a validated before-state Manifest for `score`;
- an output directory outside the target workspace;
- a timeout and output-size limit.

Do not pass raw Agent file contents through a shell command. Pass the workspace path as an argument.

## Suggested host request

```json
{
  "workspace": "/srv/homi/workspaces/agent-001",
  "operation": "scan",
  "language": "zh",
  "output_format": "json",
  "baseline": null
}
```

## Suggested host response

The host should preserve the AgentSec report and add only bounded invocation metadata:

```json
{
  "status": "complete",
  "report": {},
  "authority": {
    "report_only": true,
    "runtime_verified": false,
    "ci_blocked": false
  }
}
```

Never convert a non-zero CLI exit code into a successful response.

## Version pinning

Record the AgentSec package version and wheel SHA-256 in the Homi integration metadata. Do not silently upgrade the package while comparing baselines.
