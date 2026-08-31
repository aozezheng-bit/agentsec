# External Real-project Report-only Pilot Template

This directory is a **template only**. It is not evidence from a real external
project and must not be reported as an accepted Pilot.

A non-authoritative GitHub Actions starting point is
`github-actions-report-only.yml`; replace its repository/ref/digest
placeholders through protected project configuration before use.

## Required inputs

- one real Agent repository or a read-only export of its reviewed states;
- a separate protected trust root containing the organization Policy;
- at least 20 reviewed scan states, including at least 10 pull-request states;
- risky-change, incomplete-Coverage, and Waiver-lifecycle exercises;
- an independent security Reviewer who records `human-labels.json`.

The target repository is untrusted input. AgentSec reads bounded Agent assets;
it does not execute project code, hooks, commands, skills, or MCP servers.

## Run report-only collection

From the AgentSec repository:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-pilot.py \
  --plan pilots/external-repository-template/pilot.yaml \
  --target-root /absolute/path/to/external-agent-repo \
  --trust-root /absolute/path/to/protected-policy-root \
  --expect-policy-sha256 SHA256_OF_PROTECTED_POLICY \
  --output-dir /absolute/path/to/external-pilot-results \
  --allow-evidence-pending
```

The plan path and human-label file remain AgentSec-controlled. `--target-root`
and `--trust-root` are explicit and must be different non-symlink directories.
The trust root is never discovered from the target repository.

## Complete acceptance

After the independent Reviewer completes all labels:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-pilot.py \
  --plan pilots/external-repository-template/pilot.yaml \
  --target-root /absolute/path/to/external-agent-repo \
  --trust-root /absolute/path/to/protected-policy-root \
  --expect-policy-sha256 SHA256_OF_PROTECTED_POLICY \
  --human-labels pilots/external-repository-template/human-labels.json \
  --output-dir pilots/external-repository-template/results
```

Only a report with `status=complete`, complete scope, complete independent
labels, and all reports/SARIF artifacts valid is eligible for acceptance.
This Pilot remains report-only and cannot authorize CI blocking.
