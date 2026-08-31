# AgentSec Internal Pilot Integration

- Task: `P2-30`
- Status: Complete internal integration pilot
- Date: 2026-08-25
- ADR: `docs/decisions/0059-versioned-pilot-evidence.md`
- Plan Schema: `0.1.0`
- Report Output: `0.1.0`

## Pilot target

The first pilot uses the inert Release Agent project states already reviewed by
the AgentSec Demo and adds a safe shell-documentation near miss. It is an
**internal integration pilot**, not evidence from a remote production or
business repository.

```text
pilots/internal-release-agent/pilot.yaml
```

Eight scenarios cover:

1. safe baseline;
2. risky deterministic Policy block;
3. malformed/incomplete fail-closed behavior;
4. prompt-injection declarations as inert input;
5. remediated zero-Finding state;
6. safe shell documentation near miss;
7. active Waiver preserving Findings while removing blocking;
8. expired Waiver restoring blocking.

## Run

```bash
PYTHONPATH=src .venv/bin/python scripts/run-pilot.py \
  --agentsec .venv/bin/agentsec
```

Outputs:

```text
pilots/internal-release-agent/results/pilot-report.json
pilots/internal-release-agent/results/pilot-report.md
```

The active GitHub Actions pilot workflow is:

```text
.github/workflows/agentsec-pilot.yml
```

It preserves the generated reports with `if: always()` and then fails the job
when any scenario has decision, Coverage, detection, SARIF, or performance
regression.

## Data contract

Each plan case declares:

```text
case_id
project_root
policy_path
expected_exit
expected_coverage
expected_rule_ids
max_duration_ms
```

Paths must be repository-relative and contained. The Loader rejects Symlink
plans/projects/policies, duplicate YAML keys, Alias, Anchor, Tag, unknown fields,
unknown Rule IDs, unsorted Cases, and escaping paths.

The report stores only Rule/Finding metadata needed for metrics. It excludes
Evidence excerpts, command text, URLs, environment names, Secret values, and
raw scanned source values.

## FP/FN definition

For each reviewed scenario, AgentSec compares expected and observed unique Rule
IDs:

```text
TP = expected ∩ observed
FP = observed - expected
FN = expected - observed
```

This is appropriate for deterministic integration regression. It is not a
claim about production prevalence, runtime exploitability, or occurrence-level
Precision/Recall.

## Current pilot result

The checked-in run completed on August 25, 2026:

```text
Cases: 8/8 passed
Scenario-Rule TP: 29
FP: 0
FN: 0
Precision: 100%
Recall: 100%
Decision accuracy: 100%
Coverage accuracy: 100%
Detection accuracy: 100%
Local p50/p95/max: 605/654/654 ms
```

Performance values are one local wall-clock observation and will vary by host,
filesystem cache, and installed environment. The acceptance ceiling is 10
seconds per scenario, including two scanner executions needed to retain JSON
and SARIF.

## P2-31 handoff

P2-31 can consume `pilot-report.json` to:

- investigate any future FP/FN Rule IDs;
- compare decision and Coverage regressions;
- identify slow scenarios;
- tune Rules or scoring only through reviewed changes and replay tests.

Because the current sample is curated and internal, P2-31 must not interpret
100% Precision/Recall as production accuracy. External repository sampling is a
recommended follow-up, not a hidden prerequisite for replaying this contract.

## P2-EXIT-06 external repository mode

The internal pilot above is not external evidence. For a real project, keep
the Pilot plan and human labels in the AgentSec-controlled directory and pass
the target repository and protected Policy root explicitly:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-pilot.py \
  --plan pilots/external-repository-template/pilot.yaml \
  --target-root /absolute/path/to/external-agent-repo \
  --trust-root /absolute/path/to/protected-policy-root \
  --expect-policy-sha256 SHA256_OF_PROTECTED_POLICY \
  --output-dir /absolute/path/to/external-pilot-results \
  --allow-evidence-pending
```

External mode requires at least 20 scan states, 10 pull-request states, and
risky-change, incomplete-Coverage, and Waiver-lifecycle drills. Independent
human labels are loaded separately from `human-labels.json`; until every case
is labelled, the report is `evidence_pending`, not accepted. The target and
trust roots must be different non-symlink directories. The target is treated
as untrusted input, and no target code, hook, skill, command, or MCP server is
executed.
