# AgentSec 0.1.0 Release Agent Demo

This offline Demo tells one story: a reviewed Release Agent drifts from a local,
approval-based assistant into instructions that declare shell execution, secret
access, external transmission, production writes, automatic deployment, hidden
behavior, and executable tooling.

All files are synthetic untrusted data. AgentSec does not execute any instruction
or follow the referenced deployment helper.

## Scenarios

| Scenario | Assets | Expected result |
|---|---:|---|
| `baseline/` | 2 | Complete Coverage, zero Findings |
| `risky-drift/` | 2 | Complete Coverage, 10 Findings, highest High |
| `prompt-injection/` | 1 | Two instruction-integrity Findings |
| `malformed/` | 1 | Incomplete Coverage, `unsupported_encoding`, exit `2` |
| `remediated/` | 2 | Complete Coverage, zero Findings |

The risky scenario produces nine unique Rule IDs. `MD-INSTR-002` produces two
source-backed Findings because two separate lines declare suppression/hiding.

## Run the presenter-friendly Developer Demo

For a live terminal presentation, use the step-by-step runner:

```bash
scripts/demo-developer.sh
```

It pauses between eight narrated stages, prints compact Chinese summaries instead
of the complete JSON payload, preserves every JSON artifact, and validates the
story before it reports success. It does not clear the terminal or execute any
content declared by the scanned Demo Assets.

Useful options:

```bash
# Rehearse or test without waiting for Enter.
scripts/demo-developer.sh --no-pause

# Include the complete deterministic Rule Pack during preflight.
scripts/demo-developer.sh --show-rules

# Use fully Chinese Agent Assets and localized Rule inventory.
scripts/demo-developer.sh --case-language zh --show-rules

# Keep outputs in a selected new or empty directory.
scripts/demo-developer.sh --output-dir /tmp/agentsec-developer-demo
```

Set `NO_COLOR=1` for plain output. Use `--python PATH` or the `PYTHON`
environment variable when the repository virtual environment is not available.

## Run the complete automated Demo

From the repository root:

```bash
scripts/run-demo.sh
```

Optionally preserve outputs in a selected directory:

```bash
scripts/run-demo.sh /tmp/agentsec-release-demo
```

The runner uses the installed package through `python -m agentsec`, creates a
fresh temporary Baseline, executes the real scan/diff commands, validates the
semantic result, and prints the output directory.

## Policy boundary

The risky scan exits `0` because the 0.1.0 PoC is report-only:

```text
enforcement_mode=report_only
ci_blocking_enabled=false
global_safety_claimed=false
```

AgentSec does not block the release. The Demo's human recommendation is to hold
the release until the risky drift is reviewed and remediated.

## Frozen offline fallback

`expected/` contains accepted deterministic output generated with fixed
execution metadata. `checksums.sha256` protects the frozen files from silent
drift.

Regenerate only as part of a reviewed release update:

```bash
PYTHONPATH=src python3.12 scripts/freeze_demo.py
```

After regeneration, run the release tests and repeat the acceptance review.
