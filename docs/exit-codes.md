# AgentSec CLI Exit Codes

- Task: `P1-04`
- Status: Complete
- Decision date: 2026-08-18

AgentSec uses stable process outcomes so local scripts and CI systems can act on
results without parsing human-readable text.

| Code | Name | Meaning |
|---:|---|---|
| 0 | `SUCCESS` | Command succeeded; a completed scan did not trigger a blocking policy |
| 1 | `RISK_THRESHOLD_EXCEEDED` | An explicit deterministic policy gate selected blocking, including `scan --fail-on high|critical` |
| 2 | `SCAN_INCOMPLETE` | An assessment returned with incomplete coverage |
| 3 | `CONFIGURATION_ERROR` | Project configuration or future policy configuration is invalid |
| 4 | `BASELINE_ERROR` / `ARTIFACT_ERROR` | A required Baseline/Manifest artifact is missing, incompatible, unverifiable, or unsafe to write |
| 5 | `REQUIRED_ANALYSIS_FAILED` | A required analysis stage is unavailable or failed |
| 64 | `USAGE_ERROR` | The command, option or argument syntax is invalid |

## Current behavior

- `agentsec`, `--help`, `version`, `--version`, and `rules list` return `0`.
- `scan` renders the final Text or JSON Assessment through the complete
  Rule/Risk/Confidence/Hard Gate pipeline.
- `scan` with incomplete collection, parsing, or Rule coverage returns `2`.
- `scan` required-analysis failure returns `5` without a partial Assessment.
- Findings remain report-only when `--fail-on` is absent.
- `scan --fail-on high` returns `1` for complete High/Critical Findings;
  `--fail-on critical` returns `1` for complete Critical Findings only.
- incomplete Coverage retains precedence and returns `2`, even if visible
  Findings meet the selected threshold.
- invalid or incompatible config returns `3`.
- an injected assessment with incomplete coverage returns `2`.
- unknown commands and malformed CLI usage return `64` through the installed
  console/module entry point.
- code `1` is now produced only by explicit deterministic enforcement: P2-26
  scan fail-on or P2-15B qualified Capability Policy enforcement.
- `baseline create` returns `4` for incomplete coverage, parser or Git
  provenance failure, invalid output, unsafe replacement, or write failure.
- `diff` returns `0` for a complete comparable result even when files changed.
- `diff` returns `2` for incomplete current coverage or incomplete Text Diff
  evidence.
- `diff` returns `4` for Baseline input failure or collection-scope mismatch.
- `diff` returns `5` for required Asset/Text Diff analysis failure.
- `manifest` returns `0` for complete Coverage and `2` for a visible Partial
  Manifest; output failure returns `4`, required Pipeline failure returns `5`.
- `capability assess` returns `0` for complete report-only analysis even when
  Findings exist, and `2` for incomplete Coverage or Rule execution.
- `capability diff` returns `0` for two complete compatible Manifests, `2` when
  either Manifest Coverage is incomplete, `4` for invalid/incompatible input or
  unsafe artifact output, and `5` for required Diff failure.
- `--force` without `--output` returns `3`; `capability assess` remains
  report-only, while `capability enforce` may select `1` through explicit Policy.

## Assessment mapping

`exit_code_for_assessment` currently maps:

```text
coverage.complete = true  → 0
coverage.complete = false → 2
```

Findings alone do not fail the command. P2-26 selects code `1` only when the
operator explicitly supplies `--fail-on high|critical`; otherwise the same
complete Assessment returns `0`.

P1-19 rule failures become `RULE_ERROR` coverage issues and make merged scan
coverage incomplete. The integrated `scan` command maps that condition to exit
code `2`, not a clean success and not risk-policy code `1`.

## Framework parsing

Unit tests may invoke the Typer application object directly, where Click's
internal usage code can still be visible. The installed `agentsec` entry point
uses `run_cli`, executes Click in non-standalone mode, and maps usage failures to
`64`. Automation must call the installed entry point or `python -m agentsec`.

## Stability

Changing the numeric meaning of an existing exit code is a breaking CLI change.
Adding a new code requires documentation, tests, and a package-version review.

## P2-15B Policy-controlled Capability Enforcement

`agentsec capability enforce` only makes a CI decision after an explicit Policy
is loaded. `capability assess` remains report-only. A qualified deterministic
Gate match returns `1`; incomplete Coverage or a Policy requiring unknown-free
evidence returns `2`; invalid Policy or an unqualified Gate returns `3`.

## P2-26 Explicit Severity Fail-On

`agentsec scan --fail-on high|critical` evaluates final deterministic AgentSec
Finding Severity. It does not use SARIF level, Confidence, CVSS score, LLM output,
or runtime state. The JSON decision wrapper and SARIF policy fields preserve the
selected threshold and exact matching Finding IDs. See `docs/fail-on.md`.

## P2-27 Organization Policy

`scan --policy POLICY.yaml` returns `1` only for an active enforce Policy with a configured Rule/Severity match, `2` for incomplete Coverage, `3` for invalid Policy, and `0` otherwise. `--policy` and `--fail-on` are mutually exclusive.
