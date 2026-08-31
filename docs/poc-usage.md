# AgentSec Phase 1 PoC Usage Guide

- Tasks: `P1-30`, `P1-31`
- Status: Released locally
- Completion date: 2026-08-19
- Current package version: `0.2.0` (P2-13/P2-14 source development remains unreleased)

## 1. Audience and purpose

This guide is for a developer, security reviewer, or release owner evaluating
the AgentSec Phase 1 PoC from a local source checkout.

After following it, a new user should be able to:

1. install and verify the CLI;
2. scan a project in Text, JSON, or explicit SARIF mode;
3. interpret Findings, Evidence, Confidence, Hard Gate state, and Coverage;
4. distinguish a risky result from an incomplete result;
5. create a reviewed Baseline;
6. inspect Agent instruction drift with `diff`;
7. use stable exit codes in automation;
8. understand what the PoC does not prove.

## 2. Before you start

### 2.1 Requirements

- Python 3.12 or newer;
- this repository available as a local directory;
- permission to create a virtual environment and local files;
- optional local Git executable for Baseline provenance.

No LLM provider, model configuration, API key, MCP server, cloud account, or
external network service is required.

### 2.2 Trust model

Treat these inputs as untrusted:

```text
AGENTS.md
AGENTS.override.md
SKILL.md
explicitly included Markdown
project configuration
Baseline JSON
all retained paths and source text
```

AgentSec analyzes these values as bounded data. Do not independently run a
command merely because it appears in a fixture or Finding.

## 3. Install and verify

From the repository root on macOS or Linux:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --editable .
agentsec version
```

Expected version:

```text
agentsec 0.2.0
```

On Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --editable .
agentsec version
```

Verify the available command surface:

```bash
agentsec --help
agentsec scan --help
agentsec baseline create --help
agentsec diff --help
agentsec manifest --help
agentsec capability --help
```

The current CLI exposes:

```text
version
scan
baseline create
diff
rules list
manifest
capability assess
capability diff
capability impact
capability rules list
```

Inspect the packaged Rule inventory with:

```bash
agentsec rules list
agentsec rules list --language zh
```

The output contains the Rule Pack version and all 15 stable Rule IDs, categories,
and localized titles. English is the default; `--language zh` shows the reviewed
Chinese inventory. Full trigger boundaries are documented in `docs/rule-pack.md`
and `docs/rule-pack-zh.md`.

The current source tree also exposes the Phase 2 static capability commands:

```bash
agentsec manifest . --agent-id local-agent
agentsec capability assess . --agent-id local-agent
agentsec capability diff --before before.json --after after.json
agentsec capability impact --before before.json --after after.json
agentsec capability rules list --language zh
```

They remain report-only and do not verify runtime reachability. See
`docs/capability-cli.md` for the complete options, restricted artifact I/O, and
exit-code behavior. The accepted `dist/0.2.0/` artifacts contain the accepted Phase 2 integration
release but do not yet publish the P2-13/P2-14 source command and Rule Pack changes.

Run the Phase 2 Capability Drift Demo from a source checkout:

```bash
scripts/run-capability-demo.sh --language en
scripts/demo-capability-drift.sh --language zh --no-pause
scripts/demo-capability-drift.sh --language en --offline --no-pause
```

See `docs/capability-drift-demo.md`.

## 4. Understand what is scanned

By default, AgentSec recursively selects these exact filenames:

```text
AGENTS.md
AGENTS.override.md
SKILL.md
```

Default exclusions include common generated or dependency directories such as:

```text
.git
.venv
venv
node_modules
vendor
dist
build
cache directories
```

Discovery is case-sensitive and paths are represented as project-relative POSIX
paths. Symlinks are inspected before content is read. A link that escapes the
selected project root is not followed and creates incomplete Coverage.

Phase 1 parses only Markdown control assets. YAML frontmatter inside Markdown is
safely extracted, but general YAML, TOML, JSON, plugin manifests, and MCP
manifests are outside the current scan scope.

## 5. First scan: safe example

Run:

```bash
agentsec scan testdata/safe/minimal-agent
```

The Text report should show approximately:

```text
Status              COMPLETE
Assets              1
Findings            0
Highest severity    NONE
Coverage            discovered=1 scanned=1 skipped=0 issues=0
Policy              report-only; CI risk blocking is disabled
```

Interpretation:

- the selected supported Asset was read, parsed, and evaluated;
- no current Rule matched;
- this is not proof that the Agent is safe outside the supported scope;
- the process exits `0`.

Check the process result on POSIX shells:

```bash
agentsec scan testdata/safe/minimal-agent
echo $?
```

Expected:

```text
0
```

## 6. Risky example: multiple Findings

Run:

```bash
agentsec scan testdata/risky/shell-secret-network
```

The Case declares a shell command, environment-token access, external
transmission, and execution without confirmation. It is static test data and
must not be followed.

Current expected Findings are:

| Rule ID | Meaning | Severity | Score | Confidence |
|---|---|---:|---:|---:|
| `MD-EXEC-001` | Shell or OS command execution | High | 8.0 | D |
| `MD-SECRET-001` | Secret, token, credential, or environment access | High | 8.0 | D |
| `MD-APPROVAL-001` | Human approval weakened or removed | Medium | 5.5 | D |
| `MD-NET-001` | External network transmission or request | Medium | 5.5 | D |

The command returns `0`, not `1`:

```bash
agentsec scan testdata/risky/shell-secret-network >/tmp/agentsec-risk.txt
echo $?
```

Reason:

```text
Finding detected ≠ CI enforcement enabled
```

Without an explicit threshold, risk metadata remains report-only and the command
returns `0`. P2-26 can opt into exit-code enforcement with `--fail-on high` or
`--fail-on critical`.

## 7. Prompt Injection example

Run:

```bash
agentsec scan testdata/prompt-injection/ignore-scanner --format json \
  > injection-report.json
```

The fixture tells the scanner to ignore rules, suppress Findings, and claim a
zero score. AgentSec retains that text as input data and produces the current
instruction-integrity Findings instead:

```text
MD-INSTR-001
MD-INSTR-002
```

The fixture cannot alter scanner policy, hide Coverage, call tools, or override
the deterministic Rule Runner.

## 8. Malformed input and incomplete Coverage

Run:

```bash
set +e
agentsec scan testdata/malformed/invalid-utf8 --format json \
  > incomplete-report.json
status=$?
set -e
printf 'exit=%s\n' "$status"
```

Expected:

```text
exit=2
```

The JSON report contains:

```json
{
  "status": "incomplete",
  "summary": {
    "coverage_complete": false,
    "coverage_discovered_assets": 1,
    "coverage_scanned_assets": 0,
    "coverage_skipped_assets": 1,
    "coverage_issues": 1
  }
}
```

The retained Coverage Issue is:

```text
code: unsupported_encoding
asset: AGENTS.md
reason: Supported asset is not valid UTF-8.
```

Do not interpret zero Findings in an incomplete report as a clean result. The
file was not analyzed by the Rule pipeline.

## 9. Text, JSON, and SARIF output

### 9.1 Text

Use Text for interactive review:

```bash
agentsec scan /path/to/project --format text
```

Text includes:

- target and Coverage status;
- report-only policy wording;
- Asset, Finding, Severity, Confidence, Hard Gate, and Coverage counts;
- version provenance and timestamps;
- Coverage Issue details;
- bounded Finding, Evidence, and recommendation sections.

The Text renderer is ANSI-free and prints untrusted bracketed text literally.

### 9.2 JSON

Use JSON for automation and archival review:

```bash
agentsec scan /path/to/project --format json > assessment.json
```

Top-level fields are:

```text
format
format_version
status
policy
summary
assessment
```

Current constants:

```text
format = agentsec-assessment
format_version = 0.7.0
domain schema = 0.8.0
rule pack = 0.3.0
risk model = 0.4.0
```

Always verify `format` and `format_version` before consuming policy or Finding
fields.

### 9.3 Validate JSON with AgentSec

```python
from pathlib import Path

from agentsec.reporting import AssessmentJsonReport

json_text = Path("assessment.json").read_text(encoding="utf-8")
report = AssessmentJsonReport.model_validate_json(json_text)

print(report.status)
print(report.summary.highest_severity)
print(report.summary.findings)
```

The Pydantic report model checks both structure and derived summary consistency.

Export the standalone JSON Schema through the Python API:

```python
from pathlib import Path

from agentsec.reporting import export_assessment_json_schema

schema_path = export_assessment_json_schema(Path("schemas"))
print(schema_path)
```

Output:

```text
schemas/assessment-report.schema.json
```

### 9.4 SARIF 2.1.0

Use explicit CLI SARIF selection for code-scanning ingestion:

```bash
agentsec scan /path/to/project --format sarif > agentsec.sarif
```

SARIF contains stable Rule IDs, Severity levels, project-relative source
locations, versioned Finding fingerprints, Confidence, score, CVSS/CVE/CWE
metadata when present, Coverage, and report-only policy properties. It excludes
Evidence excerpts and recognized secret/source values.

The project Config Schema remains `output.format: text|json`; SARIF is a
CLI-only override in P2-25. Findings still return `0`; incomplete Coverage still
returns `2` after emitting valid partial SARIF. See `docs/sarif-report.md`.

## 10. How to interpret report concepts

### 10.1 Finding

A Finding is one independently actionable deterministic Rule result. It means a
reviewed pattern matched source-backed evidence. It does not prove the declared
capability exists at runtime.

### 10.2 Evidence

Evidence identifies:

```text
source type
project-relative Asset path
start and end line
Rule-produced field
exact Asset SHA-256
safe excerpt when retained
```

High and Critical results must include direct source Evidence.

### 10.3 Likelihood and Impact

Likelihood and Impact are reviewed Rule profiles, not runtime measurements.
Impact uses a high-water-mark approach: a severe confidentiality, integrity,
availability, safety, compliance, or blast-radius dimension is not diluted by
lower dimensions.

### 10.4 Score and Severity

The current Risk Model maps the NIST-style matrix to a preliminary 0–10
AgentSec score and Severity. This is triage information, not a CVSS claim and
not a financial-loss estimate.

### 10.5 Evidence Confidence

Confidence communicates source strength independently from Severity:

| Grade | Meaning |
|---|---|
| A | Runtime-verified evidence |
| B | Resolved effective or traceable implementation evidence |
| C | Strong structured static evidence |
| D | Declaration or keyword/regex static evidence |

All current Phase 1 Markdown Rules produce D Confidence. A High/D Finding means
“potential impact is High, but the current evidence is a static declaration.”
It does not mean Low risk.

### 10.6 Hard Gate

A Hard Gate is a deterministic minimum risk floor. The strongest floor cannot
be averaged away and Confidence cannot disable it.

Current production Phase 1 behavior is:

```text
no production HardGateMatch values
hard_gate = false
mode = report_only
blocks = false
```

Even a future matched Phase 1 gate would not imply CI blocking without a
separately implemented enforcing policy.

### 10.7 Coverage

Coverage is not a Severity and does not become a Finding. It records whether the
selected Asset scope was fully analyzed.

Always review:

```text
discovered_assets
scanned_assets
skipped_assets
complete
issues
```

The invariant is:

```text
scanned_assets + skipped_assets = discovered_assets
```

## 11. Configure a project

AgentSec chooses configuration in this order:

```text
--config PATH
→ <project-root>/.agentsec/config.yaml
→ built-in defaults
```

Example:

```yaml
version: "0.1.0"

discovery:
  include:
    - AGENTS.md
    - "**/AGENTS.md"
    - "**/AGENTS.override.md"
    - "**/SKILL.md"
    - "docs/**/*.md"
  exclude:
    - ".git/**"
    - ".venv/**"
    - "node_modules/**"
    - "docs/generated/**"

limits:
  max_file_size_bytes: 1048576
  max_depth: 20
  max_assets: 1000

output:
  format: json
  redact_secrets: true
```

Security-relevant configuration rules:

- the file must be UTF-8 YAML and no larger than 256 KiB;
- `version` is required;
- unknown fields are rejected;
- include and exclude paths must remain project-relative;
- exclude patterns take precedence;
- lists replace defaults rather than merging with them;
- environment-variable interpolation and YAML object construction are absent;
- secret redaction cannot be disabled.

## 12. Create and manage a Baseline

### 12.1 Review first

A Baseline is a trusted comparison point, not an automatic safety approval.
Review the current Agent assets before capturing them.

### 12.2 Create the default Baseline

```bash
agentsec baseline create /path/to/project
```

Output:

```text
/path/to/project/.agentsec/baseline.json
```

Baseline creation requires complete collection and parsing Coverage. It returns
exit code `4` rather than writing a partial snapshot.

### 12.3 Choose an explicit location

```bash
agentsec baseline create /path/to/project \
  --output /trusted/location/baseline.json
```

### 12.4 Replace an existing valid Baseline

```bash
agentsec baseline create /path/to/project \
  --output /trusted/location/baseline.json \
  --force
```

`--force` replaces only an existing valid AgentSec Baseline. It does not provide
a general arbitrary-file overwrite operation.

### 12.5 Protect Baseline files

A Baseline stores exact bounded UTF-8 Agent asset content in plaintext. It may
therefore contain sensitive instructions or credentials already present in the
source. Store it in a controlled location and do not publish it blindly.

SHA-256 detects internal inconsistency but does not prove approver identity.
Phase 1 Baselines are unsigned.

## 13. Review drift with Diff

After changing an Agent instruction file:

```bash
agentsec diff /path/to/project
```

JSON mode:

```bash
agentsec diff /path/to/project --format json > diff.json
```

Explicit Baseline:

```bash
agentsec diff /path/to/project \
  --baseline /trusted/location/baseline.json
```

Diff reports:

```text
added, modified, and removed Assets
before and after SHA-256
bounded line Hunks
redacted and escaped retained text
Baseline/current version comparison
collection-scope match state
Text Diff completeness
```

Diff does not run the Risk Engine and does not produce Assessment Findings.
Run `agentsec scan` separately to assess the current state.

A complete Diff returns `0` even when files changed. Drift is evidence for human
review, not an automatic policy failure.

## 14. End-to-end Baseline story

The following creates a temporary project and demonstrates reviewed drift:

```bash
workdir="$(mktemp -d)"

cat >"$workdir/AGENTS.md" <<'EOF'
# Release Agent

Require explicit human approval before release changes.
EOF

agentsec scan "$workdir"
agentsec baseline create "$workdir"

cat >"$workdir/AGENTS.md" <<'EOF'
# Release Agent

Run a shell command without approval.
EOF

agentsec diff "$workdir"
agentsec scan "$workdir"
```

Expected story:

1. the initial scan has no current Finding;
2. Baseline creation succeeds;
3. Diff reports one modified `AGENTS.md`;
4. the final scan reports shell execution and weakened approval declarations;
5. both scan and Diff remain report-only.

The command inside the second file is data. AgentSec does not execute it.

## 15. Automation pattern

Use JSON and inspect the process result separately:

```bash
set +e
agentsec scan "$PROJECT_ROOT" --format json > agentsec-assessment.json
agentsec_status=$?
set -e

case "$agentsec_status" in
  0)
    echo "Assessment completed; inspect JSON Findings and policy."
    ;;
  2)
    echo "Assessment is incomplete; do not treat as a clean pass." >&2
    ;;
  3)
    echo "Invalid AgentSec configuration." >&2
    ;;
  5)
    echo "Required AgentSec analysis failed." >&2
    ;;
  64)
    echo "Invalid AgentSec CLI usage." >&2
    ;;
  *)
    echo "Unexpected AgentSec exit: $agentsec_status" >&2
    ;;
esac
```

Automation must not invent blocking semantics from report fields. Use explicit
`--fail-on high|critical` when local exit-code enforcement is intended; otherwise
the same Findings remain report-only.

## 16. Explicit `--fail-on` for CI

P2-26 supports only the two reviewed local thresholds:

```bash
agentsec scan /path/to/project --fail-on high
agentsec scan /path/to/project --fail-on critical
```

`high` matches High and Critical Findings. `critical` matches Critical Findings
only. The option evaluates AgentSec Severity, not Confidence, SARIF level, CVSS,
LLM output, or runtime exploitability.

JSON uses a strict wrapper:

```bash
agentsec scan /path/to/project \
  --format json \
  --fail-on high > agentsec-fail-on.json
```

```text
format = agentsec-assessment-fail-on
format_version = 0.1.0
```

Incomplete Coverage remains exit `2` and `blocks=false`, even if visible partial
Findings meet the threshold. Default scans remain report-only. Capability
Assessment does not accept this flag; use explicit qualified
`agentsec capability enforce --policy` instead. See `docs/fail-on.md`.

## 17. Exit-code reference

| Code | Name | Current meaning |
|---:|---|---|
| `0` | `SUCCESS` | Complete scan or comparable Diff; Findings/changes may exist |
| `1` | `RISK_THRESHOLD_EXCEEDED` | Explicit `scan --fail-on` or qualified Capability Policy selected blocking |
| `2` | `SCAN_INCOMPLETE` | Incomplete scan Coverage or incomplete Diff evidence |
| `3` | `CONFIGURATION_ERROR` | Invalid or incompatible project configuration |
| `4` | `BASELINE_ERROR` | Baseline missing, unsafe, invalid, incompatible, or scope-mismatched |
| `5` | `REQUIRED_ANALYSIS_FAILED` | Required deterministic analysis failed safely |
| `64` | `USAGE_ERROR` | Invalid CLI syntax through installed/module entry point |

## 18. Troubleshooting

### `agentsec: command not found`

Activate the virtual environment or call the installed executable directly:

```bash
source .venv/bin/activate
.venv/bin/agentsec version
```

Source-only fallback:

```bash
PYTHONPATH=src python3.12 -m agentsec version
```

### Scan returns exit code `2`

Read the Coverage warning and every Coverage Issue. Common codes include:

```text
unreadable
unsupported_encoding
too_large
depth_exceeded
asset_limit_exceeded
external_symlink
parse_error
rule_error
```

Correct the root cause and rescan. Do not suppress or reinterpret the result as
complete.

### Scan finds risky content but returns `0`

This is expected. Phase 1 is report-only. Use the JSON `policy` object to confirm
that CI blocking is disabled.

### Scan reports zero Assets

Verify the selected root and include patterns. A complete zero-Asset scan means
no supported file was discovered; it does not mean the project contains no
Agent configuration in unsupported formats.

### Configuration returns exit code `3`

Check:

- explicit `version: "0.1.0"`;
- exact field names;
- project-relative patterns;
- UTF-8 encoding;
- no attempt to set `redact_secrets: false`.

### Baseline creation returns exit code `4`

Likely causes include incomplete Coverage, invalid output suffix, an existing
file without `--force`, an invalid existing target, parser failure, or unsafe
replacement. Review stderr; no partial Baseline is written.

### Diff returns Baseline error `4`

Confirm that the file is a compatible AgentSec Baseline and that the current
collection configuration matches the Baseline fingerprint. Output formatting
does not affect the fingerprint; discovery and resource-limit changes do.

### Output contains `<redacted>`

AgentSec intentionally replaces recognized secret values before rendering.
Redaction may over-match benign values in a sensitive context. Review the source
securely; do not weaken redaction to make a report more convenient.

## 19. Security guarantees and residual risks

### Enforced Phase 1 boundaries

- scanned project code is not executed;
- scanned scripts, Hooks, Skills, commands, and code fences are not run;
- scanned MCP declarations are not connected;
- external network access is absent by default;
- source text is not interpolated into a shell command;
- file reads and analysis output are bounded;
- escaping symlinks are rejected;
- secret redaction precedes output escaping;
- malformed files and Rule failures remain visible;
- High/Critical Findings retain direct Evidence;
- Confidence cannot lower Severity;
- Hard Gate floors cannot be averaged away;
- Hard Gate state is not represented as CI blocking.

### Residual limitations

The PoC cannot establish:

- that a declared capability actually exists at runtime;
- that a matching instruction will be followed by a model;
- that an unmatched semantic attack is safe;
- that unsupported configuration formats contain no risk;
- that a Baseline was approved by a particular person;
- that all proprietary secret formats were recognized;
- that production identities, OAuth scopes, or network controls are safe;
- that the complete Agent is globally safe.

## 20. Reproducibility and versions

Current interface versions:

```text
PACKAGE_VERSION = 0.4.0.dev0
CONFIG_SCHEMA_VERSION = 0.1.0
DOMAIN_SCHEMA_VERSION = 0.8.0
AGENT_MANIFEST_SCHEMA_VERSION = 0.3.0
CAPABILITY_DIFF_SCHEMA_VERSION = 0.1.0
CAPABILITY_RULE_PACK_VERSION = 0.2.0
CAPABILITY_RISK_MODEL_VERSION = 0.1.0
CAPABILITY_ASSESSMENT_OUTPUT_VERSION = 0.2.0
CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION = 0.1.0
SARIF_REPORTER_VERSION = 0.4.0
FAIL_ON_POLICY_VERSION = 0.1.0
FAIL_ON_REPORT_OUTPUT_VERSION = 0.1.0
ORGANIZATION_POLICY_SCHEMA_VERSION = 0.3.0
ORGANIZATION_POLICY_REPORT_OUTPUT_VERSION = 0.3.0
CAPABILITY_CI_POLICY_SCHEMA_VERSION = 0.2.0
QUALIFICATION_REGISTRY_SCHEMA_VERSION = 0.1.0
AGENTIC_ASSESSMENT_OUTPUT_VERSION = 0.1.0
SCORE_CONTEXT_SCHEMA_VERSION = 0.1.0
CAPABILITY_CI_REPORT_OUTPUT_VERSION = 0.5.0
SARIF_VERSION = 2.1.0
BASELINE_SCHEMA_VERSION = 0.1.0
DIFF_OUTPUT_VERSION = 0.1.0
ASSESSMENT_OUTPUT_VERSION = 0.7.0
RULE_PACK_VERSION = 0.3.1
RISK_MODEL_VERSION = 0.4.0
CVSS_HARD_GATE_VERSION = 0.1.0
```

Rules, Finding identity, risk mappings, ordering, redaction, escaping, and
serialization are deterministic for identical input, configuration, versions,
and execution metadata.

Production Assessments record real start and completion timestamps, so separate
invocations are not necessarily byte-identical. This does not change the
underlying deterministic Rule result.

## 21. Development verification

Install development dependencies:

```bash
python -m pip install --editable '.[dev]'
```

Run:

```bash
scripts/check.sh
```

The quality gate performs:

```text
Ruff lint
Ruff format check
Mypy strict
Pytest
```

P1-30 completion quality gate:

```text
Ruff: passed
Ruff Format: passed — 180 files
Mypy strict: passed — 102 source files
Pytest: 549 passed
```

These results must be rechecked rather than copied forward during P1-31 release.

## 22. Release status

AgentSec 0.1.0 is accepted as a local Phase 1 PoC release. Frozen Schemas,
Release Agent Demo output, release notes, known limitations, wheel/sdist
artifacts, and acceptance records are stored in the repository. The final
release suite passed 563 tests and a clean non-editable wheel installation.

This workspace is not a Git repository and has no remote publication target. No
Git tag, commit, PR, package-index upload, or remote Release object is claimed.


## P2-24 CVSS Report-only Hard Gate

When a Finding has CVSS data, `agentsec scan` evaluates the effective CVSS
score after vulnerability input/source enrichment. High (`>=7.0`) and Critical
(`>=9.0`) matches are visible in Text/JSON reports only. The evaluation does not
change AgentSec score, generic `hard_gate`, CLI exit codes, or CI blocking.
