# AgentSec

AgentSec is an evidence-backed CLI for static security analysis of Agent
instruction and configuration assets.

The frozen Phase 1 PoC scans Markdown with 15 deterministic Rules. The current
source tree also builds structured Agent Manifests, evaluates deterministic
Capability Rules, compares Capability Drift, and produces bilingual Text,
versioned JSON, and SARIF 2.1.0 reports without executing scanned content.

> AgentSec reports security-relevant declarations. It does not prove runtime
> exploitability or claim that an Agent is globally safe.

## Current status

Current package version:

```text
0.4.0       (local Phase 3 Ready Candidate)
```

Accepted local releases, all preserved as frozen artifacts:

```text
agentsec-0.1.0  Phase 1 PoC            dist/            2026-08-19
agentsec-0.2.0  Phase 2 integration    dist/0.2.0/      2026-08-21
agentsec-0.3.0  internal MVP           dist/0.3.0/      2026-08-25
agentsec-0.4.0  Phase 3 candidate      dist/0.4.0/      2026-08-31
```

The source tree implements the complete Phase 2 capability chain and accepted
P2-EXIT closure. Phase 3 Shadow-only work has started. P3-01 defines the strict
`SemanticAnalysisContract`; P3-02 adds the fixed Prompt, approved in-memory
offline fixture Provider, bounded request/response contracts, and deterministic
`SemanticShadowInvocationAdapter`. P3-03 adds an explicitly opt-in HTTPS live
Provider seam and semantic Evaluation Harness; P3-04 adds a provider-specific
structured-JSON adapter, Offline/Live parity, and `agentsec semantic trial`; no live endpoint, credential,
network invocation, billing, retry, or external model call is configured in the
repository. P3-05 adds quality/Human Review/controlled Shadow promotion; P3-06
adds trusted Finding links and review-required Rule Candidates; P3-10 adds
controlled deterministic Rule promotion and Owner-reviewed Rule Pack staging.
P3-AG-01 starts the renumbered Capability Attack Graph track with the strict
value-free `agentsec-capability-attack-graph` Schema, P3-AG-02 adds the
deterministic `ManifestCapabilityGraphBuilder`, P3-AG-03 adds the
reviewed Attack Path pattern library and static matcher, and P3-AG-04
adds the value-free Attack Path report; no runtime claim exists yet. LLM output is candidate evidence only and
cannot affect deterministic CI or Policy decisions. Staging never publishes or
activates a Rule.

Command surface:

```text
agentsec version | scan | baseline create | diff | rules list
agentsec manifest PROJECT
agentsec capability assess | enforce | diff | impact | rules list
agentsec score PROJECT --before MANIFEST.json [--context CONTEXT.json]
```

Authoritative current facts live in two pages; the sections that follow are
historical development logs:

- [Current architecture](docs/current-architecture.md)
- [Current release status](docs/current-release-status.md)

> Historical note: the Phase 1 PoC completed through **P1-31** on 2026-08-19
> (Markdown discovery, Baseline/Diff, 15 deterministic Rules, NIST-style
> risk, confidence, report-only Hard Gate stage, Text/JSON reports, redaction,
> Coverage, 45-Case bilingual corpus, frozen Schemas, accepted Demo,
> wheel/sdist artifacts). The 0.2.0 artifacts remain the historical Phase 2
> integration release; later work landed in 0.3.0 and the 0.4.0 development
> line.

Phase 2 task P2-01 now adds parser-only JSON, YAML, and TOML support through a
common source-location-preserving interface. These formats are not yet selected
by `agentsec scan`; structured Asset discovery and Agent Manifest mapping remain
subsequent tasks.

P2-02 now adds non-executing Codex `.rules` `prefix_rule(...)` parsing and static
MCP server declaration parsing for STDIO, Streamable HTTP, and plugin-bundled
configurations. It does not evaluate commands, launch servers, connect to URLs,
or expose static environment/header values.

P2-03 defines a one-method Framework Adapter interface with portable asset
locators, neutral roles/formats, parser-coherent records, precedence hints, and
explicit Coverage.

P2-04 now provides the first production `CodexAdapter`. It discovers explicit
project-chain and user-scope Agent, Skill, Rules, TOML, and MCP assets through
bounded, UTF-8, symlink-contained reads. The Adapter does not execute commands,
load Skills, connect to MCP, read environment-variable values, call an LLM, or
change the current Phase 1 CLI.

P2-05 through P2-11 now define independently versioned Agent Manifest Schema `0.3.0`, with
strict source provenance, identity, instruction, tool, permission, control,
runtime identity, relationship, Unknown, and Coverage models. The initial
Builder copies no parsed source values and marks not-yet-resolved dimensions
explicitly instead of treating empty data as safe.

P2-07 adds a source-level `ConfigurationResolver` for Framework, Rules, and MCP
configuration. It preserves source precedence and application order without
merging raw configuration values or claiming that a complete file replaces all
lower-level fields.


P2-08 adds deterministic `AssociationExtractor` support for Skill, static MCP
server, and MCP tool declarations. It creates source-backed tool inventory and
`uses_skill`/`uses_mcp`/`uses_tool` relationships, classifies only conservative
static `stdio=execute`, `HTTP=network`, and bundled=`unknown` potential effects,
and preserves declared-vs-runtime boundaries. It never executes Skills or
commands, launches/connects to MCP, reads environment or secret values, or calls
an LLM.


P2-09 adds deterministic `CapabilityExtractor` support for static permissions,
controls, and credential-free MCP runtime identity hypotheses. It maps known
Tool side effects into read/write/execute/network/secret/admin permission facts,
converts explicit `.rules` decisions into allow/prompt/deny permission and
Prefix Rule control facts, and records MCP enablement, approval, filter, timeout,
network, secret-handling, authentication, and environment evidence. It keeps
permission effect separate from Tool availability and never reads credentials,
executes commands, connects to MCP, or calls an LLM.


P2-10 adds deterministic `RelationshipExtractor` support for explicit Markdown
frontmatter declarations of Sub-Agent delegation and memory read/write/persist
edges. It preserves Skill/MCP/tool relationships, merges duplicate edges with
full provenance, hashes unsafe targets, and does not infer relationships from
free-form prose or dereference paths. It never executes Sub-Agents, reads memory
stores, accesses environment values, connects to MCP, or calls an LLM.


P2-11 adds idempotent `UnknownExtractor` support and a versioned
`CapabilityDiffer`. Unknowns now explicitly identify unresolved profiles,
unknown item fields, runtime verification requirements, and incomplete Coverage.
Capability Diff compares tools, permissions, controls, identities, relationships,
Unknowns, and profile status using stable IDs, SHA-256 fingerprints, safe field
names, and source references without copying complete item values. The new
`CAPABILITY_DIFF_SCHEMA_VERSION` is `0.1.0`; it is not yet part of the CLI.

P2I-01 now adds `AgentAnalysisPipeline`, a single injectable application service
that runs P2-04 through P2-11 in a fixed order, validates the final Manifest,
and returns a bounded safe Stage Trace plus the current version vector. The
Pipeline invokes Association once and uses compatible already-associated
Capability/Relationship entry points to avoid repeated semantic extraction. It
remains static, report-only, non-LLM, and outside the current CLI.

P2I-02 introduced an independent deterministic Capability Rule Pack and Risk
Model. P2-14 now expands the source-tree Rule Pack to `0.2.0` with 29 bilingual
Rules covering approval gaps, production/external permissions, control gaps,
identity uncertainty, memory, delegation, and combination risks; the Capability
Risk Model remains `0.1.0`. Correlation
distinguishes same-target, parent/child, Agent-wide, and incomplete evidence;
Findings remain value-free, report-only, non-LLM, and outside the current CLI.

P2I-03 adds deterministic English/Chinese Text and JSON delivery for Agent
Manifest, Capability Assessment, and Capability Diff. Manifest and Diff JSON use
their canonical codecs; the strict Capability Assessment Output `0.1.0` embeds
the canonical Manifest and exposes report-only policy, management summary,
Findings, Stage Trace, and Rule failures.

P2I-04 now exposes this path through `agentsec manifest`, `agentsec capability
assess`, `agentsec capability diff`, and `agentsec capability rules list`. Saved
Manifest input is bounded and compatibility-validated; file output is private,
atomic, no-clobber by default, and restricts `--force` to the same valid artifact
kind. Findings remain report-only and the CLI never claims runtime verification
or global Agent safety.

P2I-05 now adds an accepted English/Chinese Capability Drift Demo with reviewed
baseline, risky, incomplete, and remediated states. The risky state produces
17 Findings across 16 Capability Rule IDs with highest High; remediation
returns to zero current Findings. Live and offline presenter flows preserve
report-only and no-runtime-proof boundaries.

P2-CAL-02 now adds a deterministic Fact Bundle Evaluation Runner with TP/FP/FN/TN,
Precision/Recall/F1, Macro/Micro metrics, Correlation and Evidence Confidence
agreement, Coverage/Unknown visibility, and versioned Text/JSON Calibration
Reports. The current seed replay is a fact-level smoke test, not a production
calibration claim.

P2-CAL-03 now adds a separate bounded Confidence Review Set and Confidence
Calibration Report contract. It calculates reviewer pair agreement, Cohen's
Kappa over A/B/C/D grades, Expected-vs-Emitted agreement, grade matrices, and
per-Rule/Correlation metrics, with bilingual Text/JSON delivery through
`scripts/run-confidence-calibration.py`. The checked-in 64 labels are seeded
fixture labels for 32 Findings; Kappa `1.000` is not independent production
review evidence and does not enable Hard Gates or CI blocking.

P2-CAL-04 now adds an independent Adjudication Review Set and a report-only
calibration report that separates detection FP/FN, policy-accepted risk,
out-of-scope/runtime uncertainty, and unresolved reviewer disagreement. It
produces deterministic per-Rule `more_data`/`tune`/`shadow`/`keep`
recommendations and assesses three Gate Candidates. The checked-in 122 labels
are seeded for 61 expectations, so every candidate remains
`more_data_required`; no Rule, Hard Gate, or CI behavior is changed.

P2-CAL-04A now completes the engineering preparation for independent human
calibration: a 216-Case expanded draft Corpus with 431 Rule Expectations, a
blinded Reviewer Pack `0.3.0` (216 opaque Cases and 431 Rule questions per
Reviewer), ADR-0038 Reviewer/Adjudication provenance with explicit `seed` and
`human` evidence modes, and a report-only Gate Calibration Coverage Check CLI.
Draft volume reaches 25 unique Positive and at least 21 unique eligible
Negative/Near-miss scenarios per Gate Candidate, but every label remains
`seeded`: Seed Labels are not production review results, and P2-CAL-04A
produces no Hard Gate qualification conclusion. All three candidates remain
`more_data_required`; Gate-candidate `hard_gate=true` and Gate-based CI blocking
remain disabled until real Reviewers complete blind review and adjudication.
P2-26 local Severity `--fail-on` is separate and cannot qualify these Gates. See
[`docs/calibration-adjudication-reviewer-pack.md`](docs/calibration-adjudication-reviewer-pack.md).

P2-CAL-01 now adds an independent Calibration Case/Corpus Schema `0.1.0`, a
bounded root-contained Loader, and 61 inert seed Cases. All 29 Capability Rule
IDs have match and no-match labels with expected Correlation and Evidence
Confidence. These are seed labels, not Precision/Recall results or Hard Gate
approval.

P2-13 now adds deterministic Capability Change Impact and Finding Delta analysis.
The additive `agentsec capability impact` command embeds the canonical
Capability Diff, exposes only reviewed Tool/Permission/Control semantic fields,
classifies increased/reduced/uncertain exposure, and matches Findings by
`rule_id + related_ids` so evidence-only hash changes do not look like a new
logical Finding. Added High/Critical Findings remain visible and are never
averaged away. See [`docs/capability-change-impact.md`](docs/capability-change-impact.md)
and ADR-0033.

## Adjudication and Gate Candidate quick start

Run P2-CAL-04 without executing any Agent or Fixture content:

```bash
.venv/bin/python scripts/run-calibration-adjudication.py \
  --corpus calibration \
  --adjudications calibration/adjudication-reviews.json \
  --format text --language zh
```

The report separates FP/FN categories, emits Rule tuning recommendations, and
shows why the three report-only Gate Candidates are not yet eligible. See
[`docs/calibration-adjudication-report.md`](docs/calibration-adjudication-report.md)
for thresholds and limitations.

## Reviewer Pack and Gate Coverage quick start

Verify the blinded Reviewer Pack and per-Gate draft sample volume without
executing any Fixture content:

```bash
.venv/bin/python scripts/build-reviewer-pack.py \
  --operation validate \
  --corpus calibration --pack calibration/reviewer-pack

.venv/bin/python scripts/check-gate-calibration-coverage.py \
  --corpus calibration \
  --matrix calibration/gate-coverage-matrix.json \
  --format json
```

The Coverage Check exits `0` only when every approved Gate Candidate holds at
least 20 unique Positive and 20 unique eligible Negative/Near-miss scenarios.
This is draft volume readiness only: the labels are still `seeded`, so the
result cannot qualify a Hard Gate. The human recruitment, blind review,
adjudication, and post-review import workflow is documented in
[`docs/calibration-adjudication-reviewer-pack.md`](docs/calibration-adjudication-reviewer-pack.md).

## Confidence calibration quick start

Run the P2-CAL-03 reviewer agreement report without executing any Agent content:

```bash
.venv/bin/python scripts/run-confidence-calibration.py \
  --corpus calibration \
  --reviews calibration/confidence-reviews.json \
  --format text --language zh
```

For machine-readable output, use `--format json --output <new-path>`. Explicit
output files are private (`0600`) and are not overwritten. See
[`docs/confidence-calibration-report.md`](docs/confidence-calibration-report.md)
for the statistical and security boundaries.

## Phase 2 capability CLI quick start

From a source checkout, build and assess one static Agent profile:

```bash
agentsec manifest . --agent-id local-agent --format text
agentsec capability assess . --agent-id local-agent --format text
agentsec capability assess . --agent-id local-agent --format sarif > agentsec.sarif
agentsec capability rules list --language zh
```

Save two canonical Manifests and compare normalized capability drift:

```bash
agentsec manifest /path/to/before --agent-id release-agent \
  --format json --output /tmp/before.manifest.json
agentsec manifest /path/to/after --agent-id release-agent \
  --format json --output /tmp/after.manifest.json
agentsec capability diff \
  --before /tmp/before.manifest.json \
  --after /tmp/after.manifest.json
```

Explain semantic impact and Finding Delta:

```bash
agentsec capability impact \
  --before /tmp/before.manifest.json \
  --after /tmp/after.manifest.json \
  --format text
```

Complete report-only analysis returns `0`; incomplete Coverage or Rule execution
returns `2`; unsafe or incompatible artifacts return `4`. See
[`docs/capability-cli.md`](docs/capability-cli.md).

Run the Capability Drift story:

```bash
scripts/run-capability-demo.sh --language en
scripts/demo-capability-drift.sh --language zh
```

Use `--offline --no-pause` on the presenter script for the checksum-validated
fallback.

## Requirements

- Python 3.12 or newer;
- a local source checkout of this repository;
- Git is optional and is used only for local Baseline provenance when available.

AgentSec does not require an LLM, model API key, MCP connection, or network
service. Rule Pack 0.3.0 supports reviewed English and Simplified Chinese
trigger phrases.

## Install from the source checkout

### macOS or Linux

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --editable .
agentsec version
```

Expected output:

```text
agentsec 0.2.0
```

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --editable .
agentsec version
```

Without installation, a source-checkout smoke test is also available:

```bash
PYTHONPATH=src python3.12 -m agentsec version
```

## Five-minute quick start

### 0. Inspect the Chinese Rule inventory

```bash
agentsec rules list --language zh
```

Run the Chinese presenter Demo with:

```bash
scripts/demo-developer.sh --case-language zh --show-rules
```

See [`docs/rule-pack-zh.md`](docs/rule-pack-zh.md) and
[`demos/release-agent-zh/`](demos/release-agent-zh/README.md).

### 1. Scan a safe example

From the repository root:

```bash
agentsec scan testdata/safe/minimal-agent
```

Expected outcome:

```text
Status: COMPLETE
Assets: 1
Findings: 0
Exit code: 0
```

Zero Findings means only that no current deterministic Rule matched within the
supported scope. It is not a global safety guarantee.

### 2. Scan a risky example

```bash
agentsec scan testdata/risky/shell-secret-network
```

This Case produces four Findings covering:

```text
shell execution
secret or environment access
external network transmission
removed human confirmation
```

The highest current Severity is High. The command still returns exit code `0`
because Phase 1 is report-only and does not block CI based on Findings.

### 3. Produce machine-readable JSON

```bash
agentsec scan testdata/risky/shell-secret-network \
  --format json \
  > assessment.json
```

The output format is:

```text
format = agentsec-assessment
format_version = 0.2.0
```

The JSON explicitly records:

```text
enforcement_mode = report_only
ci_blocking_enabled = false
global_safety_claimed = false
```

### 4. Produce SARIF 2.1.0

```bash
agentsec scan testdata/risky/shell-secret-network \
  --format sarif \
  > agentsec.sarif
```

SARIF preserves stable Rule IDs, source locations, fingerprints, Severity,
Confidence, score, Coverage, and policy boundaries without copying Evidence
excerpts or recognized secret/source values. SARIF selection alone does not
enable CI blocking; P2-26 records an explicitly selected fail-on decision.

### 5. Opt into CI blocking with `--fail-on`

```bash
set +e
agentsec scan testdata/risky/shell-secret-network \
  --fail-on high
code=$?
set -e
printf 'exit=%s\n' "$code"
```

P2-26 supports `high` and `critical` only. Default scans remain report-only.
Incomplete Coverage returns `2` instead of a risk-policy block. JSON emits the
versioned `agentsec-assessment-fail-on` wrapper; SARIF records the explicit
AgentSec decision without treating SARIF level as authority. See
[`docs/fail-on.md`](docs/fail-on.md).


### 6. Use one organization Policy

```bash
agentsec scan /path/to/project   --policy policies/organization-policy-enforce-example.yaml

agentsec capability enforce /path/to/agent   --policy policies/organization-policy-enforce-example.yaml
```

P2-27 YAML configures Scan `high|critical`, blocking Rule IDs, and qualified
Capability Gates. Rule scope affects blocking only and never hides Findings.
See [`docs/organization-policy.md`](docs/organization-policy.md).

### 7. Observe incomplete Coverage

```bash
agentsec scan testdata/malformed/invalid-utf8 --format json
```

Expected outcome:

```text
status = incomplete
coverage issue = unsupported_encoding
exit code = 2
```

Incomplete Coverage is a partial result and must not be treated as a clean pass.

## Scan your own project

```bash
agentsec scan /path/to/project
agentsec scan /path/to/project --format text
agentsec scan /path/to/project --format json
agentsec scan /path/to/project --format sarif > agentsec.sarif
agentsec scan /path/to/project --config /path/to/config.yaml
```

Phase 1 automatically discovers these exact filenames recursively:

```text
AGENTS.md
AGENTS.override.md
SKILL.md
```

Additional lowercase `.md` files can be explicitly included through project
configuration.

## Inspect the built-in Rule Pack

```bash
agentsec rules list
```

The command lists all 15 stable Rule IDs, categories, and titles from Rule Pack
`0.2.0`. It reads trusted packaged metadata and does not scan a project.

## Minimal project configuration

Create `<project-root>/.agentsec/config.yaml`:

```yaml
version: "0.1.0"

discovery:
  include:
    - AGENTS.md
    - AGENTS.override.md
    - SKILL.md
    - "**/AGENTS.md"
    - "**/AGENTS.override.md"
    - "**/SKILL.md"
  exclude:
    - ".git/**"
    - ".venv/**"
    - "node_modules/**"
    - "dist/**"
    - "build/**"

limits:
  max_file_size_bytes: 1048576
  max_depth: 20
  max_assets: 1000

output:
  format: text
  redact_secrets: true
```

Configuration precedence is:

```text
explicit --config
→ <project-root>/.agentsec/config.yaml
→ secure built-in defaults
```

Configured output format precedence remains:

```text
--format text|json
→ config output.format
→ text
```

`scan --format sarif` is an explicit P2-25 CLI-only override. The Config Schema
still accepts only `text|json`; `diff` does not accept SARIF.

Secret redaction cannot be disabled in Phase 1.

## Baseline and Diff workflow

Create a trusted local snapshot only after reviewing the current Agent assets:

```bash
agentsec baseline create /path/to/project
```

The default output is:

```text
/path/to/project/.agentsec/baseline.json
```

After the Agent files change, compare them with the snapshot:

```bash
agentsec diff /path/to/project
agentsec diff /path/to/project --format json
```

Use an explicit Baseline location when required:

```bash
agentsec baseline create /path/to/project \
  --output /trusted/location/baseline.json

agentsec diff /path/to/project \
  --baseline /trusted/location/baseline.json
```

Important distinctions:

- `scan` reports current deterministic security Findings;
- `baseline create` captures exact bounded UTF-8 content and metadata;
- `diff` reports textual drift and does not assign risk by itself;
- a Baseline is sensitive plaintext and is not an approval signature;
- changed files alone do not cause a nonzero risk-policy exit.

## How to read a Finding

| Field | Meaning |
|---|---|
| Rule | Stable deterministic detection identity |
| Category | Type of declared security-relevant behavior |
| Likelihood | Preliminary NIST-style likelihood profile |
| Impact | Highest reviewed impact dimension; not an average |
| Score | Preliminary AgentSec 0–10 mapping |
| Severity | Risk magnitude derived from the current Risk Model |
| Confidence | Strength of available Evidence, independent from Severity |
| Hard Gate | Whether a deterministic risk floor matched; report-only in Phase 1 |
| Evidence | Project-relative file, line range, hash, field, and safe excerpt |
| Recommendations | Reviewed follow-up actions |

All 15 Markdown Rules currently use static source evidence and therefore report
Confidence `D`. A High/D Finding remains High: weak evidence confidence does not
lower or erase possible impact.

## Coverage is separate from risk

Coverage answers whether the selected input was successfully evaluated.
Findings answer which deterministic Rules matched.

```text
COMPLETE + Findings     → analysis completed and signals were found
COMPLETE + no Findings  → no current Rule matched; not a safety guarantee
INCOMPLETE              → partial result; review every Coverage Issue
```

Coverage problems include invalid UTF-8, unreadable or oversized files, unsafe
paths, traversal limits, parser failures, and isolated Rule failures.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Command succeeded; Findings remain report-only |
| `1` | Reserved for a future enforcing risk threshold; not produced in Phase 1 |
| `2` | Scan or Diff Coverage is incomplete |
| `3` | Project configuration is invalid or incompatible |
| `4` | Baseline is missing, invalid, incompatible, or unsafe |
| `5` | A required analysis stage failed safely |
| `64` | Invalid CLI syntax through the installed/module entry point |

Automation must use exit codes and JSON fields rather than parsing Rich Text.

## Security boundaries

AgentSec:

- never executes scanned code blocks, scripts, Hooks, Skills, commands, or tools;
- never connects to an MCP server declared by scanned content;
- performs no external network access by default;
- does not interpolate scanned text into shell commands;
- does not follow a symbolic link outside the selected root by default;
- bounds file size, traversal depth, asset count, matching, Diff, and Text output;
- redacts recognized secrets before escaping control characters;
- makes incomplete Coverage visible;
- requires direct Evidence for every final Finding;
- keeps Severity, Confidence, Hard Gate state, and CI policy separate.

## Current limitations

The frozen Phase 1 release does not provide:

- general TOML, YAML, JSON, plugin, or MCP-manifest parsing;
- effective capability or permission resolution;
- runtime identity, OAuth-scope, or tool availability verification;
- semantic Diff or LLM analysis;
- production Hard Gate combination detectors;
- waivers or automatic remediation; the current source supports explicit local
  fail-on and P2-27 organization-level YAML Policy;
- HTML or a Web console; the current source tree adds P2-25 SARIF but the
  accepted Phase 1/0.2.0 release artifacts are not rebuilt by this task;
- financial-loss estimates or a global safety verdict;

## Release artifacts and full PoC guide

The local release includes:

- frozen Schemas under [`schemas/`](schemas/README.md);
- Release Agent Demo under [`demos/release-agent/`](demos/release-agent/README.md);
- [0.1.0 release notes](docs/releases/0.1.0.md);
- [known limitations](docs/releases/0.1.0-known-limitations.md);
- [release acceptance record](docs/releases/0.1.0-acceptance.md);
- wheel, sdist, and SHA-256 files under `dist/`.

Rebuild and verify the local artifacts with:

```bash
scripts/build-release.sh
scripts/verify-release-install.sh
```

See [`docs/poc-usage.md`](docs/poc-usage.md) for:

- a complete first-run walkthrough;
- Safe, Risky, Prompt Injection, and Malformed examples;
- Text and JSON interpretation;
- Python JSON validation;
- Baseline lifecycle and Diff review;
- automation patterns;
- troubleshooting and residual risks.

## Development setup

Install the development dependencies:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --editable '.[dev]'
```

Run the complete local/CI quality gate:

```bash
scripts/check.sh
```

The gate runs Ruff linting, Ruff formatting verification, strict Mypy, and
Pytest. A different Python 3.12 executable can be selected with:

```bash
PYTHON=/path/to/python scripts/check.sh
```

## P2-29 CI examples

AgentSec now includes an executable GitHub Actions workflow, a GitLab example,
and a shared Runner that preserves JSON/SARIF before enforcing the deterministic
Organization Policy exit code. Validate the full safe/block/incomplete/waiver
matrix locally with:

```bash
.venv/bin/python scripts/validate-ci-examples.py \
  --agentsec .venv/bin/agentsec
```

See [`docs/ci-integration.md`](docs/ci-integration.md). Real pilot repository
rollout and remote PR evidence remain P2-30.

## P2-30 internal pilot

The first versioned pilot now replays eight Release Agent scenarios through the
real Organization Policy CI Runner and collects decision, Coverage, unique-Rule
FP/FN, and local performance evidence. Run it with:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-pilot.py \
  --agentsec .venv/bin/agentsec
```

See [`docs/pilot-integration.md`](docs/pilot-integration.md). The checked-in
evidence is explicitly an internal integration pilot, not remote production
accuracy or runtime exploitability evidence.

## P2-31 Rule and score calibration v1

The P2-30 Pilot and P2-24 score suite now replay into a versioned Rule-by-Rule
calibration report. Current evidence retains Rule Pack `0.3.0` and Risk Model
`0.4.0`; six Rules remain `more_data`, and no automatic Rule or score publication
is allowed. Run:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-rule-score-calibration.py \
  --agentsec .venv/bin/agentsec
```

See [`docs/rule-score-calibration.md`](docs/rule-score-calibration.md).

## Documentation map

### Start here

- [Current architecture (authoritative)](docs/current-architecture.md)
- [Current release status (authoritative)](docs/current-release-status.md)
- [PoC usage guide](docs/poc-usage.md)
- [Phase 1 scope](docs/scope.md)
- [Project configuration](docs/configuration.md)
- [CLI integration](docs/cli-integration.md)
- [Exit codes](docs/exit-codes.md)
- [CI integration examples](docs/ci-integration.md)
- [Trusted CI control plane](docs/trusted-ci.md)
- [Organization Policy](docs/organization-policy.md)
- [Policy-controlled CI enforcement (P2-15B)](docs/p2-15b-policy-controlled-ci-enforcement.md)
- [Integrated Agentic Score](docs/agentic-score.md)
- [Pilot integration](docs/pilot-integration.md)
- [Rule and score calibration](docs/rule-score-calibration.md)

### Reports and security interpretation

- [Assessment Text report](docs/assessment-text-report.md)
- [Assessment JSON report](docs/assessment-json-report.md)
- [Phase 2 Capability reports](docs/capability-reports.md)
- [Manifest and Capability CLI](docs/capability-cli.md)
- [Capability Drift Demo](docs/capability-drift-demo.md)
- [Capability Change Impact / Finding Delta](docs/capability-change-impact.md)
- [Coverage reporting](docs/coverage-report.md)
- [Risk Model](docs/risk-model.md)
- [Evidence Confidence](docs/confidence-model.md)
- [Hard Gate semantics](docs/hard-gate.md)
- [Secret redaction](docs/secret-redaction.md)
- [Calibration Corpus](calibration/README.md)
- [Independent Reviewer Pack guide](docs/calibration-adjudication-reviewer-pack.md)

### Collection, Baseline, and Diff

- [Path safety](docs/path-safety.md)
- [Resource limits](docs/resource-limits.md)
- [Markdown parser](docs/markdown-parser.md)
- [Phase 2 scope](docs/phase2-scope.md)
- [JSON/YAML/TOML structured parsers](docs/structured-parsers.md)
- [Rules and MCP specialized parsers](docs/rules-mcp-parsers.md)
- [Framework Adapter interface](docs/framework-adapter-interface.md)
- [Codex Adapter](docs/codex-adapter.md)
- [Agent Manifest Schema](docs/agent-manifest-schema.md)
- [Instruction Resolver](docs/instruction-resolver.md)
- [Configuration Precedence Resolver](docs/configuration-precedence-resolver.md)
- [Baseline creation](docs/baseline-create.md)
- [Baseline Schema](docs/baseline-schema.md)
- [Asset Diff](docs/asset-diff.md)
- [Text Diff](docs/text-diff.md)
- [Diff CLI](docs/diff-cli.md)

### Rules, tests, and project governance

- [Rule Pack](docs/rule-pack.md)
- [中文 Rule Pack](docs/rule-pack-zh.md)
- [Rule pipeline](docs/rule-pipeline.md)
- [Test corpus](docs/test-corpus.md)
- [Threat model](docs/threat-model.md)
- [Semantic analysis contract](docs/semantic-analysis-contract.md)
- [Semantic Shadow invocation](docs/semantic-shadow-invocation.md)
- [Semantic evaluation](docs/semantic-evaluation.md)
- [Provider-specific semantic trial](docs/provider-specific-semantic-trial.md)
- [Semantic Finding integration and Rule Candidates](docs/semantic-finding-integration.md)
- [Semantic Shadow Pipeline](docs/semantic-shadow-pipeline.md)
- [Semantic Candidate Calibration and Rule Replay](docs/semantic-candidate-calibration.md)
- [Attack Path CLI and Report](docs/tasks/P3-AG-04B-attack-graph-cli-wiring.md)
- [Versioning](docs/versioning.md)
- [Skill / MCP / Tool Association](docs/skill-mcp-tool-association.md)
- [Static Capability Profile](docs/static-capability-profile.md)
- [Sub-Agent / Memory Relationships](docs/sub-agent-memory-relationships.md)
- [Explicit Unknowns / Capability Diff](docs/manifest-unknowns-capability-diff.md)
- [Full Agent Analysis Pipeline](docs/agent-analysis-pipeline.md)
- [Deterministic Capability Rules](docs/capability-rules.md)
- [Phase 2 Integration Closure Plan](docs/phase2-integration-plan.md)
- [Developer and management Demo plan](docs/demo-plan.md)
- [Domain glossary](CONTEXT.md)

## P2-32 internal MVP release

The complete internal MVP is packaged as AgentSec `0.3.0` under `dist/0.3.0/`.
The release preserves the calibrated Markdown Rule Pack `0.3.0` and Risk Model
`0.4.0`, includes CI/Pilot/Calibration evidence, and passes clean offline Wheel
installation. See [`docs/releases/0.3.0.md`](docs/releases/0.3.0.md) and the
[acceptance record](docs/releases/0.3.0-acceptance.md).

## Release status

AgentSec 0.1.0 remains the accepted local Phase 1 PoC release and 0.2.0 remains
the preserved Phase 2 Integration release. AgentSec 0.3.0 is the accepted local
internal MVP, adding Capability Impact, expanded deterministic Rules, CVSS and
Agentic scoring, SARIF, explicit fail-on, Organization Policy, Waivers, qualified
Capability enforcement, CI examples, Pilot evidence, and Rule/Score calibration.

The source tree now runs the locally accepted `0.4.0` Phase 3 Ready Candidate.
P2-EXIT-08 Stage 2 reached `candidate_go`; Phase 2 and P2-EXIT-01～08A are complete, including the external Homi Pilot, independent
Human Evidence, package/supply-chain hardening, and Phase 3 entry review. Phase 3
has started in Shadow-only mode; the Semantic Track runs P3-01～P3-11B, and
the Attack Graph Track has delivered the Schema (P3-AG-01), the
`ManifestCapabilityGraphBuilder` (P3-AG-02), the Attack Path pattern
library and matcher (P3-AG-03), and the value-free Attack Path report
(P3-AG-04). So far P3-04 adds
the provider-specific adapter, Offline/Live parity, and `agentsec semantic trial`,
but no live Provider is configured. The authoritative
status is
[`docs/current-release-status.md`](docs/current-release-status.md).

This workspace is a local Git working tree and has no configured remote publication
target. No Git tag, signed commit, PR, package-index upload, remote Release
object, production deployment, or CI enforcement is claimed.

## P2-28 risk waivers

Organization Policy `0.3.0` supports expiring Owner/Reason/Expiry Waivers for Finding, Rule, and qualified Gate scope. Waivers live inside pinned Policy artifacts, never hide Findings, and expired Waivers automatically lose effect. See [`docs/risk-waivers.md`](docs/risk-waivers.md).

### Attack Path Evidence Association (P3-AG-05)

The Python API can correlate a validated static Attack Graph with existing
Finding and Shadow Semantic Evidence without granting authority:

```python
from agentsec.attack_graph import AttackPathEvidenceAssociator

report = AttackPathEvidenceAssociator().associate(
    graph,
    findings=findings,
    semantic_result=semantic_result,
    semantic_evidence=semantic_chunks,
)
```

The report is deterministic and value-minimized: matching requires normalized
asset path, content SHA-256, and overlapping line ranges. It reports
`duplicates`, `supports`, `partially_supports`, or `unmatched` and never
creates Findings, changes Severity/Confidence, blocks CI, or claims runtime
reachability. See
`docs/tasks/P3-AG-05-semantic-deterministic-evidence-association.md`.


### Attack Path Evidence Association CLI (P3-AG-06)

Associate a validated graph with existing Finding and Shadow Semantic Evidence:

```bash
agentsec attack-graph-associate \
  --graph graph.json \
  --findings findings.json \
  --semantic-result semantic-result.json \
  --semantic-evidence semantic-evidence.json \
  --format json \
  --output association-report.json
```

For end-to-end project mode, replace `--graph graph.json` with
`--project ./homi-agent`. The command is report-only and never executes the
scanned project or blocks CI.


### Attack Path Story Demo (P3-AG-07)

Run the bounded Homi-like story Demo through the production CLI:

```bash
scripts/run-attack-path-demo.sh
scripts/demo-attack-path.sh --no-pause
```

The story shows a static path, an existing deterministic Finding, Shadow
Semantic Candidates, and `duplicates` / `partially_supports` / `unmatched`
Evidence associations. It is fully offline and report-only; it does not execute
the fixture or prove runtime reachability.


### Attack Path Evidence Calibration (P3-AG-08)

Evaluate reviewed labels against the frozen association report:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-attack-path-calibration.py
```

The pilot distinguishes exact, partial, unmatched, and missing associations and
remains report-only. The checked-in three-case seed is wiring evidence, not a
production Precision/Recall qualification claim.

### P3-REL-01 current source / candidate reconciliation

The current source tree can be reconciled into a new local candidate without
overwriting the preserved `dist/0.4.0/` artifacts:

```bash
.venv/bin/python scripts/reconcile-candidate-artifacts.py
```

The command builds fixed-epoch Wheel/sdist artifacts, checks that all current
modules and Schemas are packaged, installs the Wheel offline, and smoke-tests
the Attack Graph and Score CLIs. Output is written to
`dist/candidates/0.4.0-p3-rel-01/`. This proves source/package consistency
only; it does not claim signatures, SLSA provenance, runtime capability,
Provider quality, or production readiness.

### P3-REL-02 reconciled Candidate Acceptance

Candidate Acceptance can now consume the current source-reconciled Candidate
instead of implicitly checking the historical `dist/0.4.0/` directory:

```bash
PYTHONPATH=src .venv/bin/python scripts/run-phase3-entry-review.py \
  --repository-root . \
  --stage candidate_acceptance \
  --entry-readiness-report \
    docs/reviews/phase3-entry-readiness-2026-08-26.json \
  --reconciled-candidate-report \
    dist/candidates/0.4.0-p3-rel-01/reconciliation-report.json \
  --release-provenance-bundle \
    dist/candidates/0.4.0-p3-rel-01/provenance-bundle.json \
  --format json
```

The state machine rechecks the reconciled Candidate's source inventory digest,
artifacts, checksums, reproducibility, and installed CLI smoke evidence. The
historical candidate remains preserved and no publication or production
authority is implied.

### P3-REL-03 byte-level content reconciliation

The reconciliation report also verifies the actual bytes of each packaged
Python module, Schema, and sdist release metadata file against the current
source tree:

```bash
.venv/bin/python scripts/reconcile-candidate-artifacts.py --force
```

The report contains `content_checks` plus bounded mismatch paths. Candidate
Acceptance requires all content checks to pass and all mismatch lists to be
empty; recomputing `SHA256SUMS` after changing an archive member is therefore
not sufficient. No source content is printed, and this remains local,
report-only evidence.

### P3-18 Semantic Gate Definition / Controlled Qualification

Create a digest-bound Semantic Gate candidate and qualify it against explicit
sample, quality, human-confidence, and upstream P3-05/P3-07/P3-10 evidence:

```bash
PYTHONPATH=src .venv/bin/python scripts/create-semantic-gate-candidate.py \
  --gate-id SG-INSTRUCTION-INTEGRITY-001 \
  --title "Instruction integrity" \
  --description "Detect semantic instruction integrity risks." \
  --signal instruction_integrity \
  --output calibration/semantic-gates/sg-instruction-integrity-001.json
```

Run the deterministic report-only qualification with
`scripts/run-semantic-gate-qualification.py`. The result distinguishes
`qualified`, `conditionally_qualified`, and `not_qualified`; missing review or
confidence evidence is pending. Qualification never grants CI, Rule, Waiver,
runtime, Hard Gate, or release authority.

### P3-REL-04 release manifest and provenance bundle

Bind the reconciled Candidate, source inventory, byte-level report,
lockfiles/SBOM/license evidence, and explicit non-claims into a deterministic
release evidence bundle:

```bash
.venv/bin/python scripts/build-release-provenance-bundle.py --force
```

The command writes `release-manifest.json`, `provenance-bundle.json`, and
`PROVENANCE-SHA256SUMS` under
`dist/candidates/0.4.0-p3-rel-01/`. Candidate Acceptance consumes the bundle
with `--release-provenance-bundle` and fails closed on stale paths, digests,
sizes, source inventory, supply-chain evidence, or authority claims. This is
local report-only evidence; it does not claim signatures, SLSA provenance,
Runtime Attestation, publication, or production deployment.
