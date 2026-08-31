# AgentSec Manifest and Capability CLI

- Task: `P2I-04`
- Status: Complete
- Completion date: 2026-08-20
- Decision: `docs/decisions/0031-manifest-capability-cli-artifact-io.md`
- Depends on: P2I-01 Pipeline, P2I-02 Capability Rules, P2I-03 Reports

## 1. Command surface

P2I-04 exposes the Phase 2 static capability path:

```bash
agentsec manifest PROJECT [OPTIONS]
agentsec capability assess PROJECT [OPTIONS]
agentsec capability diff --before BEFORE.json --after AFTER.json [OPTIONS]
agentsec capability impact --before BEFORE.json --after AFTER.json [OPTIONS]
agentsec capability rules list [--language en|zh]
```

These commands are static, local, deterministic, and report-only. They do not
execute Commands, Hooks, Skills, plugins, Sub-Agents, Rules, or MCP servers; they
do not connect to endpoints or read environment/credential values; and they do
not prove runtime reachability or global Agent safety.

## 2. Generate an Agent Manifest

Text output:

```bash
agentsec manifest /path/to/agent \
  --agent-id release-agent \
  --format text
```

Canonical JSON to stdout:

```bash
agentsec manifest /path/to/agent \
  --agent-id release-agent \
  --format json > release-agent.manifest.json
```

Restricted atomic file output:

```bash
agentsec manifest /path/to/agent \
  --agent-id release-agent \
  --format json \
  --output artifacts/release-agent.manifest.json
```

Chinese Text:

```bash
agentsec manifest /path/to/agent \
  --agent-id release-agent \
  --language zh
```

Options:

```text
--working-directory PATH
--user-home PATH
--codex-home PATH
--agent-id ID
--format text|json
--language en|zh
--output PATH
--force
```

`--user-home` and `--codex-home` are explicit. AgentSec does not call
`Path.home()` or infer them from process environment in the application core.

Manifest JSON is the canonical Agent Manifest Schema `0.3.0` artifact. Complete
Coverage returns `0`; incomplete Coverage still writes/renders the partial
Manifest and returns `2`.

## 3. Run Capability Assessment

```bash
agentsec capability assess /path/to/agent \
  --agent-id release-agent \
  --format text
```

JSON artifact:

```bash
agentsec capability assess /path/to/agent \
  --agent-id release-agent \
  --format json \
  --output artifacts/release-agent.assessment.json
```

SARIF 2.1.0 artifact (P2-25):

```bash
agentsec capability assess /path/to/agent \
  --agent-id release-agent \
  --format sarif \
  --output artifacts/release-agent.assessment.sarif
```

Chinese management/developer report:

```bash
agentsec capability assess /path/to/agent \
  --agent-id release-agent \
  --language zh
```

The command runs:

```text
AgentAnalysisPipeline
→ final Agent Manifest
→ deterministic Capability Rule Pack 0.2.0
→ Capability Assessment Text, JSON, or SARIF 2.1.0
```

Findings remain report-only:

```text
Findings present + complete analysis → exit 0
Incomplete Coverage or Rule execution → exit 2
```

Capability Assessment JSON uses:

```text
format = agentsec-capability-assessment
format_version = 0.2.0
```

and fixes policy to CI blocking disabled and runtime capability not verified.
SARIF is an independently versioned delivery mapping (`0.1.0`) over the same
result; it does not change the JSON output version or enforcement semantics.

## 4. Compare saved Manifests

Create before and after artifacts with the same Agent ID:

```bash
agentsec manifest demos/baseline \
  --agent-id release-agent \
  --format json \
  --output /tmp/before.manifest.json

agentsec manifest demos/risky-drift \
  --agent-id release-agent \
  --format json \
  --output /tmp/after.manifest.json
```

Compare them:

```bash
agentsec capability diff \
  --before /tmp/before.manifest.json \
  --after /tmp/after.manifest.json \
  --format text
```

Machine output:

```bash
agentsec capability diff \
  --before /tmp/before.manifest.json \
  --after /tmp/after.manifest.json \
  --format json \
  --output /tmp/capability-diff.json
```

The first CLI version requires two saved Manifest files. Both inputs are read as
bounded regular non-symlink UTF-8 files and validated for Schema compatibility
before comparison. The Differ rejects different Agent IDs, Framework IDs, or
unsupported Manifest versions.

Capability Diff contains safe changed-field names, fingerprints, and source
provenance. It deliberately does not contain complete raw before/after values.
A complete comparison returns `0`; if either Manifest Coverage is incomplete,
the visible Diff is written/rendered and the command returns `2`.

## 5. Explain Change Impact and Finding Delta

P2-13 adds an additive source-development command:

```bash
agentsec capability impact \
  --before /tmp/before.manifest.json \
  --after /tmp/after.manifest.json \
  --format text
```

JSON output:

```bash
agentsec capability impact \
  --before /tmp/before.manifest.json \
  --after /tmp/after.manifest.json \
  --format json \
  --output /tmp/capability-impact.json
```

The report embeds the canonical Capability Diff and adds reviewed semantic
before/after fields for Tools, Permissions, and Controls, deterministic exposure
direction, and Finding Delta statuses (`added`, `resolved`, `changed`, and
`unchanged`). It does not expose source values, Commands, endpoints, Headers,
environment values, credentials, or memory content. See
`docs/capability-change-impact.md` and ADR-0033.

This command is report-only source development. It returns `0` for a complete
comparison even when a High Finding is added, and `2` when Coverage or Rule
execution is incomplete. The accepted `dist/0.2.0/` artifacts do not include P2-13 or Capability Rule
Pack `0.2.0` from P2-14 until a later release review.

## 6. Inspect Capability Rules

```bash
agentsec capability rules list
agentsec capability rules list --language zh
```

The inventory displays Capability Rule Pack `0.2.0`, stable Rule IDs, categories,
and reviewed localized titles. It is distinct from the Phase 1
`agentsec rules list` Markdown Rule inventory.

## 6. Artifact output safety

When `--output` is absent, stdout contains exactly the selected report. When it
is present, AgentSec writes the report and produces no success text on stdout.
Errors use stderr.

Filename requirements:

```text
--format json → .json
--format text → .txt
--format sarif → .sarif (Capability Assessment only)
```

New artifacts are created atomically with mode `0600`. Existing files are never
overwritten by default.

`--force` is deliberately restricted:

```text
may replace only an existing valid AgentSec artifact
of the same report kind and format
```

It cannot replace an unrelated JSON/Text/SARIF file, symbolic link, directory, or a
Capability Diff input artifact. `--force` without `--output` returns option error
`3`.

## 7. Exit codes

| Code | Meaning for P2I-04 |
|---:|---|
| `0` | Complete report-only Manifest, Assessment, or Diff; Findings may exist |
| `1` | Reserved; no risk-based blocking is enabled |
| `2` | Incomplete Coverage, Rule execution, or two-Manifest Diff |
| `3` | Invalid CLI option combination |
| `4` | Missing, invalid, incompatible, oversized, or unsafe input/output artifact |
| `5` | Required Pipeline, Rule, or Diff analysis failed safely |
| `64` | Invalid CLI syntax through the installed/module runner |

Automation should consume exit codes and JSON fields rather than parse Text.

## 8. Security and interpretation boundary

P2I-04 does not add:

```text
runtime Tool verification
OAuth scope enumeration
actual permission attestation
MCP connection or Tool execution
LLM analysis
Capability Hard Gates
--fail-on or CI blocking
waivers or organization Policy
automatic remediation
```

A complete report means the selected supported static assets and deterministic
Rules completed within configured limits. Zero Findings is not a safety
certificate. A static combination Finding is not proof that the capability chain
is reachable or exploitable at runtime.

## 9. Verification

P2I-04 tests cover:

- root, Manifest, Capability, Assess, Diff, and Rule help;
- canonical Manifest and Capability JSON through the real CLI;
- English and Simplified Chinese Text;
- complete and incomplete exit behavior;
- findings remaining exit `0` in report-only mode;
- bounded no-follow Manifest reads;
- invalid/missing/oversized Manifest input;
- Agent and Framework compatibility rejection;
- atomic mode-0600 output;
- no-clobber creation and race behavior;
- restricted same-kind `--force` replacement;
- unrelated, symbolic-link, and protected-input overwrite rejection;
- stdout/stderr separation;
- secret and endpoint value non-disclosure;
- installed `run_cli` Capability command behavior.

## 10. Next task

P2I-05 now provides the accepted bilingual Capability Drift story Demo on this
CLI surface. The next work is integration hardening, explicit Phase 2 release
review, and the remaining original Capability Rule/Hard Gate gaps.

## 11. P2-25 SARIF extension

`agentsec capability assess` now accepts `--format sarif`. The SARIF report retains
stable Rule IDs, source locations, versioned Finding fingerprints, Severity,
Confidence, Correlation, related IDs, Shadow Gate state, Coverage, and explicit
`ci_blocking_enabled=false` / `runtime_capability_verified=false` boundaries. It
does not copy source excerpts, Commands, URLs, Headers, environment values,
credentials, or memory content. See `docs/sarif-report.md` and ADR-0055.

## 12. P2-27 organization Policy

`capability enforce --policy` accepts Capability JSON `0.2.0` or organization YAML `0.2.0`. Unknown/Coverage checks remain fail closed. See `docs/organization-policy.md`.

## 13. P2-EXIT-01 Trusted Gate Qualification

Capability JSON Policies that list `qualified_gates` must pin a Qualified Gate Registry (`qualification.registry_path` plus an approved `registry_sha256`). Gate authority is granted only after the registry digest pin and the full qualification evidence-binding chain verify; forged, truncated, mismatched, or missing trust evidence fails closed with exit `3`. See `docs/decisions/0062-trusted-policy-and-qualification-root.md`.

## 14. P2-EXIT-02 Trusted CI Control Plane

`capability enforce` and `scan` accept `--trust-root`, `--expect-policy-sha256`, and (enforce only) `--expect-registry-sha256`. Organization YAML Policy `0.3.0` carries the same `capability.qualification` registry binding as the JSON path. Reports record trust mode and digest verification state (`agentsec-capability-ci-enforcement` `0.5.0`, organization assessment `0.3.0`). Digest mismatches, escaping policy paths, and unsafe trust roots fail closed with exit `3`. See `docs/trusted-ci.md`.

## 15. P2-EXIT-03 Integrated Agentic Score

`agentsec score PROJECT --before MANIFEST.json [--context CONTEXT.json]` runs the complete deterministic Agentic scoring chain (Factors, Threat/Mitigation, Technical, Drift, Governance, Overall, plus qualified Hard Gate floors) as report-only output in Text, JSON (`agentsec-agentic-assessment` `0.1.0`), or SARIF. Drift and Governance semantics come only from the explicit `agentsec-score-context` file or conservative unknowns. See `docs/agentic-score.md`.
