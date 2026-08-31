# AgentSec Phase 1 CLI Integration

- Task: `P1-29`
- Status: Complete
- Decision date: 2026-08-19

## 1. Purpose

P1-29 connects the previously independent Phase 1 components into the real
`agentsec scan` command and protects the full command surface with end-to-end
regression tests.

The production scan path is now:

```text
ProjectConfig
→ MarkdownAssetCollector
→ MarkdownItParser
→ RuleContext
→ 15-Rule DeterministicRuleRunner
→ DeterministicRiskEngine
→ DeterministicConfidenceEngine
→ DeterministicHardGateEngine (report-only, no production matches)
→ final Domain Finding
→ AssessmentTextRenderer or AssessmentJsonRenderer
```

Scanned Markdown remains untrusted data at every stage. No stage receives an
execution, network, Skill, Hook, MCP, or scanned-import capability.

## 2. Scan output selection

`agentsec scan` supports both final Assessment formats:

```bash
agentsec scan .
agentsec scan . --format text
agentsec scan . --format json
```

Precedence is:

```text
--format text|json
→ output.format from the effective project config
→ text default
```

Text uses the bounded ANSI-free Rich Assessment report. JSON uses the strict
`agentsec-assessment` format and remains valid against
`AssessmentJsonReport` / `assessment-report.schema.json`.

Configuration and required-analysis failures remain diagnostic stderr rather
than pretending to be an Assessment document. JSON operational error documents
are not part of Phase 1.

## 3. Result and exit semantics

| Condition | Exit code | Report behavior |
|---|---:|---|
| Complete Coverage, zero or more Findings | `0` | Full Text or JSON Assessment |
| Incomplete Collector, Parser, or Rule Coverage | `2` | Partial Assessment with visible Coverage Issues |
| Invalid configuration | `3` | Safe configuration diagnostic on stderr |
| Required Rule/Risk/Confidence/Hard Gate analysis failure | `5` | Safe fixed-stage diagnostic; no partial Assessment |

Findings do not produce exit code `1` in Phase 1. Hard Gate processing is
executed, but the production Phase 1 path supplies no `HardGateMatch` values and
all matches would remain report-only. `--fail-on` and CI blocking are still
absent.

## 4. Coverage composition

The integrated engine keeps these distinctions:

- Collector failures are retained as Collector Coverage Issues.
- Parser failures are isolated per Asset and recorded as `parse_error`.
- Rule failures are isolated per Rule × Asset and recorded as `rule_error`.
- Risk, Confidence, Hard Gate, or final Finding assembly failures are required
  analysis failures and return exit code `5`; a partial score is not emitted.

Coverage always preserves:

```text
scanned_assets + skipped_assets == discovered_assets
```

A partial result never appears as complete or as a clean pass.

## 5. Integration regression suite

`tests/test_cli_integration.py` exercises:

1. all current 45 Safe, Risky, Prompt Injection, and Malformed Corpus Cases through the
   real `scan --format json` CLI;
2. exact unique Rule IDs from each Case manifest;
3. JSON Schema-backed model validation;
4. Text/JSON config selection and CLI override precedence;
5. final Rule → Risk → Confidence → Hard Gate → Domain Finding assembly;
6. Complete and Incomplete Coverage with stable exit codes;
7. isolated Rule failure and required-analysis failure behavior;
8. shared secret redaction and control-character escaping;
9. no shell, subprocess, OS command, URL fetch, or socket action while scanning;
10. inert Script, Hook, Skill, and MCP instructions;
11. deterministic JSON for identical input, versions, config, and execution
    metadata;
12. a real `baseline create → mutate → diff` Text/JSON command story.

The embedded-NUL Malformed Case now records `MD-OBFUSC-001`, matching the real
parser indicator and production Rule pipeline. This corrects a fixture
expectation; it does not change Rule meaning or Rule Pack version.

## 6. Determinism boundary

Rule evaluation, Finding identity, risk mapping, Confidence, Hard Gate
application, array ordering, redaction, escaping, and serialization are
deterministic for identical inputs and versioned configuration.

Assessment metadata intentionally records real start and completion timestamps.
Two independent production invocations therefore need not be byte-identical.
Tests fix execution metadata when asserting byte-for-byte output determinism.
This is execution provenance, not nondeterministic Rule behavior.

## 7. Version decision

P1-29 reuses existing interfaces and changes no serialized shape or risk
meaning:

```text
CONFIG_SCHEMA_VERSION = 0.1.0
DOMAIN_SCHEMA_VERSION = 0.8.0
BASELINE_SCHEMA_VERSION = 0.1.0
DIFF_OUTPUT_VERSION = 0.1.0
ASSESSMENT_OUTPUT_VERSION = 0.7.0
RULE_PACK_VERSION = 0.3.1
RISK_MODEL_VERSION = 0.4.0
```

No ADR or version increment is required because P1-29 composes already-versioned
components and adds CLI delivery plus integration coverage without changing
their schema or semantics.

## 8. Remaining limitations

P1-29 does not add:

- non-Markdown configuration parsing;
- effective capability resolution;
- production Hard Gate combination detectors;
- CI blocking, `--fail-on`, policy waivers, or remediation;
- JSON operational error documents;
- LLM or semantic analysis;
- runtime execution or exploitability verification;
- a global Agent safety claim.
## 9. M1-01 Chinese integration extension

M1-01 keeps the same CLI and report pipeline while extending Rule Pack provenance
to `0.3.0`. Five Chinese Cases and the Chinese Release Agent Demo run through the
real Collector, Parser, Rule, Risk, Confidence, Hard Gate, and reporter chain.
English remains the default inventory language; `agentsec rules list --language
zh` is display-only localization. No scanned Chinese instruction gains execution,
network, MCP, or tool authority.

## 10. P2I-04 Phase 2 Manifest and Capability commands

P2I-04 adds `manifest` and the `capability assess|diff|rules list` command group
without changing the Phase 1 `scan`, `baseline`, `diff`, or `rules` contracts.
The new commands use P2I-01 application services and P2I-03 renderers instead of
constructing semantic analysis inside Typer callbacks.

Saved Manifest input uses a bounded no-follow reader. File output uses a
validated, mode-0600, atomic, no-clobber writer; `--force` is limited to an
existing valid artifact of the same kind and format. Numeric code `4` now also
has the public alias `ARTIFACT_ERROR` for invalid/incompatible Manifest input or
unsafe report output. Findings remain report-only and return `0` when analysis is
complete. See `docs/capability-cli.md` and ADR-0031.


## 11. P2-25 SARIF output extension

P2-25 adds an explicit CLI-only `scan --format sarif` renderer over the same
final `Assessment`. The project Config Schema remains `text|json`; the new format
does not change collection, Rule, risk, Confidence, Hard Gate, Coverage, or exit
semantics. A complete scan with Findings returns `0`; an incomplete scan emits a
valid partial SARIF document and returns `2`. SARIF messages omit source excerpts
and recognized secret/source values. See `docs/sarif-report.md` and ADR-0055.

## 12. P2-26 explicit Severity fail-on

P2-26 adds CLI-only `scan --fail-on high|critical`. Default scan behavior remains
report-only. Complete threshold matches return `1`; incomplete Coverage retains
exit `2`; unmatched complete scans return `0`. JSON uses a separate versioned
decision wrapper and SARIF records the AgentSec-computed decision rather than
deriving authority from SARIF level. Capability Assessment remains behind the
qualified `capability enforce --policy` path. See ADR-0056.
