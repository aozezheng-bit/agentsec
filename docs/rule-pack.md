# AgentSec Bilingual Markdown Rule Pack

- Task: `P1-20`
- Status: Complete
- Decision date: 2026-08-19
- Rule-pack version: `0.3.0`
- Rule count: `15`
- Initial decision: `docs/decisions/0009-initial-markdown-rule-pack.md`
- Chinese extension: `docs/decisions/0017-bilingual-markdown-rule-pack.md`

## 1. Purpose

P1-20 publishes the first reviewed production Rule IDs for Phase 1 Markdown
assets. The pack is available through:

```python
from agentsec.rules import builtin_markdown_rules

rules = builtin_markdown_rules()
```

The function returns 15 new Rule adapters in stable Rule ID order. Every call
returns a complete pack suitable for `DeterministicRuleRunner`.

A rule match means:

> The supported static Markdown contains direct source-backed text, a parser
> indicator, or an executable reference associated with a risky declaration.

A match does not prove that the Agent has the runtime tool, identity, permission,
network route, secret, or ability needed to perform the declared action. These
rules are deterministic static signals, not confirmed vulnerabilities.

## 2. Rule inventory

| Rule ID | Category | Signal |
|---|---|---|
| `MD-INSTR-001` | `instruction_integrity` | Ignore, disregard, or replace earlier instructions |
| `MD-INSTR-002` | `instruction_integrity` | Disable safety checks, suppress findings, or hide controlling instructions |
| `MD-APPROVAL-001` | `human_approval` | Execute without approval or confirmation |
| `MD-EXEC-001` | `code_execution` | Shell, terminal, or operating-system command execution |
| `MD-EXEC-002` | `code_execution` | `eval`, `exec`, dynamic import, or arbitrary code execution |
| `MD-NET-001` | `network_access` | External API, webhook, HTTP request, or URL-supported data transfer |
| `MD-SECRET-001` | `secret_access` | Credential, secret, token, key, or environment-variable access |
| `MD-PRIV-001` | `privileged_access` | Production environment, system, database, cluster, credential, or write access |
| `MD-PRIV-002` | `privileged_access` | Administrator, root, sudo, or elevated privilege |
| `MD-DESTRUCT-001` | `destructive_action` | Broad deletion, destructive reset, database drop, or force removal |
| `MD-DEPLOY-001` | `destructive_action` | Deployment, release, or package publishing |
| `MD-MEMORY-001` | `persistent_memory` | Cross-session or future-task retention |
| `MD-SELF-001` | `self_modification` | Modification of the Agent's own instructions, configuration, or Skills |
| `MD-OBFUSC-001` | `obfuscation` | Base64-like, zero-width, bidi, control, or mixed-script content |
| `MD-TOOL-001` | `external_tooling` | External tool invocation or executable script/binary reference |

The pack covers all Phase 1 security categories except `scan_coverage`, which is
produced by collector, parser, and rule execution failures rather than a content
rule.

## 3. Stable identity and metadata

Every rule has:

```text
FAMILY-TOPIC-NNN Rule ID
FindingCategory
reader-facing title
evidence-aware description
one concrete remediation recommendation
all supported Markdown AssetType values
deterministic = true
```

The registry exports:

```text
BUILTIN_MARKDOWN_RULE_IDS
BUILTIN_MARKDOWN_RULE_COUNT
builtin_markdown_rules()
```

`BUILTIN_MARKDOWN_RULE_IDS` is the canonical sorted identity list. Runtime pack
construction verifies that all 15 generated adapters match it exactly. A missing,
duplicate, renamed, or unexpectedly ordered ID fails pack construction rather
than silently changing analysis.

Rule titles, descriptions, and recommendations are trusted package metadata.
They are never derived from scanned Markdown.

## 4. Text matching rules

Most rules use P1-18 physical-line `KeywordRule` or `RegexRule` adapters.

The current pack includes reviewed English and Simplified Chinese trigger
phrases. Matching is case-insensitive by default. It is intentionally phrase oriented rather than
a broad bag of individual words. For example, `shell command` is a signal while
the word `shell` by itself is not.

Rules that describe instruction integrity, approval, memory, or
self-modification inspect prose-oriented blocks:

```text
heading
paragraph
list_item
```

Capability rules that may legitimately appear as examples or commands also
inspect:

```text
fenced_code
indented_code
```

This increases recall for declared execution and destructive behavior while
accepting that code examples may require later Confidence and human review.

## 5. Safe Regex rules

`MD-EXEC-002` and `MD-DESTRUCT-001` use the restricted P1-18 Regex dialect.
Representative patterns include:

```text
\beval\(
\bexec\(
\bdynamic\s{1,8}import\b
\brm\s{1,8}-rf\b
\bgit\s{1,8}reset --hard\b
```

They do not add new Regex syntax. Wildcards, unbounded repetition, capturing,
lookaround, backreferences, quantified groups, or open-ended repetition remain
prohibited.

## 6. Network rule composition

`MD-NET-001` combines two deterministic delegates under one Rule ID:

1. direct phrases such as external API, webhook, HTTP request, network request,
   secret transmission, or exfiltration;
2. data-transfer phrases such as send, upload, or post, when a bounded one-line
   before/after context contains a static `http://` or `https://` host.

Both delegates use the same trusted `RuleMetadata`. Their candidates are sorted
and deduplicated before entering the P1-19 pipeline.

The rule never opens the URL, performs DNS, sends a request, or checks endpoint
reachability.

## 7. Obfuscation rule

`MD-OBFUSC-001` consumes the safe parser indicators created by P1-11. It creates
one candidate for each of:

```text
base64_like
zero_width
bidi_control
control_character
mixed_script_confusable
```

It intentionally excludes:

```text
long_line
long_block
```

Length alone is not classified as encoded or hidden content by the production
Rule.

Obfuscation Evidence uses:

```text
asset path
source line range
content SHA-256
field = obfuscation:<indicator kind>
```

It does not copy or decode the suspicious token. AgentSec never executes decoded
content.

## 8. External tooling and executable references

`MD-TOOL-001` combines direct tool/script phrases with static Markdown reference
classification.

Executable reference suffixes are:

```text
.bash .bat .bin .cjs .cmd .exe .js .mjs .pl .ps1 .py .rb .sh .zsh
```

Query strings and fragments are removed only for suffix classification. The
reference target is never opened, imported, executed, downloaded, or fetched.

Reference Evidence uses the parser-provided source range and a bounded exact
source excerpt. The field is:

```text
reference:executable_script
```

References to ordinary documentation such as `.md` do not trigger this rule.

## 9. Evidence and Finding behavior

Every positive rule test verifies:

```text
project-relative asset path
1-based source line
content SHA-256
non-empty Evidence
```

The rules return `RuleFindingCandidate`. P1-19 binds trusted metadata and creates
`UnscoredFinding` values. P1-20 still does not assign:

```text
likelihood
impact
severity
score
confidence
hard_gate
```

A single source line may produce multiple Findings when it declares multiple
independent capabilities. Different Rule IDs are never averaged or deduplicated
away.

## 10. Test corpus alignment

The `testdata` case manifest now requires:

```json
{
  "expected": {
    "coverage": "complete",
    "signals": ["..."],
    "rule_ids": ["MD-...-001"]
  }
}
```

Existing safe, risky, prompt-injection, and malformed manifests have been
updated with stable expected Rule IDs. Safe fixtures require an empty Rule ID
list. The runner integration test compares actual observed IDs with these
manifests.

## 11. Positive, negative, and boundary tests

Every one of the 15 Rule IDs has:

- a positive source-backed match;
- a benign negative non-match;
- Category and Metadata validation;
- direct Evidence validation through the Rule interface.

Additional boundary coverage includes:

- phrases split across physical lines do not become an exact phrase match;
- fenced shell/destructive examples are detected but never executed;
- long-line indicators alone do not trigger the obfuscation Rule;
- executable URL references with query strings are classified without I/O;
- the complete pack runs deterministically through P1-19;
- existing fixture expectations match observed IDs;
- rule execution performs no file, shell, or network side effect.

## 12. Known false-positive and false-negative boundaries

The initial pack is intentionally simple and explainable.

Known false-positive sources include:

- documentation quoting a risky phrase;
- instructions that explicitly prohibit a phrase but still contain its direct
  textual form;
- safe code examples that demonstrate a dangerous command;
- benign production, credential, or deployment documentation.

Known false-negative sources include:

- paraphrases not present in the reviewed phrase set;
- phrases split across Markdown markup or physical lines;
- semantic implications requiring natural-language understanding;
- tools and permissions declared only in unsupported TOML/YAML/JSON formats;
- runtime capabilities absent from Markdown;
- encoded instructions that do not meet the deterministic indicator heuristics.

P1-22 now reflects these limitations through explicit D-level Confidence for
all built-in Markdown rules. The pack must not claim that a lexical match proves
exploitability or that zero matches prove safety.

## 13. Version decision

P1-20 published the first 15 production Rule IDs as Rule Pack `0.2.0`. M1-01
keeps those identities and risk meanings but expands their reviewed trigger set
with common Simplified Chinese expressions. Identical Chinese Markdown can now
produce new Findings, so provenance increments to:

```text
RULE_PACK_VERSION = 0.3.0
```

This is a pre-1.0 minor change. Consumers supporting only `0.2.x` must not treat
`0.3.0` results as semantically equivalent. Domain Schema and Risk Model remain
unchanged because Finding shape, categories, scores, Confidence, and Hard Gate
semantics do not change. ADR-0017 records the bilingual compatibility boundary.

Future implementation fixes that preserve Rule meaning use a Rule Pack patch.
Materially changing a risk meaning requires a new Rule ID or a reviewed
minor/major change with migration notes.

## 14. Current integration boundary

The packaged inventory is available through:

```bash
agentsec rules list
agentsec rules list --language zh
```

The commands print Rule Pack version, stable Rule ID, category, and localized
title for all 15 Rules without scanning a project. The pack can also run through:

```python
runner = DeterministicRuleRunner(builtin_markdown_rules())
result = runner.run(contexts)
```

Each result can now be passed to `DeterministicRiskEngine`, which maps the
`UnscoredFinding` to a traceable intermediate `ScoredFinding`. P1-21 introduced
this base score in Risk Model `0.2.0`; the current Risk Model is `0.4.0` after
P1-22 Confidence and P1-23 Hard Gate extensions.

Each `ScoredFinding` can now be passed to `DeterministicConfidenceEngine`.
All 15 built-in Markdown profiles produce D Confidence while retaining their
original score and Severity.

P1-23 can now attach report-only Hard Gate metadata and assemble the final
Domain `Finding`. The production Phase 1 path supplies no gate matches, so
`hard_gate=false` by default and CI blocking remains disabled.

P1-29 wires final Findings into `agentsec scan` Text/JSON output through the
complete Risk, Confidence, and report-only Hard Gate chain. The current suite provides the 45-Case inert corpus, and P1-29 replays every Case through the real CLI; see
`docs/test-corpus.md` and `docs/cli-integration.md`.


## 15. Rule Pack 0.3.1 external Human Review patch

P2-EXIT-06-05A preserves the independent external Homi labels and adds bounded
coverage for direct Git command, web search, AGENTS.md update, and Skills/tool
declarations. This is a patch-level false-negative fix: Rule IDs, categories,
Risk Model, Confidence, Policy, Waiver, and CI authority remain unchanged.

```text
RULE_PACK_VERSION = 0.3.1
External reviewed Replay: TP=25, FP=0, FN=0, Precision=1.0, Recall=1.0
```

ADR-0081 records the decision and the immutable pre-calibration 19/20 evidence.
