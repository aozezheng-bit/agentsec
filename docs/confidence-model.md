# AgentSec Evidence Confidence Model

- Task: `P1-22`
- Status: Complete
- Decision date: 2026-08-19
- Current Risk Model version: `0.4.0`
- Decision record: `docs/decisions/0011-evidence-confidence-model.md`

## 1. Purpose

P1-22 assigns an A/B/C/D Evidence Confidence level to each P1-21
`ScoredFinding` without changing its Likelihood, Impact, score, or Severity.

The pipeline is:

```text
UnscoredFinding
→ ScoredFinding
→ ConfidenceFinding
→ GatedFinding
→ final Domain Finding
```

Confidence answers:

```text
How strongly does the available evidence support this Finding?
```

Severity answers:

```text
How harmful could the Finding be if the declared behavior is real and reachable?
```

These questions are deliberately independent.

## 2. Standards and policy boundary

[NIST SP 800-30 Rev. 1](https://csrc.nist.gov/pubs/sp/800/30/r1/final)
requires risk-assessment results to communicate uncertainty and confidence and
notes that confidence depends on the quality, quantity, and relevance of the
available information.

NIST does not define AgentSec's A/B/C/D labels. The four labels and their source
mapping are AgentSec engineering policy from project-plan section 6.7.6.
`ConfidenceAssessment.mapping_basis` retains both facts:

```text
NIST uncertainty/confidence communication principle
AgentSec A/B/C/D evidence-source policy
```

## 3. Confidence levels

| Level | Required evidence strength | Examples |
|---|---|---|
| A | Directly verified or independently attested | Runtime verification, stable red-team reproduction, actual tool enumeration, signed attestation |
| B | Deterministic effective behavior or traceable implementation evidence | Resolved effective configuration, deterministic structured rule, traceable source-code path |
| C | Probabilistic semantic judgment with exact supporting context | LLM semantic analysis retaining exact source evidence and structured context |
| D | Preliminary static or incomplete inference | Keyword, bounded regex, local context, parser indicator, static executable reference, partial-scan inference |

The levels are ordinal source-strength labels, not numeric score multipliers.
AgentSec does not multiply, average, or subtract Confidence from risk.

## 4. Evidence methods

`ConfidenceMethod` distinguishes how the evidence was produced:

| Method | Level |
|---|---|
| `runtime_verification` | A |
| `red_team_reproduction` | A |
| `actual_tool_enumeration` | A |
| `signed_attestation` | A |
| `effective_configuration` | B |
| `deterministic_structured_rule` | B |
| `traceable_source_code` | B |
| `llm_semantic_analysis` | C |
| `keyword_match` | D |
| `bounded_regex_match` | D |
| `contextual_lexical_match` | D |
| `parser_indicator` | D |
| `static_reference` | D |
| `partial_scan_inference` | D |

`confidence_for_method()` is the single executable mapping. A
`ConfidenceProfile` or `ConfidenceAssessment` is rejected if its declared level
does not match every method it contains.

## 5. Phase 1 built-in profiles

Every Rule Pack `0.2.0` Rule ID has one explicit reviewed Confidence profile.
All current profiles are `D` because P1-20 Findings are lexical, bounded-regex,
contextual, parser-indicator, or static-reference signals from Markdown. They do
not establish effective runtime configuration or successful execution.

| Rule ID | Default method | Confidence |
|---|---|---|
| `MD-APPROVAL-001` | Keyword match | D |
| `MD-DEPLOY-001` | Keyword match | D |
| `MD-DESTRUCT-001` | Bounded regex match | D |
| `MD-EXEC-001` | Keyword match | D |
| `MD-EXEC-002` | Bounded regex match | D |
| `MD-INSTR-001` | Keyword match | D |
| `MD-INSTR-002` | Keyword match | D |
| `MD-MEMORY-001` | Keyword match | D |
| `MD-NET-001` | Contextual lexical match | D |
| `MD-OBFUSC-001` | Parser indicator | D |
| `MD-PRIV-001` | Keyword match | D |
| `MD-PRIV-002` | Keyword match | D |
| `MD-SECRET-001` | Keyword match | D |
| `MD-SELF-001` | Keyword match | D |
| `MD-TOOL-001` | Keyword match or static reference | D |

`MD-TOOL-001` uses trusted Evidence field metadata:

```text
field starts with reference: → static_reference
otherwise                    → keyword_match
```

This changes the reported evidence method, not the D level. Attacker-authored
source wording cannot self-upgrade Confidence.

## 6. ConfidenceAssessment

Each immutable assessment retains:

```text
risk_model_version
profile_rule_id
level
methods
rationale
limitations
mapping_basis
```

Methods are sorted and unique. Rationale and limitations are non-empty trusted
profile text and never come from the scanned excerpt.

Every built-in profile explicitly states these limitations:

- Phase 1 sees local Markdown rather than a fully resolved effective Agent
  configuration;
- runtime capability, actual tool inventory, permission grant, signed
  attestation, and dynamic reproduction remain unverified.

## 7. Severity independence

P1-22 enforces:

```text
Confidence ≠ Severity
```

For example:

```text
MD-EXEC-001
Risk Score: 8.0
Severity: High
Confidence: D
```

The result remains High. D means the static evidence needs verification; it does
not mean the potential impact is Low.

`ConfidenceFinding` retains the exact `ScoredFinding` object. The Confidence
Engine never reconstructs, rounds, lowers, or replaces:

```text
likelihood
impact
risk level
NIST value
AgentSec score
severity
finding ID
evidence
```

## 8. Registry and failure behavior

`DeterministicConfidenceEngine` validates its trusted registry:

- the registry is a non-empty tuple;
- every entry is a valid immutable `ConfidenceProfile`;
- Rule IDs are unique;
- built-in IDs exactly match the production Rule inventory;
- profile category must match the Finding category;
- method and level must match the approved mapping;
- Evidence field prefixes are bounded, unique, and non-overlapping;
- unknown Rule IDs fail closed;
- duplicate Finding IDs fail closed.

Errors use stable `ConfidenceScoringCode` values and fixed messages. They do not
include source excerpts, secret values, absolute paths, or underlying exception
text.

## 9. Security and determinism

Confidence assignment:

- does not inspect excerpt wording to choose a level;
- reads only trusted Rule/profile identity and validated Evidence metadata;
- performs no filesystem reads or writes;
- performs no shell or subprocess execution;
- performs no network access;
- imports no scanned project code;
- invokes no Skill, MCP, or LLM;
- preserves Finding and Evidence identity;
- processes every Finding independently;
- returns stable Rule/source ordering;
- excludes the underlying `ScoredFinding` from `ConfidenceFinding.__repr__`.

Identical Findings, profiles, and Risk Model versions produce identical output.

## 10. Version decision

P1-22 introduced:

```text
RISK_MODEL_VERSION: 0.2.0 → 0.3.0
```

There is no separate Confidence-model identifier in the Phase 1 version vector.
Evidence Confidence is part of the overall risk interpretation, so changes to
A/B/C/D definitions, method mappings, profile levels, downgrade/upgrade rules,
or aggregation behavior require a Risk Model version change.

The following remain unchanged:

```text
DOMAIN_SCHEMA_VERSION = 0.2.0
RULE_PACK_VERSION = 0.2.0
```

P1-23 subsequently adds report-only Hard Gate metadata and increments the
current Risk Model to `0.4.0`. Confidence definitions and method mappings remain
unchanged.

`ConfidenceAssessment` and `ConfidenceFinding` are internal Python pipeline
objects. The existing Domain `Finding.confidence` field and
`EvidenceConfidence` enum already contain the required final-report shape, so no
Domain Schema change is needed.

## 11. P1-22 boundary and remaining limitations

At the P1-22 boundary, Hard Gate metadata and final Domain Finding assembly were
absent. P1-23 now implements both in `docs/hard-gate.md` without changing
Confidence semantics.

The remaining deferred behavior is:

- scan command integration;
- Text or JSON Finding reporters;
- coverage-aware Confidence downgrade input;
- effective configuration resolution;
- runtime verification or actual tool enumeration;
- LLM semantic analysis;
- dynamic red-team reproduction;
- signed evidence or provenance attestation;
- organization-specific Confidence overrides.

Because all current production Findings are D, incomplete project coverage does
not lower them further. Future B/A sources must explicitly incorporate coverage,
provenance, freshness, and corroboration before they can claim stronger
Confidence.
