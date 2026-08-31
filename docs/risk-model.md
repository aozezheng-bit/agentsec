# AgentSec Risk Model v0

- Task: `P1-21`
- Status: Complete
- Decision date: 2026-08-19
- Current Risk Model version: `0.4.0`
- Base-score decision: `docs/decisions/0010-nist-base-risk-model-v0.md`
- Confidence extension: `docs/decisions/0011-evidence-confidence-model.md`
- Hard Gate extension: `docs/decisions/0012-report-only-hard-gate-metadata.md`

## 1. Purpose

P1-21 converts each validated `UnscoredFinding` into an independently scored,
traceable `ScoredFinding`:

```text
trusted Rule ID and category
+ reviewed rule-specific RiskProfile
+ NIST likelihood-impact matrix
+ explicit numeric and Severity mappings
= RiskAssessment
```

The v0 model answers:

1. What qualitative likelihood is assigned and why?
2. Which impact dimensions are affected?
3. Which impact dimension establishes the high-water mark?
4. Which NIST matrix cell is selected?
5. What NIST semi-quantitative value belongs to that cell?
6. What AgentSec 0–10 representative score is reported?
7. Which Severity range contains that score?
8. Which Risk Model version and mapping sources produced the result?

It does not claim that a static Markdown match proves runtime capability or
exploitability.

## 2. Standards and policy sources

The implementation separates standards-derived behavior from AgentSec policy:

- [NIST SP 800-30 Rev. 1](https://csrc.nist.gov/pubs/sp/800/30/r1/final)
  supplies the five qualitative likelihood levels, five qualitative impact
  levels, and Table I-2 likelihood-impact risk matrix.
- [FIPS 199](https://csrc.nist.gov/pubs/fips/199/final) supplies the
  high-water-mark principle used by AgentSec to prevent a severe impact
  dimension from being diluted by lower dimensions.
- [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document)
  supplies the qualitative Severity ranges for a 0–10 score.
- The approved AgentSec project plan section 6.7.2 supplies the v0 representative
  0–10 values for NIST matrix levels.

NIST Table I-2 includes semi-quantitative values `0 / 2 / 5 / 8 / 10`.
AgentSec separately reports engineering representatives
`0.0 / 2.0 / 5.5 / 8.0 / 9.5` so its Medium and Critical output fits the
project's CVSS/AIVSS-compatible reporting plan.

These are deliberately stored as different fields:

```text
nist_semi_quantitative_value  # NIST Table I-2 value
score                         # AgentSec project-policy representative
```

The AgentSec score mapping is not presented as a NIST formula.

## 3. Pipeline boundary

P1-21 introduces two internal immutable objects:

```text
RiskAssessment
ScoredFinding
```

The lifecycle is now:

```text
RuleFindingCandidate
→ UnscoredFinding
→ ScoredFinding
→ ConfidenceFinding
→ GatedFinding
→ final Domain Finding
```

`ScoredFinding` retains the exact `UnscoredFinding` instance, including Finding
ID and Evidence. Risk scoring does not rewrite, summarize, or interpret the
untrusted excerpt.

`RiskAssessment` intentionally has no:

```text
confidence
hard_gate
```

`RiskAssessment` remains base-risk-only. P1-22 attaches a separate
`ConfidenceAssessment`, and P1-23 now attaches a report-only
`HardGateAssessment`.

## 4. Likelihood levels

Ordinals are retained as explicit intermediate values:

| Likelihood | Ordinal | AgentSec v0 interpretation |
|---|---:|---|
| Very Low | 1 | Theoretical only; no reachable path or key precondition |
| Low | 2 | Multiple or restrictive unverified preconditions |
| Moderate | 3 | A direct control-asset declaration exists, but runtime reachability and successful execution are unverified |
| High | 4 | Untrusted input is demonstrably reachable with low complexity or ordinary privilege |
| Very High | 5 | Persistent/public autonomous exposure or stable dynamic reproduction exists |

P1-21 has only static Markdown evidence. Therefore reviewed direct-declaration
profiles use `Moderate`, while indirect indicators and executable references use
`Low`. No built-in v0 profile uses `High` or `Very High` likelihood because Phase
1 has no runtime reachability, exposure, or reproduction evidence.

This is a conservative evidence boundary, not a confidence adjustment. P1-22
now reports Evidence Confidence independently through `ConfidenceFinding`.

## 5. Impact dimensions and high-water mark

Each `RiskProfile` stores one or more `ImpactRating` values:

| Dimension | Meaning |
|---|---|
| Confidentiality | Sensitive information, credentials, personal data, or protected context |
| Integrity | Code, configuration, instructions, identity, data, or business state |
| Availability | Agent, host, service, data, or downstream system availability |
| Safety | Harm to people, property, or real-world operations |
| Business & Compliance | Financial, legal, regulatory, audit, and reputation impact |
| Downstream Blast Radius | Other Agents, services, tenants, users, production systems, or supply chain |

The overall Impact is:

```text
Impact = max(all rated impact dimensions)
```

The engine never averages impact dimensions. Each dimension retains its level
and trusted rationale in `RiskAssessment.impact_ratings`.

## 6. NIST five-by-five matrix

The engine encodes NIST SP 800-30 Rev. 1 Table I-2 explicitly rather than using
an arithmetic approximation.

| Likelihood \ Impact | Very Low | Low | Moderate | High | Very High |
|---|---|---|---|---|---|
| Very High | Very Low | Low | Moderate | High | Very High |
| High | Very Low | Low | Moderate | High | Very High |
| Moderate | Very Low | Low | Moderate | Moderate | High |
| Low | Very Low | Low | Low | Low | Moderate |
| Very Low | Very Low | Very Low | Very Low | Very Low | Low |

Tests cover all 25 cells and verify monotonicity on both axes.

## 7. Numeric and Severity mappings

| Matrix risk level | NIST Table I-2 value | AgentSec Base Score | Severity |
|---|---:|---:|---|
| Very Low | 0 | 0.0 | None |
| Low | 2 | 2.0 | Low |
| Moderate | 5 | 5.5 | Medium |
| High | 8 | 8.0 | High |
| Very High | 10 | 9.5 | Critical |

Severity follows the CVSS v4.0 qualitative ranges:

| Score | Severity |
|---:|---|
| 0.0 | None |
| 0.1–3.9 | Low |
| 4.0–6.9 | Medium |
| 7.0–8.9 | High |
| 9.0–10.0 | Critical |

Scores are finite, bounded to `0.0–10.0`, and never silently clamped.

## 8. Built-in rule profiles

Every Rule Pack `0.2.0` Rule ID has one explicit reviewed profile. There is no
category-only fallback.

| Rule ID | Likelihood | High-water Impact | Matrix level | Score | Severity |
|---|---|---|---|---:|---|
| `MD-APPROVAL-001` | Moderate | High | Moderate | 5.5 | Medium |
| `MD-DEPLOY-001` | Moderate | Very High | High | 8.0 | High |
| `MD-DESTRUCT-001` | Moderate | Very High | High | 8.0 | High |
| `MD-EXEC-001` | Moderate | Very High | High | 8.0 | High |
| `MD-EXEC-002` | Moderate | Very High | High | 8.0 | High |
| `MD-INSTR-001` | Moderate | High | Moderate | 5.5 | Medium |
| `MD-INSTR-002` | Moderate | High | Moderate | 5.5 | Medium |
| `MD-MEMORY-001` | Low | High | Low | 2.0 | Low |
| `MD-NET-001` | Moderate | High | Moderate | 5.5 | Medium |
| `MD-OBFUSC-001` | Low | Moderate | Low | 2.0 | Low |
| `MD-PRIV-001` | Moderate | Very High | High | 8.0 | High |
| `MD-PRIV-002` | Moderate | Very High | High | 8.0 | High |
| `MD-SECRET-001` | Moderate | Very High | High | 8.0 | High |
| `MD-SELF-001` | Moderate | Very High | High | 8.0 | High |
| `MD-TOOL-001` | Low | High | Low | 2.0 | Low |

The complete likelihood and per-dimension impact rationale lives in trusted
package code, not in scanned Markdown.

No current built-in profile produces Critical from static evidence alone. A
Critical matrix result remains supported for a future reviewed profile with
High/Very High likelihood and Very High impact. Future combination floors and
non-dilutable policy remain P1-23/P2 work.

## 9. RiskAssessment fields

Each result retains:

```text
risk_model_version
profile_rule_id
likelihood
impact
likelihood_ordinal
impact_ordinal
risk_level
nist_semi_quantitative_value
score
severity
likelihood_basis
impact_ratings
mapping_basis
```

`mapping_basis` contains stable identifiers for:

1. the NIST Table I-2 matrix;
2. the FIPS 199 high-water-mark principle adapted to AgentSec dimensions;
3. the AgentSec project-plan score mapping;
4. the CVSS v4.0 Severity ranges.

## 10. Registry and failure behavior

`DeterministicRiskEngine` validates its trusted profile registry before use:

- registry input must be a non-empty tuple;
- every item must be a valid immutable `RiskProfile`;
- Rule IDs must be unique;
- every built-in profile inventory must exactly match the production Rule IDs;
- a Finding category must match its registered profile category;
- an unknown Rule ID fails closed instead of receiving a category default;
- duplicate Finding IDs are rejected by `score_all()`.

Failures use stable `RiskScoringCode` values and fixed messages. They do not copy
source excerpts, exception text, absolute paths, secret values, or other scanned
content.

## 11. Determinism and security properties

For identical Findings, profiles, and Risk Model version, output is identical.
The engine:

- reads no files;
- writes no files;
- executes no shell or subprocess;
- imports no scanned project code;
- performs no network access;
- invokes no Skill, MCP, or LLM;
- does not inspect source excerpts to alter risk;
- preserves Evidence and Finding identity;
- scores every Finding independently;
- performs no cross-Finding average;
- returns multi-Finding output in stable Rule/source order;
- excludes the underlying `UnscoredFinding` from `ScoredFinding.__repr__`.

## 12. Version decision

P1-21 introduced:

```text
RISK_MODEL_VERSION: 0.1.0 → 0.2.0
```

`0.1.x` reserved a Risk Model identifier but defined no executable scoring
semantics. `0.2.0` introduces concrete likelihood profiles, high-water impact
ratings, the five-by-five matrix, numeric mappings, Severity ranges, failure
behavior, and intermediate result contract.

The following remain unchanged:

```text
DOMAIN_SCHEMA_VERSION = 0.2.0
RULE_PACK_VERSION = 0.2.0
```

P1-22 subsequently adds independent A/B/C/D Confidence and increments the Risk
Model to `0.3.0`. P1-23 adds report-only Hard Gate floors and increments the
current Risk Model to `0.4.0`. Base-score mappings defined by P1-21 are unchanged.

`RiskAssessment` and `ScoredFinding` are internal Python pipeline objects, not
new serialized Domain Schema fields. Changing any profile, matrix cell, score
representative, Severity threshold, Confidence mapping, aggregation rule, or
hard-gate rule requires a Risk Model version change and ADR review.

## 13. P1-21 boundary and remaining limitations

P2-17 now provides a standalone CVSS Base input adapter in `docs/cvss-adapter.md`;
CVSS Base remains separate from this NIST-style RiskAssessment and is not
averaged into the AgentSec score.

At the P1-21 boundary, Evidence Confidence was intentionally absent. P1-22 now
implements it separately in `docs/confidence-model.md` without changing the base
score.

At the P1-21 boundary, Hard Gate metadata was also absent. P1-23 now implements
it separately in `docs/hard-gate.md` and can assemble the final Domain Finding.

The remaining deferred behavior is:

- CI blocking;
- scan command integration;
- Text or JSON Finding reporters;
- runtime reachability or exploit verification;
- automatic attachment of the standalone CVSS Base assessment to Domain Findings;
- Agentic Uplift, threat multiplier, or mitigation factor;
- Drift Score or Governance Score;
- cross-Finding attack-path aggregation;
- organization-specific profile overrides.

A numeric score is a preliminary deterministic triage result. Zero Findings or a
low static score does not prove that an Agent is safe.
