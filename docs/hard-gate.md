# AgentSec Hard Gate Metadata

- Task: `P1-23`
- Status: Complete
- Decision date: 2026-08-19
- Risk Model version: `0.4.0`
- Decision record: `docs/decisions/0012-report-only-hard-gate-metadata.md`

## 1. Purpose

P1-23 completes the internal Phase 1 Finding data path:

```text
UnscoredFinding
→ ScoredFinding
→ ConfidenceFinding
→ GatedFinding
→ Domain Finding
```

A Hard Gate is a deterministic policy condition that establishes a minimum risk
level which cannot be lowered by averaging, a lower base score, or weak Evidence
Confidence.

A matched Hard Gate is not the same thing as CI blocking. Phase 1 records and
applies gate metadata in `report_only` mode but never blocks delivery.

Canonical terminology is recorded in the repository `CONTEXT.md` glossary.

## 2. Standards and policy boundary

The model distinguishes standards-derived thresholds from AgentSec policy:

- [FIPS 199](https://csrc.nist.gov/pubs/fips/199/final) provides a
  high-water-mark principle: a severe security objective must not be diluted by
  lower objectives. AgentSec adapts this non-dilution principle to Hard Gate
  floors; FIPS 199 does not define AgentSec gates.
- [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document)
  defines `7.0` as the lower bound for High and `9.0` as the lower bound for
  Critical.
- AgentSec project-plan section 6.8 defines the reviewed concept that certain
  deterministic conditions establish a minimum High or Critical risk level.

`HardGateAssessment.mapping_basis` retains all three sources.

## 3. Phase 1 scope

P1-23 implements:

- immutable Hard Gate metadata;
- stable gate and Finding identity;
- High and Critical floors;
- non-dilutable effective score calculation;
- report-only mode;
- deterministic match binding;
- final Domain `Finding` assembly.

P1-23 does not implement the production combination rules listed in project-plan
section 6.8. Those conditions require effective capability resolution and are
P2-15 work.

Therefore the production Phase 1 path supplies no `HardGateMatch` values by
default:

```text
matches = ()
triggered = false
hard_gate = false
blocks = false
```

Tests may provide trusted synthetic matches to verify floor semantics, but the
production CLI does not activate them.

## 4. Hard Gate floors

Phase 1 supports only non-trivial policy floors:

| Floor | Minimum score | Effective Severity |
|---|---:|---|
| High | 7.0 | High |
| Critical | 9.0 | Critical |

The effective score is:

```text
effective_score = max(base_score, strongest_gate_floor_score)
```

When no gate matches:

```text
effective_score = base_score
```

When several gates match:

```text
strongest_gate_floor = max(all matched floors)
```

No sum, mean, weighted average, or Confidence multiplier is used.

Examples:

```text
Base 5.5 / Medium + High floor     → 7.0 / High
Base 8.0 / High   + High floor     → 8.0 / High
Base 8.0 / High   + Critical floor → 9.0 / Critical
High + Critical matches            → Critical floor
```

## 5. HardGateMatch

One trusted deterministic match contains:

```text
finding_id
gate_id
floor
rule_ids
rationale
```

Contracts:

- Finding ID uses `finding-sha256:<64 hex>`;
- Gate ID uses `HG-TOPIC-NNN`;
- supporting Rule IDs use the existing stable Rule ID format;
- Rule IDs are non-empty, sorted, and unique;
- the current Finding Rule ID must be included;
- rationale is non-empty trusted policy text and is excluded from generated
  representations;
- gate IDs are unique per Finding.

`HardGateMatch` does not accept source excerpts, shell commands, URLs, or runtime
clients.

## 6. HardGateAssessment

Each assessment retains:

```text
risk_model_version
finding_id
mode
base_score
base_severity
matches
mapping_basis
```

It derives:

```text
triggered
floor
floor_score
effective_score
effective_severity
blocks
```

Derived properties prevent contradictory stored values such as:

```text
triggered = false with non-empty matches
Critical floor with Medium effective Severity
report_only with blocks = true
```

`blocks` is always `false` under Risk Model `0.4.0`.

## 7. Report-only mode

The only supported Phase 1 mode is:

```text
GateEnforcementMode.REPORT_ONLY
```

Report-only means:

- a deterministic match may set `hard_gate=true`;
- the effective score and Severity reflect the floor;
- the result is visible to future reporters;
- no CLI exit code or CI policy changes;
- no process is stopped;
- no deployment is blocked.

`hard_gate=true` means a gate condition matched. It does not mean AgentSec
blocked a pipeline.

An enforcing mode must be introduced later through an explicit policy task,
ADR, tests, and Risk Model version change.

## 8. DeterministicHardGateEngine

The public internal seam is:

```python
engine = DeterministicHardGateEngine()
gated = engine.apply_all(confidence_findings, matches=trusted_matches)
```

The engine:

1. validates unique input Finding IDs;
2. rejects matches for unknown Finding IDs;
3. groups matches by Finding ID;
4. requires each match to include the current Rule ID;
5. rejects duplicate Gate IDs per Finding;
6. sorts Findings and matches deterministically;
7. constructs a report-only `HardGateAssessment`;
8. returns a `GatedFinding`.

With the production default `matches=()`, all Findings remain untriggered.

## 9. Final Domain Finding assembly

P1-23 is the first task where every required Domain `Finding` field exists.
`GatedFinding.to_domain_finding()` assembles the existing Pydantic model using:

```text
UnscoredFinding metadata and Evidence
+ RiskAssessment likelihood and impact
+ HardGateAssessment effective score and Severity
+ ConfidenceAssessment level
+ HardGateAssessment triggered flag
```

The conversion does not render, log, redact, or serialize the Finding. P1-24
provides safe bounded Text rendering for a final Assessment. P1-25 now provides
strict versioned JSON with explicit report-only and CI-disabled policy. P1-26
now provides broader shared secret-redaction hardening.

## 10. Confidence independence

Hard Gate behavior is independent from Evidence Confidence:

```text
D Confidence + Critical gate floor = Critical, report-only
```

Confidence may cause a reviewer to request verification. It cannot:

- remove a gate match;
- lower a gate floor;
- change `hard_gate=true` to false;
- lower effective score or Severity;
- enable or disable CI enforcement.

## 11. Failure behavior

`HardGateCode` provides stable safe failures:

```text
duplicate_finding_id
unknown_finding_id
duplicate_gate_id
source_rule_mismatch
```

Errors never contain scanned excerpts, secret values, absolute paths, gate
rationale, or underlying exception text.

Model validation also rejects:

- malformed Finding, Gate, or Rule IDs;
- empty or unsorted Rule IDs;
- invalid floor types;
- inconsistent base score and Severity;
- matches bound to another Finding;
- unsupported enforcement modes;
- incorrect mapping basis.

## 12. Security and determinism

Hard Gate processing:

- reads no files;
- writes no files;
- executes no shell or subprocess;
- performs no network access;
- imports no scanned project code;
- invokes no Skill, MCP, or LLM;
- does not inspect Evidence excerpts to select a floor;
- preserves Finding ID, Evidence, and Confidence;
- does not average Findings or matches;
- excludes `ConfidenceFinding` and match rationale from generated
  representations;
- returns stable output for identical input, matches, and Risk Model version.

## 13. Version decision

P1-23 changes:

```text
RISK_MODEL_VERSION: 0.3.0 → 0.4.0
```

The version changes because P1-23 adds:

- Hard Gate match meaning;
- High/Critical floor mappings;
- `max(base, floor)` aggregation behavior;
- report-only enforcement semantics;
- final score and Severity selection;
- Domain `hard_gate` interpretation.

The following remain unchanged:

```text
DOMAIN_SCHEMA_VERSION = 0.2.0
RULE_PACK_VERSION = 0.2.0
```

The Domain `Finding.hard_gate` field already exists, and no Rule trigger changes.
P1-24 later increments Domain Schema to `0.3.0` only to retain Config Schema
and Risk Model provenance in Assessment Metadata; it does not change P1-23
Hard Gate semantics.

Any future change to gate conditions, gate identity, floor values, floor
aggregation, enforcement mode, Confidence interaction, or blocking behavior
requires an ADR and Risk Model version change.

## 14. Deferred behavior

P1-23 does not implement:

- production Critical or High combination detectors;
- effective capability or permission resolution;
- CI enforcement;
- `--fail-on`;
- policy configuration;
- waivers or exceptions;
- gate approval ownership;
- P1-24 and P1-25 now provide Text and JSON Finding reporters;
- P1-26 now provides broader secret-redaction hardening;
- SARIF;
- organization-level enforcement mode.
