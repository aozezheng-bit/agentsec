# ADR-0071: Homi Cross-file Combination Rules

- Status: Accepted for P2-HOMI-04
- Date: 2026-08-25
- Depends on: ADR-0070 Homi Capability Profile
- Scope: static report-only combination analysis; not runtime authorization

## Context

A single Homi file can be benign or ambiguous while the combination of several
files creates a materially different security story. Examples include proactive
persona guidance together with external tools, Heartbeat tasks together with
network access, and user-profile persistence together with long-term memory.

The P2-HOMI-03 Profile already provides typed, bounded states and source
locators. P2-HOMI-04 needs a deterministic rule seam that can consume that
Profile without rereading or executing Markdown and without treating a static
combination as proof of runtime reachability.

## Decision

Create an adapter-local `HomiCombinationRule` contract and
`DeterministicHomiCombinationRuleEngine` with a versioned Rule Pack `0.1.0`.
The first pack contains five rules:

```text
HOMI-COMB-001  proactive + external capability
HOMI-COMB-002  Heartbeat + external access
HOMI-COMB-003  USER persistence + persistent memory
HOMI-COMB-004  SOUL self-evolution + IDENTITY self-assignment
HOMI-COMB-005  active TOOLS binding + Skill tool discovery
```

Each rule returns bounded signal evidence and is materialized into a bilingual,
report-only `HomiCombinationFinding`. The result also records which tool notes
were suppressed because they were classified as `example_only`.

## Confidence and scoring

- Finding confidence is the weakest evidence confidence among its signals.
- Static declarations remain D confidence unless a future independently verified
  evidence layer supplies a different grade; this engine never emits runtime A.
- Existing NIST SP 800-30 / AgentSec mappings provide likelihood, high-water-mark
  impact, score, and severity.
- Severity is separate from evidence confidence.
- Critical or high impact is not diluted by averaging.

The combination rules are not CVSS calculations, runtime vulnerability proofs,
or CI gates. Their score is a deterministic review prioritization aid only.

## Security boundaries

The engine must not:

- execute or interpret Homi source as code;
- connect to any declared external tool or service;
- fetch remote avatars;
- copy raw User, tool, credential, or Secret values;
- infer that `TOOLS.md` is a runtime Tool Registry;
- convert Persona/Identity signals into permissions;
- block CI or authorize production changes.

## Consequences

Positive:

- cross-file interactions become explainable and testable;
- `example_only`, `conditional`, `present`, and `unknown` remain distinct;
- incomplete Profile coverage is visible instead of silently treated as absence;
- rule failures are isolated without leaking implementation details;
- later Safe Simulation and Homi CLI layers receive a stable deterministic input.

Trade-offs:

- lexical Profile signals have limited semantic recall;
- static combinations may be false positives without runtime attestation;
- the initial Rule Pack is intentionally small and requires calibration before
  any future enforcement use.

## Rejected alternatives

- **Run the Homi Agent to validate combinations:** unsafe and outside static
  scanner scope; runtime verification requires a separate sandbox/attestation
  design.
- **Treat every `TOOLS.md` example as active:** creates false runtime authority;
  example-only notes are explicitly suppressed.
- **Use an LLM as the blocking authority:** non-deterministic and inappropriate
  for authorization; LLM analysis can later provide candidate evidence only.
- **Reuse generic Agent Manifest Findings directly:** the Homi Profile has a
  different source/provenance contract and must not be forced into the Manifest
  schema prematurely.

## Follow-up

P2-HOMI-05 may add safe, bounded simulation, but simulation results must remain
separate from static evidence and must not automatically grant runtime authority.
P2-HOMI-06 may integrate these findings into a real-project report-only pilot.
P2-HOMI-07 may expose the engine through the CLI after its output contract is
reviewed.
