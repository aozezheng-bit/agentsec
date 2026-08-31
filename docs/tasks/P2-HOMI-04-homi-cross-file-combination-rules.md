# P2-HOMI-04: Homi Cross-file Combination Rules

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-HOMI-01, P2-HOMI-02, P2-HOMI-03
- ADR: `docs/decisions/0071-homi-cross-file-combination-rules.md`

## Objective

Evaluate bounded combinations of the P2-HOMI-03 static Profile. The goal is to
identify interactions that are more security-relevant than any single file
alone, while preserving the distinction between:

```text
static declaration     evidence of intent or documented behavior
runtime authority      a separately verified Tool/Scheduler/Permission fact
report-only finding    an explanation for review, not a CI decision
```

## Delivered

```text
src/agentsec/frameworks/homi_combination.py
src/agentsec/frameworks/__init__.py
tests/test_homi_combination.py
docs/decisions/0071-homi-cross-file-combination-rules.md
```

Public entry point:

```python
from agentsec.frameworks import (
    DeterministicHomiCombinationRuleEngine,
    HomiCapabilityProfileBuilder,
)

profile = HomiCapabilityProfileBuilder().build(inspection)
result = DeterministicHomiCombinationRuleEngine().run(profile)
```

## Rule Pack 0.1.0

The initial five rules are deterministic, bilingual, and report-only:

| Rule | Combination | Default impact | Purpose |
|---|---|---|---|
| `HOMI-COMB-001` | proactive persona + active external capability | confidentiality/downstream | Identify autonomous behavior combined with network, message, MCP, SSH, camera, TTS, OAuth, or Secret-like declarations. |
| `HOMI-COMB-002` | non-empty Heartbeat + external access | confidentiality/downstream | Identify scheduled behavior combined with network, message, or MCP declarations. |
| `HOMI-COMB-003` | USER persistence + persistent memory | confidentiality/integrity | Identify user-profile retention combined with long-term memory behavior. |
| `HOMI-COMB-004` | SOUL self-evolution + IDENTITY self-assignment | integrity/downstream | Identify cross-file control/identity self-modification intent. |
| `HOMI-COMB-005` | active TOOLS binding + Skill tool discovery | integrity/downstream | Identify environment bindings exposed to Skill-based tool extension. |

The rules do not create a finding for `TOOLS.md` template examples alone. The
run result reports those capabilities in `suppressed_example_capabilities`, so a
reviewer can distinguish:

```text
example_only  documented sample; does not trigger an active-tool combination
conditional   static declaration with a boundary or approval condition
present       static declaration without runtime proof
unknown       no deterministic conclusion or incomplete source coverage
```

## Evidence and scoring

Each finding contains:

- stable `HOMI-COMB-NNN` rule ID;
- English and Chinese title/description/recommendation;
- related Profile signal IDs;
- source locators without source excerpts or sensitive values;
- evidence method, state, and confidence for each signal;
- rationale and limitations;
- NIST SP 800-30 / AgentSec 0-10 mapped likelihood, impact, score, and severity;
- `report_only=true` and `runtime_verified=false`.

The finding confidence is the weakest confidence across its supporting signals.
Static Homi declarations normally result in D confidence; the engine never
upgrades static evidence to runtime proof. Impact uses the existing high-water
mark policy and is not averaged down by other dimensions.

## Determinism and failure isolation

- Built-in rules are ordered by stable rule ID.
- Candidates and findings are sorted and deduplicated deterministically.
- A failed rule becomes a bounded `HomiCombinationRuleFailure`; exception details
  are not returned.
- Incomplete Profile coverage remains visible through `profile_complete=false`
  and `result.complete=false`, while safe rules may still report findings.
- Finding IDs are SHA-256 derived from the rule ID, signal IDs, states,
  confidences, and source locator metadata.

## Security invariants

- Never execute Homi Markdown or any embedded command/code.
- Never connect to SSH, MCP, OAuth, Camera, TTS, network, or a scheduler.
- Never fetch Avatar URLs.
- Never copy user-profile values, passwords, IP addresses, tokens, or Secret
  values into the result.
- Never treat `TOOLS.md` as a Runtime Tool Registry.
- Never treat Persona or Identity as runtime permission.
- Never emit CI blocking or Hard Gate decisions from this layer.
- LLM semantic analysis is not used; future LLM output remains candidate evidence.

## Verification

```text
.venv/bin/pytest -q tests/test_homi_adapter.py tests/test_homi_profile.py tests/test_homi_combination.py
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/mypy
```

P2-HOMI-04 acceptance tests cover all five combinations, template-example
suppression, incomplete coverage visibility, localization, deterministic Rule
registration, failure isolation, report-only flags, and Secret non-disclosure.

## Deferred work

```text
P2-HOMI-06 Homi Real-project Report-only Pilot
P2-HOMI-07 Homi CLI Packaging
```
