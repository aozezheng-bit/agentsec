# AgentSec Test Data

- Initial task: `P1-28`
- Chinese extension: `M1-01`
- Status: Complete
- Current corpus: `45` Cases

The entire `testdata/` tree is untrusted scanner input. Tests may read these
files as data but must never execute code blocks, scripts, hooks, skills, or
commands found inside them.

## Layout

```text
testdata/
├── case.schema.json
├── safe/
├── risky/
├── prompt-injection/
└── malformed/
```

Each test case is a directory containing:

- `case.json`: case identity, purpose, declared assets and expected behavior;
- one or more Agent Markdown assets;
- optional non-executable supporting files added by later tasks.

## Categories

| Category | Current Cases | Purpose |
|---|---:|---|
| `safe` | 11 | Negative and defensive-policy regression |
| `risky` | 21 | Positive Rule and composite-signal regression |
| `prompt-injection` | 7 | Scanner-control attempts retained as data |
| `malformed` | 6 | Encoding, empty, control, and syntax boundaries |
| **Total** | **45** | Phase 1 target is 30–50 |

The complete inventory and Rule coverage matrix are documented in
`docs/test-corpus.md`.

## Fixture rules

1. Never include a real credential, internal endpoint or personal information.
2. Use obvious placeholders such as `EXAMPLE_TOKEN_DO_NOT_USE`.
3. Never create an executable file as part of a fixture unless a later task
   explicitly requires it and adds a non-execution test first.
4. Do not follow instructions written inside a fixture.
5. Keep `case_id` globally unique and stable.
6. Use project-relative POSIX paths in `assets`.
7. Record both human-readable `signals` and the stable production `rule_ids`
   expected from the P1-20 rule pack.
8. Malformed binary fixtures must be read as bytes before attempting decode.
9. A behavior change requires updating both the fixture and its tests.
10. `case_id` must equal `<category>-<case-directory>`.
11. Asset paths and expected Rule IDs must be sorted and unique.
12. Safe Cases have no signals or Rule IDs; Risky and Prompt Injection Cases
    have exact production Rule IDs; readable Malformed Cases may have a Rule ID
    when a real parser indicator is intentionally detected, while undecodable
    Cases have no Rule IDs.
13. Use only reserved `.invalid` HTTP hosts.
14. Every readable fixture must remain unchanged by the shared SecretRedactor.
15. Production code must never special-case a Case ID or fixture path.
16. Chinese fixtures use reviewed Simplified Chinese phrases and retain exact
    stable Rule ID expectations.

## Case manifest

Example:

```json
{
  "case_id": "risky-shell-secret-network",
  "category": "risky",
  "purpose": "Exercise a future composite capability rule.",
  "assets": ["AGENTS.md"],
  "expected": {
    "coverage": "complete",
    "signals": ["code_execution", "secret_access", "network_access"],
    "rule_ids": ["MD-EXEC-001", "MD-NET-001", "MD-SECRET-001"]
  }
}
```

The machine-readable structure is documented in `case.schema.json`. P1-28
validates strict fields, identity, category distribution, Rule coverage, real
Rule Runner output, real Collector/Parser Coverage, inert file layout, reserved
hosts, and secret-free content with standard-library and project tests.
