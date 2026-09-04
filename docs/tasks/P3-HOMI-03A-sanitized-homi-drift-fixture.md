# P3-HOMI-03A：Sanitized Homi Capability Drift Fixture

- Status: Complete
- Completed: 2026-09-01
- Mode: static, offline, report-only
- Audience: developers, security reviewers, and management

## Goal

Provide a sanitized Homi/OpenClaw workspace fixture that demonstrates the
smallest useful path from a reviewed baseline to deterministic capability and
risk drift. The fixture is separate from any real Homi workspace and contains
no credentials, private keys, production endpoints, or executable files.

## Cases

- `baseline/`: six-file, low-risk reference state.
- `drift-add-external-message/`: adds a conditional external-message declaration
  and proactive persona signal; expected `HOMI-COMB-001`.
- `drift-modify-memory-policy/`: adds user-profile persistence wording; expected
  `HOMI-COMB-003`.
- `drift-remove-safety-control/`: adds autonomous control-file, persona, and
  identity modification wording; expected `HOMI-COMB-004`.

## Runner

```bash
PYTHONPATH=src .venv/bin/python scripts/run-homi-drift-demo.py --language zh
```

The runner executes only the AgentSec CLI against the fixture. It writes JSON
and text Homi Pilot reports plus a bounded demo drift report containing:

- capability state changes classified as `added`, `removed`, or `modified`;
- Finding Delta by stable Homi Rule ID;
- a presentation-only sum of Homi combination Finding scores;
- explicit `report_only=true`, `runtime_verified=false`, and `ci_blocked=false`.

The score is not the Phase 2/3 Agentic Overall Score and cannot authorize or
block an action. It is included only to tell the story of directional change.

## Acceptance Criteria

- Every case contains exactly the six standard Homi files.
- The fixture is inert and sanitized.
- Baseline has no Homi combination Findings.
- Each drift case produces its intended capability/risk signal.
- The runner passes through `agentsec homi scan` and produces JSON/Text output.
- No source content is executed and no real Homi Workspace is modified.
