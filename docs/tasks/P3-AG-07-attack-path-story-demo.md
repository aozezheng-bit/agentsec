# P3-AG-07: Attack Path Story Demo

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-AG-01～06
- Audience: developers, security reviewers, and management
- Mode: report-only; inert Homi-like fixtures

## Objective

Provide a repeatable presenter Demo that explains the complete Attack Graph
Evidence chain without executing the target Agent:

```text
Homi-like workspace
  → Manifest / static Capability Graph
  → static Attack Path
  → existing deterministic Finding
  → Shadow Semantic Candidates
  → exact / partial / unmatched Evidence association
  → Text / JSON report
```

## Demo assets

The inert synthetic Agent is under:

```text
demos/attack-path-story-agent/
```

It contains Homi-style `AGENTS.md`, `SOUL.md`, `IDENTITY.md`, `USER.md`,
`TOOLS.md`, `HEARTBEAT.md`, a Skill, and a TOML MCP declaration. Values are
synthetic and external locations use `example.invalid`; no credential value is
included.

The runner intentionally selects one static path as the story slice so the
presenter sees three understandable outcomes rather than an unbounded matrix:

- one deterministic Finding with `partially_supports`;
- one Semantic Candidate with `duplicates`;
- one unrelated Semantic Candidate with `unmatched`.

## Running

Generate and validate artifacts:

```bash
scripts/run-attack-path-demo.sh
scripts/run-attack-path-demo.sh --output-dir /tmp/agentsec-attack-path-demo
```

Presenter flow:

```bash
scripts/demo-attack-path.sh --no-pause
```

The generated directory contains:

```text
graph.json
findings.json
semantic-result.json
semantic-evidence.json
association-report.json
association-report.txt
story-summary.json
```

## Narration

1. **Collect:** Homi has multiple control files; they are read as inert text.
2. **Model:** AgentSec converts declarations into a value-minimized graph.
3. **Match:** a static instruction-override-to-tool path is identified.
4. **Associate:** trusted locators connect the path to deterministic and
   semantic Evidence.
5. **Interpret:** exact, partial, and unmatched are separate outcomes.
6. **Close:** the report is evidence for review, not a runtime exploit proof or
   CI blocking decision.

## Acceptance criteria

- [x] Real production CLI `agentsec attack-graph-associate` is exercised.
- [x] Project analysis, graph artifact, Finding input, Semantic Result input,
      and Semantic Evidence input are all represented.
- [x] Text and JSON reports are generated and schema-validated.
- [x] Same inputs produce deterministic output.
- [x] No source code, Skill, Hook, MCP server, Provider, or target command is
      executed.
- [x] No source excerpt, credential, endpoint, or secret is emitted by the
      association report.
- [x] All authority flags remain disabled and runtime behavior remains
      `not_proven`.
- [x] Output directory is private (`0700`); generated files are private
      (`0600`) and existing files are never clobbered.

## Limitations

The Demo is a story slice, not a benchmark. It does not qualify a Gate, prove
runtime reachability, demonstrate exploitation, or establish Semantic Provider
quality. Evidence calibration is a separate follow-up task.
