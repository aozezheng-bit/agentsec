# AgentSec Capability Drift Story Demo

- Task: `P2I-05`
- Status: Complete and accepted
- Completion date: 2026-08-20
- Audiences: developers, security reviewers, and management
- English assets: `demos/capability-drift-agent/`
- Chinese assets: `demos/capability-drift-agent-zh/`

## 1. Purpose

P2I-05 demonstrates the complete Phase 2 integration path through the production
CLI:

```text
reviewed baseline
→ configuration drift
→ Agent Manifest
→ deterministic Capability Assessment
→ normalized Capability Diff
→ incomplete Coverage example
→ remediation
→ removal of current combination Findings
```

The Demo is an explainable static security-review story, not a runtime exploit.
It executes no scanned Command, Skill, Hook, plugin, Sub-Agent, Rule, or MCP
server; performs no external network access; reads no environment or credential
value; and calls no LLM.

## 2. Scenarios

| Scenario | Coverage | Findings | Expected exit |
|---|---|---:|---:|
| Baseline | Complete | 0 | `0` |
| Risky drift | Complete | 17 across 16 Rule IDs, highest High | `0` |
| Incomplete | Incomplete UTF-8 Override | 0, not a clean pass | `2` |
| Remediated | Complete | 0 | `0` |

The risky state declares execution, Secret access, external network, a required
credentialed external MCP identity, automatic approval behavior, delegation, and
persistent release memory. The first-release Capability Risk Model remains
report-only; every Finding has `hard_gate=false`.

## 3. Live automation

English:

```bash
scripts/run-capability-demo.sh --language en
```

Chinese:

```bash
scripts/run-capability-demo.sh --language zh
```

The runner creates Manifest and Assessment Text/JSON for all four states, plus
baseline-to-risky and risky-to-remediated Capability Diff and Capability Impact
Text/JSON. It validates Schema contracts, expected Findings, Coverage, policy,
remediation, Finding Delta, and absence of synthetic secret/endpoint values from
output.

## 4. Presenter flow

```bash
scripts/demo-capability-drift.sh --language en
scripts/demo-capability-drift.sh --language zh
```

Use `--no-pause` for rehearsal. The seven stages are:

```text
security boundary
reviewed baseline
risky Capability Assessment
Capability Diff
a deliberately incomplete scan
remediation and removal Diff
management close
```

The management close fits in one screen and states that the recommendation to
hold release is a human governance decision, not a CLI block.

## 5. Offline fallback

```bash
scripts/demo-capability-drift.sh --language en --offline --no-pause
scripts/demo-capability-drift.sh --language zh --offline --no-pause
```

Each language has 26 frozen report/summary artifacts plus
`checksums.sha256`. Frozen JSON is strict and deterministic; Text matches the
selected presenter language. Regeneration is explicit:

```bash
PYTHONPATH=src .venv/bin/python scripts/freeze_capability_demo.py
```

Validation:

```bash
PYTHONPATH=src .venv/bin/python \
  scripts/validate_capability_demo_outputs.py \
  demos/capability-drift-agent/expected
```

## 6. Developer outcomes

A developer can inspect:

- Tool, Permission, Control, Runtime Identity, Relationship, and Unknown IDs;
- added, removed, and modified normalized items;
- Rule ID, correlation, related IDs, Severity, and Evidence Confidence;
- portable path, structured field, line range, and SHA-256 provenance;
- complete versus incomplete Coverage;
- canonical Manifest, Capability Assessment, and Capability Diff JSON;
- remediation changes without exposing complete raw before/after values.

## 7. Management outcomes

A management viewer can answer:

```text
What changed?
Why does the combination matter?
Which external identity, credential, approval, delegation, and memory boundaries
are involved?
What is the highest reported Severity?
What remediation removes the chain?
Does AgentSec block CI or prove exploitation?
```

The answers are: high-impact static capability drift was detected; the highest
reported Severity is High; remediation removes current matching declarations;
and AgentSec remains report-only with runtime capability unverified.

## 8. Acceptance and limitations

Acceptance records:

- `demos/capability-drift-agent/acceptance.md`
- `demos/capability-drift-agent-zh/acceptance.md`

The Demo does not prove actual grants, reachable attack paths, successful
exploitation, absence of unsupported semantic risk, or global Agent safety. The
frozen Phase 1 release artifacts are not rebuilt by P2I-05.

## 9. Next work

The Phase 2 integration chain P2I-01 through P2I-05 and Integration Hardening /
Release Review are complete. Final package-level verification passes Ruff, Ruff
Format across 405 files, strict Mypy across 165 source files, 809 Pytest cases,
both live language tracks, both offline checksum fallbacks, frozen Schema and
source/candidate consistency checks, and a non-editable offline wheel install.

P2-13 Capability Change Impact / Finding Delta and P2-14 Capability Rule Pack
`0.2.0` are implemented in the source tree and included in the development Demo
artifacts. The still-open next work is P2-15 reviewed report-only Capability Hard
Gates before any enforcement Policy. P2-13 and P2-14 remain unreleased until a
future package release review.
