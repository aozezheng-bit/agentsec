# P3-12: AgentDojo-Style Injection Scenario Corpus

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-11A (human-confirmed gold labels; dependency released)
- Mode: static, report-only; no corpus execution; no network; no LLM
- Decision record: ADR-0094

## Objective

Add the plan's "AgentDojo 风格场景" evaluation set: paired normal-task and
attack-task cases recorded as static, non-executing corpus so later metric
work (P3-14) can replay detection-based attack-success proxies without
violating the scanner's execution invariants.

## What was delivered

```text
agentsec.semantic.scenarios        scenario contracts, pairing validation,
                                   fail-closed loader, Evaluation-Case converter
pilots/agentdojo-style-p3-12/      9 scenarios / 18 cases / bilingual pack + README
scripts/build-p3-12-agentdojo-scenarios.py   deterministic idempotent builder
tests/test_semantic_p3_12.py       16 tests (pairing, provenance, conversion,
                                   replay, tamper fail-closed)
docs/decisions/0093-agent-dojo-style-static-paired-scenario-corpus.md
```

Scenario inventory: 6 injection families (instruction_override ×2,
scanner_control ×3, finding_suppression, hidden_instruction,
command_execution, auto_approval) over real corpus from
`testdata/prompt-injection`, `testdata/safe`, `demos/release-agent{,-zh}`,
`demos/release-agent` prompt-injection, and Homi pilot snapshots; one
Chinese scenario pair provides bilingual coverage.

## Key behaviors

- Every scenario records exactly one `normal` and one `attack` task; the
  model rejects unpaired scenarios, wrong slot kinds, and duplicate case
  IDs across the set.
- Attack tasks must expect a supported `instruction_integrity` judgment;
  normal tasks must expect none (static injection signature, ADR-0094).
- Expected judgments are inherited verbatim from the P3-11A
  human-confirmed gold set; set-level `label_provenance` is
  `p3-11a_gold_derived` with the source gold file SHA-256 bound.
- `build_scenario_evaluation_cases` rebuilds Evidence chunks and
  recomputes content-addressed bindings, so tampered text or Evidence IDs
  fail closed; conversion output is sorted and unique for replay.
- Harness replay over converted cases with an echoing offline Provider
  yields precision=recall=1.0 (33 expected judgments); a Provider that
  drops attack candidates surfaces them as visible false negatives
  (the detection-based ASR proxy P3-14 will formalize).

## Authority boundary

```text
report_only                        true
blocks                             false
policy_authority / release_authority / runtime_verified   false
provider_promotion_authority       false
```

No Finding, Rule, Policy, CI, Hard Gate, release, or runtime authority is
granted or implied. No corpus content is executed; no secrets, raw
Provider payloads, or commands are stored or echoed.

## Verification

```bash
.venv/bin/python -m pytest tests/test_semantic_p3_12.py -q        # 16 passed
.venv/bin/python scripts/build-p3-12-agentdojo-scenarios.py       # idempotent
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy src tests
.venv/bin/python -m pytest
```

## Limitations and follow-ups

- Quality numbers on an offline fixture Provider are not real quality
  claims (P3-11/P3-11C boundary unchanged).
- Scenario count (9) is bounded by gold-confirmed corpus coverage; growth
  requires new human-confirmed gold cases first.
- ASR/Utility/FPR/FNR computation itself is P3-14; this task only records
  the paired tasks and their expected judgments.
- P3-13 (InjecAgent-style tool-description injection) is a separate Task
  ID and was intentionally not started (single-task principle).
- The next ADR number is 0094.
