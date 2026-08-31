# P3-13: InjecAgent-Style Tool-Injection Scenario Corpus

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-11A (human-confirmed gold labels; dependency released)
- Mode: static, report-only; no corpus execution; no network; no LLM
- Decision record: ADR-0095

## Objective

Add the plan's "InjecAgent 风格场景" evaluation set: paired scenario
tasks adapted from the tool-injection benchmark so later metric work
(P3-14) can replay detection-based attack-success proxies for the
tool-integration channel without violating the scanner's execution
invariants.

## What was delivered

```text
agentsec.semantic.scenarios        extended with the
                                   agentsec-p3-13-injecagent-scenario-set
                                   family: InjecAgentIntent taxonomy,
                                   tool-injection static signature,
                                   pairing validation, fail-closed loader,
                                   shared-case Evaluation converter
pilots/injecagent-style-p3-13/     7 scenarios / 14 cases / bilingual pack
                                   + README
scripts/build-p3-13-injecagent-scenarios.py   deterministic idempotent builder
tests/test_semantic_p3_13.py       19 tests (pairing, signature, provenance,
                                   conversion, replay, tamper fail-closed)
docs/decisions/0095-injecagent-style-static-tool-injection-scenario-corpus.md
```

Scenario inventory: six intents (secret_disclosure, data_forwarding,
tool_commandeering ×2, external_tool_binding, destructive_action,
multi_capability_chain) over real corpus from `testdata/risky`,
`testdata/safe`, `demos/release-agent-zh`, and Homi pilot snapshots;
`scenario-zh-capability-chain` provides the Chinese pair.

## Key behaviors

- Every scenario records exactly one `normal` and one `attack` task; the
  model rejects unpaired scenarios, wrong slot kinds, and duplicate case
  IDs within the set.
- Attack tasks must expect a supported tool-integration judgment
  (`code_execution` / `network_access` / `external_tooling` /
  `secret_access` / `destructive_action`); normal tasks must expect none
  — the static tool-injection signature complementary to P3-12's
  `instruction_integrity` channel.
- Expected judgments are inherited verbatim from the P3-11A
  human-confirmed gold set; set-level `label_provenance` is
  `p3-11a_gold_derived` with the source gold file SHA-256 recorded and
  test-verified against the artifact.
- `build_injecagent_evaluation_cases` shares the P3-12 conversion path:
  Evidence chunks are rebuilt with recomputed content addressing, so
  tampered text or Evidence IDs fail closed.
- Harness replay over converted cases with an echoing offline Provider
  yields precision=recall=1.0 (24 expected judgments); a Provider that
  drops attack-side candidates surfaces the 11 attack-task judgments as
  visible false negatives (the detection-based ASR proxy P3-14 will
  formalize).
- Two normal cases are intentionally shared with the P3-12 pack
  (`safe-local-only-network`, `safe-read-only-control-assets`): the same
  corpus serves both channel lenses; case IDs remain unique per set.

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
.venv/bin/python -m pytest tests/test_semantic_p3_13.py -q        # 19 passed
.venv/bin/python scripts/build-p3-13-injecagent-scenarios.py      # idempotent
.venv/bin/python -m ruff check . && .venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy src tests
.venv/bin/python -m pytest
```

## Limitations and follow-ups

- Quality numbers on an offline fixture Provider are not real quality
  claims (P3-11/P3-11C boundary unchanged).
- Scenario count (7) is bounded by gold-confirmed corpus coverage; growth
  requires new human-confirmed gold cases first.
- ASR/Utility/FPR/FNR computation itself is P3-14; this task only records
  the paired tasks and their expected judgments.
- InjecAgent's dynamic dimensions (injection position within tool
  descriptions, real tool-call observation) are NOT statically
  recorded; intents and detection expectations are.
- P3-14 was intentionally not started (single-task principle).
- The next ADR number is 0096.
