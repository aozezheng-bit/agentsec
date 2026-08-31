# P2-EXIT-03: Integrated Agentic Score CLI/Report

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-31, P2-EXIT-01
- Package: `0.3.0 → 0.4.0.dev0` (development line toward 0.4.0)
- Agentic Assessment Output: `0.1.0`
- Score Context Schema: `0.1.0`
- User documentation: `docs/agentic-score.md`

Exposed the complete P2-18 through P2-23 deterministic scoring chain through
one additive CLI command. `capability assess` and all existing command
semantics remain unchanged. The score is report-only and does not gain CI
authority in this task.

## Delivered

```text
src/agentsec/score_context.py                  bounded score-context contract 0.1.0
src/agentsec/application/agentic_score.py      AgenticScoreEngine orchestration
src/agentsec/reporting/agentic_score.py        Text/JSON report + schema export
src/agentsec/reporting/sarif.py                AgenticAssessmentSarifRenderer
src/agentsec/artifacts/storage.py              AGENTIC_ASSESSMENT artifact kind
src/agentsec/cli/score.py                      `agentsec score` command
src/agentsec/cli/app.py                        score command registration
src/agentsec/versioning.py                     AGENTIC_ASSESSMENT_OUTPUT_VERSION,
                                               SCORE_CONTEXT_SCHEMA_VERSION,
                                               PACKAGE_VERSION 0.4.0.dev0
schemas/agentic-assessment/...schema.json      frozen report schema
schemas/score-context/...schema.json           frozen context schema
tests/test_agentic_score_cli.py                10 tests
docs/agentic-score.md                          user documentation
testdata/scoring-replay/expected.json          re-baselined (package-version
                                               provenance change only; P2-32
                                               precedent)
```

## Contract decisions

- Command surface: additive `agentsec score` (plan Option B); no existing
  command semantics changed.
- `--before` is required; Drift/Governance context comes only from the
  explicit `--context` file or conservative `unknown` defaults — values are
  never fabricated.
- CVSS is an optional context block adapted through the existing deterministic
  CVSS adapter; Gate floors accept only `accepted` matches with confidence
  A/B/C (D-confidence rejected at load with exit 3).
- Incomplete Coverage keeps fail-closed exit `2` after rendering the honest
  report; incompatible/missing before Manifests return exit `4`; invalid
  context returns exit `3`.

## Acceptance

```text
Ruff check / format: see final project gate
Mypy strict: see final project gate
Pytest: full suite green (1196+ tests), including:
  tests/test_agentic_score_cli.py                 10 passed
  tests/test_release_artifacts.py (frozen schemas) 9 passed
  tests/test_scoring_replay.py re-baselined suite  passed
  tests/test_rule_score_calibration.py             passed
  tests/test_poc_documentation.py version block    passed
CLI smoke: score text/json/sarif on the Capability Drift demo story verified
```

## Boundaries

- Score output never blocks CI, grants no Gate authority, and does not change
  the deterministic Policy enforcement path.
- No LLM involvement; runtime capability unverified; no execution of scanned
  content.
- The 0.4.0 release itself remains gated on P2-EXIT-04 through P2-EXIT-08.

## Next task

```text
P2-EXIT-04: Hard Gate Scope Closure
```
