# P2-29: CI Examples

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-25 through P2-28

Delivered executable GitHub Actions and GitLab CI examples around the canonical
Organization Policy exit-code contract. The shared Runner preserves JSON and
SARIF before returning the deterministic decision, and the GitHub workflow uses
a final always-run enforcement step so artifact upload cannot mask blocking.

## Acceptance replay

```text
safe complete                    → 0
risky enforce                    → 1
incomplete Coverage              → 2
invalid Policy                   → 3
active Waiver                    → 0
expired Waiver                   → 1
```

## Verification

```bash
.venv/bin/python scripts/validate-ci-examples.py \
  --agentsec .venv/bin/agentsec
.venv/bin/python -m pytest -q tests/test_ci_examples.py
```

## Final verification

```text
CI replay matrix: 6/6 passed
P2-29 targeted tests: 4 passed
Bash syntax: passed
Ruff check: passed
Ruff format: passed — 725 files
Mypy strict: passed — 253 source files
Pytest: 1136 passed
```

## Boundaries

P2-29 adds no new decision authority and does not claim a live remote CI run.
SARIF remains a review/reporting surface; deterministic Policy exit codes own
blocking. Real pilot-repository adoption and remote PR evidence remain P2-30.
