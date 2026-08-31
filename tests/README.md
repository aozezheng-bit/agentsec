# Tests

Pytest, Ruff, and Mypy are configured by task P0-03. Test modules and fixtures
must follow the task IDs and security invariants defined in the execution plan.

Untrusted scanner fixtures live in `testdata/` and follow the manifest and
safety rules in `testdata/README.md`.

Run the complete local/CI quality gate from the repository root:

```bash
scripts/check.sh
```
