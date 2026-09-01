# P3-AG-04B: Attack Graph CLI Wiring

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-AG-01（Schema）、P3-AG-02（Builder）、P3-AG-03（Matcher）、P3-AG-04（Report）
- Mode: report-only; static declared paths only
- ADR: `docs/decisions/0102-attack-graph-cli-wiring.md`

## Objective

Expose the existing Attack Graph Schema, Manifest builder, path matcher, and
P3-AG-04 report as one safe, installable CLI workflow:

```text
agentsec attack-graph PROJECT
  → AgentAnalysisPipeline
  → ManifestCapabilityGraphBuilder
  → AttackPathMatcher
  → build_attack_path_report
  → Text/JSON output
```

The command must not execute scanned code, connect to MCP, make network calls,
claim runtime reachability, or grant Finding/Policy/CI/Hard-Gate authority.

## Deliverables

- [x] Add `DeterministicAttackGraphAnalysisEngine` application service.
- [x] Add `AttackGraphAnalysisResult` binding Manifest analysis, matched graph,
      and report digests.
- [x] Add `agentsec attack-graph PROJECT`.
- [x] Support `--format text|json` and `--output PATH`.
- [x] Support explicit project/user/Codex roots and `--agent-id`.
- [x] Reuse `ReportArtifactWriter` with a dedicated
      `ATTACK_PATH_REPORT` artifact kind.
- [x] Validate JSON artifacts against `AttackPathReport` before writing and on
      `--force` replacement.
- [x] Map incomplete Manifest Coverage to stable exit code `2`.
- [x] Keep analysis and graph failures fail-closed with safe exit code `5`.
- [x] Add CLI, artifact-writer, canonical JSON, no-secret, and authority-boundary tests.
- [x] Export the application service through the public Python API.
- [x] Add this task record, ADR, current architecture/status, README, and changelog updates.

## Command examples

```bash
agentsec attack-graph ./homi-agent --format text
agentsec attack-graph ./homi-agent \
  --format json \
  --output /tmp/attack-path-report.json
```

The command is report-only. A successful scan with no paths returns `0`; an
incomplete Manifest Coverage returns `2`; artifact validation/output errors
return `4`; required analysis or graph failures return `5`.

## Output contract

Text begins with the fixed boundary and reports one bounded line per matched
path. JSON is the canonical `agentsec-attack-path-report` `0.1.0` artifact.
The report retains only Pattern ID, node-kind sequence, content-addressed Node
IDs, counts, digests, and fixed limitations. It does not retain labels,
Manifest references, source excerpts, credentials, or endpoints.

## Security invariants

```text
No target-project code/script/Hook/Skill/MCP execution
No MCP connection or default network access
No raw source, credential, endpoint, or secret value in report output
No model invocation
report_only=true
blocks=false
runtime_verified=false
reachability=not_proven
exploitability=not_proven
finding/policy/CI/Hard-Gate/release authority=false
```

## Acceptance criteria

1. `agentsec attack-graph --help` exposes the command and safe options.
2. A real Homi/Codex project can be analyzed through the deterministic pipeline.
3. Text and JSON outputs are deterministic for the same input and versions.
4. JSON output validates as `AttackPathReport` and is safe for atomic artifact writing.
5. `--force` replaces only an existing valid same-kind report.
6. Incomplete source coverage is visible and returns exit `2`.
7. The command does not expose source labels, endpoints, environment names, or secrets.
8. The full test suite, package hardening, and reproducible-build checks pass.

## Verification

```bash
.venv/bin/python -m pytest tests/test_attack_graph_cli.py -q
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
./scripts/check.sh
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
PYTHONPATH=src .venv/bin/python scripts/verify-reproducible-build.py
```
