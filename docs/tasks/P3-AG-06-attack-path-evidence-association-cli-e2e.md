# P3-AG-06: Attack Path Evidence Association CLI / E2E Integration

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-AG-05
- Mode: report-only; no enforcement
- Artifact kind: `attack_path_evidence_association`

## Objective

Expose the P3-AG-05 deterministic association contract through a safe CLI and
connect it to both validated JSON artifacts and the existing Manifest-to-Graph
application pipeline.

## Commands

Artifact mode:

```bash
agentsec attack-graph-associate \
  --graph graph.json \
  --findings findings.json \
  --semantic-result semantic-result.json \
  --semantic-evidence semantic-evidence.json \
  --format json \
  --output association-report.json
```

Project mode:

```bash
agentsec attack-graph-associate \
  --project ./homi-agent \
  --findings findings.json \
  --format text
```

Exactly one of `--graph` and `--project` is required. Finding and Semantic
inputs are optional; when omitted, the report makes the missing association
surface explicit rather than silently claiming a match.

## Input contracts

`AttackPathAssociationInputReader` reads bounded regular UTF-8 JSON files with
`O_NOFOLLOW`, rejects symlinks and non-regular files, rejects invalid JSON
constants, and validates:

- `CapabilityAttackGraph` for `--graph`;
- a Finding array or an object with a `findings` array for `--findings`;
- `SemanticAnalysisResult` for `--semantic-result`;
- a Semantic Evidence array or an object with an `evidence` array for
  `--semantic-evidence`.

The reader never executes input content and never includes input payloads in
error messages.

## Output and exit behavior

Output uses the P3-AG-05 frozen report:

```text
agentsec-attack-path-evidence-association-report 0.1.0
```

Both Text and JSON are supported. JSON output is validated again by
`ReportArtifactWriter`, which supports atomic writes and same-kind `--force`
replacement. Valid report-only unmatched results return exit `0`; malformed
input/output returns `4`; analysis failures return `5`; incomplete project
analysis returns `2` after the report is emitted.

## Security boundary

```text
No target-project code/script/Hook/Skill/MCP execution
No network or Provider invocation
No source excerpts, credentials, endpoints, or secrets in output
report_only=true
blocks=false
finding/semantic/policy/CI/Hard-Gate/release authority=false
runtime_verified=false
```

The CLI is an output adapter. Correlation remains in
`AttackPathEvidenceAssociator`; it cannot create or mutate a Finding or
Semantic Candidate and does not alter Severity, Confidence, Policy, or CI.

## Verification

```bash
.venv/bin/python -m pytest tests/test_attack_graph_association_cli.py -q
.venv/bin/python -m ruff check src tests scripts
.venv/bin/python -m mypy src tests
```
