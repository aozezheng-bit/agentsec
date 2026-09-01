# P3-AG-05: Semantic / Deterministic Evidence Association

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-AG-01～04B
- Mode: report-only; deterministic correlation only
- ADR: `docs/decisions/0103-attack-path-evidence-association.md`

## Objective

Associate static Attack Graph paths with already validated deterministic
Findings and Shadow-only Semantic Candidates without turning a path or model
output into an authorization decision.

The implemented chain is:

```text
AttackGraphPath
  -> graph source locators (node/edge, path/hash/line)
  -> existing Finding Evidence (file/diff only)
  -> existing Semantic Candidate Evidence (trusted chunk IDs and locators)
```

The association layer is read-only. It does not create or mutate Findings,
Semantic Candidates, Rules, Policy, CI decisions, Hard Gates, release state,
or runtime attestations.

## Deliverables

- [x] Add `AttackPathEvidenceAssociator` deterministic API.
- [x] Match path source locators by normalized asset path, authoritative SHA-256,
      and overlapping line range.
- [x] Restrict Finding matching to complete `file` / `diff` Evidence.
- [x] Match Semantic Candidates only through supplied trusted
      `SemanticEvidenceChunk` objects and candidate Evidence IDs.
- [x] Distinguish `duplicates`, `supports`, `partially_supports`, and
      `unmatched` relationships.
- [x] Preserve node/edge source locators while omitting source text, excerpts,
      endpoints, credentials, and secrets.
- [x] Add canonical graph, path-report, Finding-input, and Semantic-result
      digest bindings.
- [x] Add frozen report model and JSON encoder/schema export.
- [x] Add deterministic replay, mismatch, partial-overlap, missing-Evidence,
      no-source, no-secret, immutability, and authority-boundary tests.
- [x] Register the schema in the provenance registry and release schema export.

## Public API

```python
from agentsec.attack_graph import AttackPathEvidenceAssociator

report = AttackPathEvidenceAssociator().associate(
    graph,
    findings=findings,
    semantic_result=semantic_result,
    semantic_evidence=semantic_chunks,
)
```

The report is `agentsec-attack-path-evidence-association-report` Schema
`0.1.0`. Each association names a `finding` or `semantic_candidate` target and
contains only value-free graph locators plus value-free target locators.

## Matching contract

A positive match requires all of:

1. normalized relative asset path equality;
2. exact SHA-256 equality;
3. overlapping line ranges;
4. for Findings, `source_type` is `file` or `diff` and all static locator
   fields are present;
5. for Semantic Candidates, the Evidence ID is present in the trusted chunk
   set supplied to the associator.

If every path source is covered with the exact same line range, the relation is
`duplicates`. If every path source is covered with a non-identical range, it is
`supports`. If only some path sources are covered, it is
`partially_supports`. Missing or invalid trusted Evidence yields `unmatched`.

The same source locator may be contributed by both a graph node and an edge;
this is represented once with sorted `roles`, so duplicate Evidence cannot
inflate the result.

## Authority and security boundary

The report always has:

```text
report_only=true
blocks=false
finding_authority=false
semantic_authority=false
policy_authority=false
ci_authority=false
hard_gate_authority=false
release_authority=false
runtime_verified=false
```

The association result is explanatory Evidence only. It does not alter Finding
Severity or Confidence, does not infer category from a path, does not accept
model-authored paths/locations, and does not claim reachability or
exploitability.

## Verification

```bash
.venv/bin/python -m pytest tests/test_attack_graph_p3_ag_05.py -q
.venv/bin/python -m pytest tests/test_provenance_registry.py -q
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
.venv/bin/python -m ruff check src tests scripts
.venv/bin/python -m mypy src tests
```

A CLI wrapper is intentionally deferred. P3-AG-05 first freezes the Python
correlation contract and report; a later CLI task may accept graph, Finding,
and semantic-result artifacts and must validate each input before association.
