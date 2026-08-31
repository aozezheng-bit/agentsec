# P3-AG-01: Attack Graph Node / Edge Schema

- Status: Complete
- Date: 2026-08-31
- Depends on: P2-05（Agent Manifest Builder）、P2-12（Capability Rules）——均已满足
- Mode: schema-only; report-only; no runtime verification
- ADR: `docs/decisions/0093-attack-graph-node-edge-schema.md`

## Objective

Define the strict, versioned data contract for the Capability Attack Graph
track: node kinds, directed edge kinds and their endpoint matrix, the whole
graph container, and the static declared-path schema. The contract must
express untrusted input, tools, identity, data, and targets while preserving
value-free Evidence and reachability status without granting any authority.

Per the 2026-08-31 roadmap erratum, Attack Graph tasks are tracked as
P3-AG-01..07 and are distinct from the completed Semantic P3-01..P3-10 work.

## Deliverables

- [x] Eleven finite node kinds (`untrusted_input`, `tool`, `skill`,
      `mcp_server`, `agent`, `secret`, `data`, `memory`, `network`,
      `production_target`, `dependency`).
- [x] Fourteen finite directed edge kinds with a validated endpoint-kind
      matrix (`agentsec/attack_graph/models.py`, `_EDGE_ENDPOINT_KINDS`).
- [x] Content-addressed `attack-node-sha256:` / `attack-edge-sha256:` /
      `attack-path-sha256:` identifiers recomputed during validation.
- [x] Value-free Evidence: Manifest component references plus
      `(asset_path, asset_sha256, start_line, end_line)` source locators.
- [x] Static declared-path schema fixed to
      `path_kind=static_declared_path`, `runtime_verified=false`,
      `reachability=not_proven`, `exploitability=not_proven`.
- [x] `CapabilityAttackGraph` `0.1.0` container with Manifest binding,
      deterministic ordering, size bounds, and fixed false authority fields.
- [x] Canonical JSON encoder, bilingual-neutral Text renderer, and frozen
      JSON Schema export at `schemas/attack-graph/`.
- [x] `ATTACK_GRAPH_SCHEMA_VERSION` product record and schema-file ownership
      in `agentsec.provenance`.
- [x] ADR-0093, threat-model TM-36, and regression tests.

## Acceptance record

```text
Node/Edge/Graph/Path Schemas     agentsec.attack_graph（StrEnum + strict Pydantic）
内容寻址                          node/edge/path ID 由 canonical JSON SHA-256 重算并复核
证据形态                          仅 (asset_path, asset_sha256, start_line, end_line) + manifest_refs
权限                              report_only=true; blocks=false; 全部 authority=false
路径标记                          path_kind=static_declared_path; runtime_verified=false;
                                  reachability=not_proven; exploitability=not_proven
资源边界                          nodes≤2048; edges≤8192; paths≤256; 路径节点≤32
导出                              schemas/attack-graph/capability-attack-graph.schema.json
测试                              tests/test_attack_graph_p3_ag_01.py（20 项）
```

## Non-goals

- No Manifest→graph builder (P3-AG-02).
- No attack-path pattern library or matcher (P3-AG-03).
- No Text/JSON attack-path report (P3-AG-04).
- No semantic/deterministic evidence association (P3-AG-05).
- No Demo or calibration (P3-AG-06/07).
- No runtime reachability verification or exploitability proof, ever.
- No execution of scanned content; scanned text never enters graph artifacts.

## Verification commands

```bash
.venv/bin/python -m pytest tests/test_attack_graph_p3_ag_01.py -q
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
./scripts/check.sh
```

## Next task

```text
P3-AG-02: Manifest Capability Graph Builder
```
