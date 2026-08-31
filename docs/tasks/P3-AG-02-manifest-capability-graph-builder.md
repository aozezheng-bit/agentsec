# P3-AG-02: Manifest Capability Graph Builder

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-AG-01（Schema 已交付）、P2-05/P2-08～P2-10（Manifest 维度）
- Mode: report-only; no runtime verification; no matching
- ADR: `docs/decisions/0097-attack-graph-manifest-builder.md`（含 ADR-0093 端点矩阵修正）

## Objective

Turn one validated `AgentManifest` into a reproducible
`CapabilityAttackGraph` without opening project files or copying raw
scanned text. The graph is serializable, stably sorted, reproducible, and
testable, with every authority boolean false and no path claims.

## Deliverables

- [x] `ManifestCapabilityGraphBuilder.build(manifest)` with fail-closed
      input typing (`AttackGraphBuildError` / `TypeError`).
- [x] Deterministic node mapping: identity AGENT, relation-derived child
      AGENT and MEMORY nodes, tool-family nodes (`skill` / `mcp_server` /
      `tool`), permission-derived SECRET and PRODUCTION_TARGET nodes, one
      `untrusted_input` node per OVERRIDE instruction candidate, and shared
      canonical SYNTHETIC network/memory sinks.
- [x] Deterministic edge mapping: relation `delegates_to` / `uses_*` /
      memory edges, permission `reads_secret` / `sends_to` / memory edges,
      tool `network`-side-effect `sends_to`, MCP `provides_tool`, and
      `overrides_instruction`.
- [x] Value-free Evidence: `(asset_path, content_sha256, start_line,
      end_line)` with whole-file fallback `(1, max(line_count, 1))`.
- [x] Deterministic merging by node/edge identity with the 16-Evidence
      bound fail-closed; self-delegation fails closed.
- [x] `canonical_manifest_sha256(manifest)` binding equal to the P3-09
      canonical digest; `ATTACK_GRAPH_BUILDER_VERSION 0.1.0` provenance
      registration; public API export.
- [x] ADR-0093 endpoint-matrix amendment: `sends_to` accepts
      `agent|tool|skill|mcp_server`; `writes_to` / `installs` accept
      `tool|skill|mcp_server`.
- [x] Regression tests over a real Codex project and a controlled synthetic
      Manifest.

## Acceptance record

```text
Builder                           ManifestCapabilityGraphBuilder 0.1.0
输入                              已验证 AgentManifest（不打开项目文件）
可复现性                          同一 Manifest 两次构建结果与 JSON 完全一致
Manifest 绑定                     canonical_manifest_sha256 == P3-09 canonical digest
确定性                            节点按 node_id、边按 edge_id 排序；合并规则固定
权限                              report_only=true; blocks=false; 全部 authority=false;
                                  paths=()（匹配留给 P3-AG-03）
映射缺口（已披露）                agent→production 无边类；runtime identity / DATA /
                                  DEPENDENCY 节点未映射；禁用工具与 deny 权限不产图
测试                              tests/test_attack_graph_p3_ag_02.py（8 项，含
                                  真实 Codex 项目与合成 Manifest 矩阵）
```

## Non-goals

- No attack-path pattern matching (P3-AG-03).
- No attack path report rendering of findings (P3-AG-04).
- No semantic/deterministic evidence association (P3-AG-05).
- No graph CLI command, Demo, or calibration (later tasks).
- No runtime reachability or exploitability claims, ever.

## Verification commands

```bash
.venv/bin/python -m pytest tests/test_attack_graph_p3_ag_02.py tests/test_attack_graph_p3_ag_01.py -q
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
./scripts/check.sh
```

## Next task

```text
P3-AG-03: Attack Path Pattern Library / Matcher (ADR-0098)
```
