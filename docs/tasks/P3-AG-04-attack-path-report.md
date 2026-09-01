# P3-AG-04: Attack Path Report

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-AG-01（Schema）、P3-AG-02（Builder）、P3-AG-03（Matcher）
- Mode: report-only; no runtime verification
- ADR: `docs/decisions/0101-attack-path-report.md`

## Objective

Deliver a Text/JSON attack path report showing matched static paths,
their evidence, and limitations, without ever claiming runtime
exploitability. The report is deterministic, value-free, and fails
closed on graph/entry mismatch.

## Deliverables

- [x] `AttackPathReportEntry 0.1.0` with value-free path content
      (pattern_id 连同 node kind 序列和节点内容寻址 ID)、
      entry-level cross-field coherence validation，和
      fixed boundary marks。
- [x] `AttackPathReport 0.1.0` with graph digest binding、
      `pattern_library_version` freeze、`path_count == len(entries)` and
      sorted-unique path IDs，and mandatory disclosed limitations。
- [x] `build_attack_path_report(graph)` builder that derives every field
      from the validated graph and fails closed on wrong input。
- [x] Text renderer with bounded per-path lines and boundary-first
      disclaimer footer；JSON encoder with canonical deterministic
      round-trip。
- [x] Frozen JSON Schema export（`schemas/attack-graph/attack-path-report.schema.json`）
      with provenance ownership and registry entry
      （`ATTACK_PATH_REPORT_VERSION`）。
- [x] 12 regression tests covering empty report、binding determinism、
      coherence validation、value-free text and JSON、schema export,
      and the real Codex pipeline。

## Acceptance record

```text
报告格式                          agentsec-attack-path-report 0.1.0
输入                              已匹配 CapabilityAttackGraph（fail-closed）
绑定                              manifest_schema_version + manifest_sha256
                                  + canonical_attack_graph_sha256
                                  + pattern_library_version
确定性                            entries 按 path_id 排序唯一；同一图两次构建
                                  输出 byte-identical JSON
边界（固定）                      report_only=true; blocks=false; 全部
                                  authority=false; runtime_verified=false;
                                  exploitability_claimed=false; 每条路径
                                  static_declared_path / not_proven 字面量
限制块                            固定披露六条：非 Finding、无运行时执行、
                                  delegation 不证明提权、
                                  production/dependency 模式暂零匹配、
                                  无任何决策权限
值自由                            无 label / manifest refs / asset 摘要 / 摘录
                                  文本；node_ids 为内容寻址
资源上限                          entries ≤ 256（继承图路径上限）
导出                              schemas/attack-graph/attack-path-report.schema.json
测试                              tests/test_attack_graph_p3_ag_04.py（12 项）
```

## Non-goals

- No severity、likelihood、confidence or recommendation rendering;
  Finding association is P3-AG-05。

- No Evidence line-range rendering in this contract; per-path source
  locators remain in the源图 for P3-AG-05/07 to consume。
- No CLI command for the report (separate wiring decision);
  Python API and encoder are the exported surface。
- No runtime reachability or exploitability claim, ever。

## Verification commands

```bash
.venv/bin/python -m pytest tests/test_attack_graph_p3_ag_04.py -q
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
./scripts/check.sh
```

## Next task

```text
P3-AG-05: Semantic / Deterministic Evidence Association (ADR-0101)
```
