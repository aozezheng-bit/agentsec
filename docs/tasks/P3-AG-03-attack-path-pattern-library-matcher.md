# P3-AG-03: Attack Path Pattern Library / Matcher

- Status: Complete
- Date: 2026-08-31
- Depends on: P3-AG-01（Schema）、P3-AG-02（Graph Builder）——已完成
- Mode: report-only; static declared paths only; no runtime verification
- ADR: `docs/decisions/0099-attack-path-pattern-library-matcher.md`

## Objective

Deliver the reviewed finite Attack Path pattern vocabulary and the
deterministic static matcher that turns a `CapabilityAttackGraph` into
matched `AttackGraphPath` entries. At least five families from the
2026-08-31 roadmap erratum must be covered, every path must carry the
unverified boundary marks, and matching must be reproducible and
value-free.

## Deliverables

- [x] `AttackPathPatternSpec` / `AttackPathStepSpec` strict contracts with
      sorted-unique kind sets and bounded steps
      (`agentsec/attack_graph/patterns.py`).
- [x] Reviewed builtin library of seven patterns
      (`ATTACK_PATH_PATTERN_LIBRARY_VERSION 0.1.0`) covering
      `secret-exfiltration`, `injection-tool-execution`,
      `memory-poisoning`, `delegation-escalation`, `mcp-external-egress`,
      `mcp-production-write`, `tool-dependency-install`.
- [x] Preconditions bound to the start node (e.g. exfiltration requires a
      start-node `reads_secret` outgoing edge).
- [x] `AttackPathMatcher` with deterministic pattern-ID → node-order →
      edge-ID DFS, content-addressed path IDs, and fixed boundary marks on
      every path.
- [x] Fail-closed bounds: per-pattern 64 (`ATTACK_PATH_MAX_MATCHES_PER_
      PATTERN`) and graph-level 256 raise `AttackPathMatchError`.
- [x] `validate_pattern_library` for injected custom libraries (tuple,
      spec-only, sorted unique pattern IDs).
- [x] `match_into_graph()` returning a fully re-validated report-only
      graph with paths attached.
- [x] Provenance registration and public API export.
- [x] 15 regression tests covering the library, matcher determinism,
      bounds, authority booleans, and the real Codex pipeline.

## Acceptance record

```text
模式库                          7 个内置模式（覆盖 17.4 五类 + 可选第六类 + egress 变体）
确定性                          pattern_id → 起始节点序 → edge_id 固定 DFS 顺序
路径标识                        attack-path-sha256 内容寻址并在测试中复算
边界标记                        path_kind=static_declared_path; runtime_verified
                                 =false; reachability=not_proven; exploitability
                                 =not_proven（全部固定字面量，不可篡改）
资源边界                        单模式 ≤64 / 全图 ≤256，超限 AttackPathMatchError
真实管线                        delegation 1 / injection 4 / memory-poisoning 2 /
                                secret-exfiltration 1（Codex fixture，两次运行一致）
词汇边界（已披露）              mcp-production-write 与 tool-dependency-install
                                依赖 writes_to / installs 边，当前 builder 不产，
                                匹配数为 0；词汇与匹配器已就绪
权限                            report_only=true; blocks=false; 全部 authority=false
```

## Non-goals

- No attack-path Text/JSON report (P3-AG-04).
- No semantic/deterministic evidence association (P3-AG-05).
- No Demo or calibration (P3-AG-06/07).
- No runtime reachability verification or exploitability proof, ever.
- No LLM-generated patterns; the library is human-reviewed only.

## Verification commands

```bash
.venv/bin/python -m pytest tests/test_attack_graph_p3_ag_03.py -q
.venv/bin/python -m pytest tests/test_attack_graph_p3_ag_01.py tests/test_attack_graph_p3_ag_02.py tests/test_attack_graph_p3_ag_03.py -q
./scripts/check.sh
```

## Next task

```text
P3-AG-04: Attack Path Report (ADR-0101)
```
