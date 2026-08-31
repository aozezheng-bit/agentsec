# P2-24：评分回放测试（Agentic Risk Track）

- 状态：完成
- 日期：2026-08-25
- 依赖：P2-18～P2-23

> 说明：仓库历史中已有一个 P2-24 CVSS Report-only Hard Gate。本任务是原始
> Agentic Risk 评分路线中的完整评分回放，使用独立的
> `SCORING_REPLAY_MODEL_VERSION=0.1.0`。

## 目标

验证同一 Before/After Manifest、评分上下文、CVSS 输入、Gate Evidence 和模型版本，
能够产生完全一致的完整评分结果和组件指纹。

## 产出

```text
src/agentsec/risk/scoring_replay.py
src/agentsec/risk/__init__.py
src/agentsec/versioning.py
scripts/run-scoring-replay.py
testdata/scoring-replay/expected.json
testdata/scoring-replay/README.md
tests/test_scoring_replay.py
docs/decisions/0054-agentic-scoring-replay.md
```

## 回放场景

| Case | 目的 |
|---|---|
| `safe-no-change` | 无 Capability Diff 的固定评分链路 |
| `risky-default` | 默认未知治理上下文下的危险漂移 |
| `risky-reviewed` | 显式评审上下文产生的有限降分 |
| `remediation-drift` | 风险能力移除后的变化评分 |
| `incomplete-coverage` | Coverage 不完整的保守结果 |
| `cvss-high-water` | CVSS Base 独立高水位 |
| `critical-gate-floor` | Critical Floor 不可稀释 |

## 使用

重新生成冻结结果：

```bash
PYTHONPATH=src .venv/bin/python scripts/run-scoring-replay.py \
  --output testdata/scoring-replay/expected.json
```

只验证、不写入：

```bash
PYTHONPATH=src .venv/bin/python scripts/run-scoring-replay.py --check
```

## 验收标准

- [x] P2-18～P2-23 按固定顺序执行；
- [x] 每个阶段都有 canonical SHA-256；
- [x] 完整独立版本向量可见；
- [x] 单 Case 有 `replay_sha256`；
- [x] Suite 有 `suite_sha256`；
- [x] 七个边界场景已冻结；
- [x] 相同输入逐字节相同；
- [x] Context 变化只影响下游 Component Hash；
- [x] 重复 Case ID 和 Context 不一致被拒绝；
- [x] 冻结产物被篡改时 `--check` 失败；
- [x] 输出不包含原始 Source Value 或 Secret；
- [x] 不修改模型公式、Hard Gate 或 CI 行为。

## 未包含内容

```text
P2-25 SARIF Reporter
P2-26 --fail-on
P2-27 Organization Policy
P2-28 Waiver Enforcement
真实项目 Pilot Calibration
```
