# P2-24：CVSS Report-only Hard Gate

- 状态：已完成（源码开发）
- 日期：2026-08-24
- 依赖：`P2-17`、`P2-18`、`P2-20`、`P2-21`、`P2-22`、`P2-23`
- CVSS Hard Gate 版本：`0.1.0`
- ADR：`docs/decisions/0047-cvss-report-only-hard-gate.md`

## 1. 目标

P2-24 在已有 CVSS Finding 集成基础上增加一个**确定性、报告专用、不可阻断 CI** 的 CVSS Hard Gate 视图。

它回答的是：

> 当前 Finding 附带的有效 CVSS Score 是否达到 High 或 Critical 的报告阈值？

它不回答：

> 这个 Agent 是否已经在运行时被证明可利用？

## 2. 阈值

P2-24 使用 CVSS 有效分数 `effective_score`，而不是 AgentSec Finding 的 `score`：

| CVSS 有效分数 | Gate | 阈值 | 结果 |
|---:|---|---:|---|
| `0.0`～`< 7.0` | 不匹配 | - | 只保留评估结果 |
| `7.0`～`< 9.0` | `HG-CVSS-001` | `7.0` | High report-only gate |
| `>= 9.0` | `HG-CVSS-002` | `9.0` | Critical report-only gate |

边界使用包含关系：

```text
score >= 7.0  -> High
score >= 9.0  -> Critical
```

如果有效分数达到 Critical，只报告最强的 Critical Gate，不重复生成 High Gate。

## 3. 为什么使用 effective_score

P2-21 已经区分：

```text
base_score
与
extended effective_score
```

因此 P2-24 采用当前有效视图：

```text
CVSS v3.1 Base only             -> Base Score
CVSS v3.1 Temporal/Environmental -> effective Score
CVSS v4.0 Threat                 -> effective Score
CVSS v4.0 Environmental          -> effective Score
CVSS v4.0 Supplemental only      -> Base Score
```

例如：

```text
Base 9.3 + Threat E:P = effective 8.9
```

该 Finding 会匹配 High Gate，但不会匹配 Critical Gate。

## 4. 与 AgentSec 风险的关系

CVSS Gate 使用独立字段：

```python
finding.cvss_hard_gate
```

它不会覆盖或改变：

```text
Finding.score
Finding.severity
Finding.likelihood
Finding.impact
Finding.confidence
Finding.hard_gate
```

这里的 `Finding.hard_gate` 仍然表示已有通用 AgentSec Hard Gate 条件是否匹配；`cvss_hard_gate` 表示 CVSS 专属 Gate 的评估结果。两个维度不应混为一谈。

## 5. Domain contract

新增：

```text
CvssHardGateMatch
CvssHardGateAssessment
Finding.cvss_hard_gate
```

### `CvssHardGateAssessment`

```text
gate_version
finding_id
mode = report_only
score
severity
score_type
match
mapping_basis
```

### `CvssHardGateMatch`

```text
gate_id
floor
threshold
score
score_type
rationale
```

当 Finding 没有 CVSS 时，不附加 CVSS Gate 评估；当 Finding 有 CVSS 时，即使没有达到 High，也会保留一条 `match = null` 的评估结果，使机器消费者能够区分：

```text
没有 CVSS
与
有 CVSS 但未达到 Gate 阈值
```

## 6. Report behavior

### Text

匹配时：

```text
CVSS Hard Gate  MATCHED HG-CVSS-002 (report-only; no CI block)
CVSS Gate Score 9.8 (CRITICAL)
```

未匹配时：

```text
CVSS Hard Gate  evaluated; not matched (report-only)
```

### JSON

```json
{
  "cvss_hard_gate": {
    "gate_version": "0.1.0",
    "finding_id": "finding-sha256:<64 hex>",
    "mode": "report_only",
    "score": 9.8,
    "severity": "critical",
    "score_type": "base",
    "match": {
      "gate_id": "HG-CVSS-002",
      "floor": "critical",
      "threshold": 9.0,
      "score": 9.8,
      "score_type": "base",
      "rationale": [
        "Effective CVSS score met the Critical report-only threshold.",
        "This match is evidence only and does not block CI."
      ]
    }
  }
}
```

Assessment Summary 新增：

```text
cvss_hard_gate_matches
```

该字段只统计真正匹配 High/Critical 阈值的 Finding，不统计 `match = null` 的 CVSS 评估。

## 7. CLI behavior

`agentsec scan` 在显式漏洞输入或本地漏洞源完成 CVSS enrichment 后自动运行 CVSS Gate：

```bash
agentsec scan ./agent \
  --vulnerability-source ./vulnerability-catalog.json \
  --format json
```

执行顺序：

```text
1. 执行静态扫描；
2. 应用 --vulnerability-input；
3. 应用 --vulnerability-source；
4. 计算 CVSS report-only Gate；
5. 生成 Text/JSON 报告；
6. 仍按原有 Coverage 规则返回 CLI 退出码。
```

即使 CVSS 达到 Critical：

```text
报告会展示匹配结果
CI Blocking 仍为 false
exit code 仍不会因为 CVSS Gate 变成风险阻断码
```

## 8. 安全边界

```text
不联网
不执行 Agent
不调用 LLM
不验证运行时可利用性
不证明漏洞真实存在
不修改 AgentSec 风险分数
不修改通用 hard_gate
不启用 --fail-on
不启用 CVSS CI Blocking
```

所有 Gate rationale 都是固定策略文本，不复制源文件摘录、Secret 或外部数据源的描述内容。

## 9. 版本变化

P2-24 新增公开 Finding 字段和 Assessment Summary 字段：

```text
DOMAIN_SCHEMA_VERSION:     0.7.0 -> 0.8.0
ASSESSMENT_OUTPUT_VERSION: 0.6.0 -> 0.7.0
CVSS_HARD_GATE_VERSION:    0.1.0
```

新增 Schema：

```text
schemas/domain/cvss-hard-gate-match.schema.json
schemas/domain/cvss-hard-gate-assessment.schema.json
```

## 10. 依据与参考

阈值依据 CVSS 定性严重性区间，并明确标注为 AgentSec 的 report-only 策略适配，不将标准阈值直接等同于组织阻断策略：

- FIRST CVSS v4.0 Specification：<https://www.first.org/cvss/v4.0/specification-document>
- FIRST CVSS v3.1 Specification：<https://www.first.org/cvss/v3.1/specification-document>
- FIPS 199 high-water-mark principle：<https://csrc.nist.gov/pubs/fips/199/final>

## 11. 后续未实现

```text
CVSS 驱动 Hard Gate enforcement
CVSS 驱动 CI Blocking
--fail-on cvss
生产策略配置和豁免
运行时漏洞验证
实际可利用性证明
```
