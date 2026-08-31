# P2-18 CVSS Base 与 Finding / Assessment Report 集成

- Task: `P2-18`
- Status: Complete for source development
- Domain Schema: `0.4.0`
- Assessment Output: `0.3.0`
- Depends on: `P2-17`
- ADR: `docs/decisions/0041-cvss-finding-assessment-integration.md`

## 1. Purpose

P2-17 产生独立的 `CvssBaseAssessment`。P2-18 将它安全地附加到 Domain
`Finding`，并让 Text/JSON Assessment Report 同时展示两种风险视图：

```text
AgentSec Finding score / Severity
        +
Finding.cvss.base_score / base_severity / vector
```

两者来源和含义不同，不能互相覆盖，也不能直接平均。

## 2. Domain contract

`Finding` 新增一个可选字段：

```python
cvss: CvssBase | None = None
```

`CvssBase` 是报告边界上的严格、不可变、Schema-backed value object，包含：

```text
adapter_version
version
vector
base_score
base_severity
metrics
score_verification
mapping_basis
```

没有 CVSS 的既有 Finding 仍然合法；有 CVSS 的 Finding 必须满足：

- CVSS version 与 Vector prefix 一致；
- Vector 中的 Base Metrics 与 version 一致；
- Metric 名称和值属于对应 CVSS version；
- Base Score 是有限的 0.0～10.0 数值且最多一位小数；
- Base Severity 与 CVSS Base Score 区间一致；
- v3.1 使用 `score_verification=calculated`；
- v4.0 使用 `score_verification=provided`；
- `mapping_basis` 非空。

注意：`Finding.severity` 仍然是 AgentSec Finding Severity，
`Finding.cvss.base_severity` 是 CVSS Base Severity。两者可以不同。

## 3. Adapter seam

```python
from agentsec.risk import CvssBaseAdapter

cvss = CvssBaseAdapter().adapt(
    {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
)

finding_with_cvss = cvss.attach_to_finding(finding)
```

`attach_to_finding()` 返回 Finding 的不可变副本，不修改原 Finding，也不改写：

```text
Finding.score
Finding.severity
Finding.likelihood
Finding.impact
Finding.confidence
Finding.hard_gate
```

## 4. Assessment Text Report

当 Finding 有 CVSS 时，Text Report 在 AgentSec 风险字段之后显示：

```text
CVSS Base          9.8 (CRITICAL)
CVSS Vector        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS Verification  calculated
```

无 CVSS 的 Finding 不显示这些额外行。

Vector 仍经过现有 Text Reporter 的安全清洗和长度限制。

## 5. Assessment JSON Report

JSON Report 在每个 Finding 中增加可选的 `cvss` 对象：

```json
{
  "score": 8.0,
  "severity": "high",
  "cvss": {
    "adapter_version": "0.1.0",
    "version": "3.1",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "base_score": 9.8,
    "base_severity": "critical",
    "score_verification": "calculated",
    "metrics": {
      "AV": "N",
      "AC": "L",
      "PR": "N",
      "UI": "N",
      "S": "U",
      "C": "H",
      "I": "H",
      "A": "H"
    },
    "mapping_basis": [
      "FIRST CVSS v3.1 Base Metrics and Base Score formula",
      "FIRST CVSS v3.1 qualitative severity rating scale",
      "AgentSec CVSS Base input adapter contract 0.1.0"
    ]
  }
}
```

JSON 仍保持：

```text
format = agentsec-assessment
format_version = 0.3.0
policy.enforcement_mode = report_only
policy.ci_blocking_enabled = false
policy.global_safety_claimed = false
```

## 6. Versioning decision

由于 `Finding` 的公开 Domain Schema 增加了新的嵌套字段，本次升级：

```text
DOMAIN_SCHEMA_VERSION:    0.3.0 → 0.4.0
ASSESSMENT_OUTPUT_VERSION: 0.2.0 → 0.3.0
```

这不是 Risk Model 变化：

```text
RISK_MODEL_VERSION:             0.4.0（不变）
CAPABILITY_RISK_MODEL_VERSION:  0.1.0（不变）
```

## 7. Non-goals

P2-18 不实现：

- CVSS 与漏洞 ID / CVE 数据源的自动关联；
- Temporal、Environmental、Threat、Supplemental 指标；
- CVSS v4.0 本地 Base Score 重新计算；
- CVSS 与 AgentSec 风险分数平均；
- CVSS 驱动的 Hard Gate 或 CI Blocking；
- 运行时漏洞验证或可利用性证明；
- LLM 语义漏洞判定。


## 8. Follow-up after P2-19

P2-19 adds an independent optional `Finding.vulnerability` reference for
internal vulnerability IDs, CVE IDs, and CWE IDs. It advances the current
Domain Schema to `0.5.0` and Assessment Output to `0.4.0`; the P2-18 contract
above remains the historical `0.4.0` / `0.3.0` snapshot.
