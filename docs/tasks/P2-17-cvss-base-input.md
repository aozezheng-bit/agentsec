# P2-17：支持 CVSS Base 输入

- 状态：已完成（源码开发）
- 依赖：P2-16
- 主要产出：CVSS Base Adapter `0.1.0`
- 验收目标：传统漏洞的 CVSS Base 结果可以被 AgentSec 安全复用

## 完成内容

1. 新增独立的 `agentsec.risk.cvss` 模块。
2. 支持 CVSS v3.1 和 CVSS v4.0 Base Vector 的严格解析。
3. 支持 Python Mapping、`CvssBaseInput` 和 JSON 对象输入。
4. CVSS v3.1 支持本地 Base Score 计算，并校验外部输入的 Score/Severity。
5. CVSS v4.0 校验 Base Vector、Score 范围和 Severity 一致性，并显式标记
   `score_verification=provided`。
6. 输出独立的 `CvssBaseAssessment`，不改变 AgentSec NIST RiskAssessment、
   Capability Risk Model、Evidence Confidence 或 Hard Gate。
7. 增加稳定错误码、输入边界、JSON 输出和安全性测试。
8. 增加 ADR-0040，明确 CVSS 与 AgentSec Base Score 不平均、不互相覆盖。

## 文件

```text
src/agentsec/risk/cvss.py
tests/test_cvss_adapter.py
docs/cvss-adapter.md
docs/decisions/0040-cvss-base-input-adapter.md
```

## 未包含内容

- 将 CVSS 附加到现有 Domain Finding 的持久化 Schema；
- Temporal、Environmental、Threat、Supplemental 指标；
- CVSS v4.0 本地公式计算；
- 运行时可利用性验证、Tool/OAuth/Permission 验证；
- `--fail-on`、CI Blocking、生产 Hard Gate；
- LLM 语义分析或自动规则发布。
