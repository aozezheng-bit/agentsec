# P2-21：Temporal / Environmental / Threat / Supplemental

- 状态：已完成（源码开发）
- 依赖：P2-20
- CVSS Adapter：`0.3.0`
- Domain Schema：`0.6.0`
- Assessment Output：`0.5.0`

## 完成内容

```text
CVSS v3.1 Temporal Metrics
CVSS v3.1 Environmental Metrics
CVSS v4.0 Threat Metrics
CVSS v4.0 Environmental Metrics
CVSS v4.0 Supplemental Metrics
Base Score 与 effective Score 分离
score_type 和 effective_severity
Text / JSON Report 集成
输入 Base/effective Score 一致性校验
ADR-0044
```

## 重要边界

```text
Supplemental Metrics 当前只保留和展示，不改变数值 Score。
CVE/CWE 数据库自动查询尚未实现。
运行时可利用性验证尚未实现。
CVSS 驱动 Hard Gate 尚未实现。
CVSS 驱动 CI Blocking 尚未实现。
```
