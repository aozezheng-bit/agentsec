# P2-CAL-04A-AGENT-03 Completion Report

## 1. 任务结果

```text
Task ID: P2-CAL-04A-AGENT-03
修复 Task ID: P2-CAL-04A-AGENT-03-FIX
状态：完成，等待真实独立 Reviewer 替换 Seed Labels
完成日期：2026-08-21
执行模式：report_only
CI Blocking：false
```

已完成 Gate Calibration Coverage Check CLI，并完成针对不可信 Matrix、
Corpus 绑定、唯一语义样本计数和路径安全的加固。该工具只检查三个已批准
候选 Gate 的样本覆盖情况，不修改 Rule、Risk Model、Reviewer Label 或 Hard
Gate 配置。

## 2. CLI 文件与用法

CLI 文件：

```text
scripts/check-gate-calibration-coverage.py
```

推荐命令：

```bash
.venv/bin/python scripts/check-gate-calibration-coverage.py \
  --corpus calibration \
  --matrix calibration/gate-coverage-matrix.json \
  --format json
```

支持的参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--corpus PATH` | `calibration` | Calibration Corpus 根目录 |
| `--matrix PATH` | `<corpus>/gate-coverage-matrix.json` | Gate Coverage Matrix；必须位于 Corpus 内 |
| `--format text\|json` | `text` | 输出 Text 或版本化 JSON Report |

## 3. 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 所有已批准候选 Gate 均达到最低唯一有效样本要求 |
| `2` | Corpus/Matrix 不完整，或候选 Gate 样本不足 |
| `4` | 输入格式、Schema、可信绑定或路径安全校验失败 |
| `5` | 未预期执行失败；错误输出不复制不可信输入内容 |

样本不足返回 `2`，非法或被篡改输入返回 `4`。当前 CLI 不实现
`--fail-on`，不会把 Coverage Check 变成 CI 或生产阻断。

## 4. 可信 Gate 定义

CLI 内固定以下三个候选 Gate；Matrix 必须逐字段复现定义，不能注入新 Gate，
也不能降低阈值、修改风险下限或替换组件 Rule：

| Gate ID | Floor | Component Rule IDs | Positive 最低样本 | Negative/Near-miss 最低样本 |
|---|---|---|---:|---:|
| `HG-CAPCHAIN-001` | High | `CAP-CHAIN-001` | 20 | 20 |
| `HG-PRODAUTO-001` | High | `CAP-APPROVAL-001`, `CAP-AUTOPROD-001` | 20 | 20 |
| `HG-EXTERNALPROD-001` | Critical | `CAP-EXTERNALPRIVILEGED-001`, `CAP-PRODADMIN-001`, `CAP-PRODIDENTITY-001`, `CAP-PRODWRITE-001` | 20 | 20 |

这些定义只用于报告样本覆盖，不表示 Gate 已获批准上线或启用。

## 5. 输入与可信绑定加固

### 5.1 Matrix 与 Corpus 绑定

CLI 会验证：

- Matrix Format 和 Schema Version；
- Matrix `corpus_id` 与已加载 Corpus 一致；
- Matrix `capability_rule_pack_version` 与 Corpus 一致；
- 每个 Row 的 Case、语言、格式、Coverage、Unknown、Review Status 与 Corpus
  Ground Truth 一致；
- `scenario_id` 必须由 Case ID 确定性派生；
- 同一 Gate 内 Scenario ID 唯一；
- Row 仅能引用 Case 中真实存在的 Rule Expectations。

### 5.2 唯一语义样本

`semantic_fingerprint` 不被 Matrix 自报值信任。CLI 从经过 Schema 校验的
Case Ground Truth 重新计算 value-free SHA-256 Fingerprint，再验证 Matrix 值。
最终门槛按每个 Gate 内唯一、Coverage 完整且无相关 Unknown 的 Fingerprint
计数，而不是按 Matrix Row 数或 Case ID 数计数。

同一个 Case 可以在其 Ground Truth 同时包含多个候选 Gate 的 Rule
Expectations 时跨 Gate 复用；每个 Gate 仍独立去重和计数。一个 Case 不能在
同一个 Gate 内重复计数。

### 5.3 Eligible Negative

`is_eligible_negative` 不能由 Matrix 任意声明。可信计算为：

```text
negative_or_near_miss AND coverage=complete AND has_unknown=false
```

Unknown 或不完整样本仍会出现在报告中，但不会计入满足 Negative/Near-miss
最低门槛的有效样本数。

### 5.4 Source Asset 绑定

`source_asset_path` 必须：

- 位于当前 Case Fixture 目录；
- 文件名与 Row Format 精确匹配：`source.md`、`source.json`、`source.yaml`、
  `source.toml` 或 `source.manifest.json`；
- 是 Corpus Root 内的安全相对路径；
- 路径组件不包含 Symbolic Link；
- 指向实际存在的普通文件。

CLI 只验证路径和存在性，不打开或执行 Source View 内容。

### 5.5 macOS 路径别名

Corpus Root 同时保留 lexical path 和 resolved path：默认 Matrix 从 lexical
Root 构造，最终 containment 使用 resolved Root。这允许 macOS 标准
`/tmp -> /private/tmp`、`/var -> /private/var` 父目录别名，同时继续拒绝
Corpus Root 本身、Matrix 和 Corpus 内部资源使用 Symbolic Link。

## 6. 当前覆盖结果

命令：

```bash
.venv/bin/python scripts/check-gate-calibration-coverage.py \
  --corpus calibration \
  --matrix calibration/gate-coverage-matrix.json \
  --format json
```

结果：`exit 0`、`overall_status=ready`。

| Gate ID | Positive Unique | Eligible Negative/Near-miss Unique | Unknown | 状态 |
|---|---:|---:|---:|---|
| `HG-CAPCHAIN-001` | 25 | 21 | 4 | `ready` |
| `HG-PRODAUTO-001` | 25 | 21 | 4 | `ready` |
| `HG-EXTERNALPROD-001` | 25 | 26 | 4 | `ready` |

当前 Matrix 共 155 Rows；每个 Gate 均覆盖英文、中文、双语，以及
Markdown、JSON、YAML、TOML、Manifest 五种 Source View 格式。

## 7. 测试与验证

定向回归：

```bash
.venv/bin/pytest -q tests/test_calibration_corpus_expansion.py
```

结果：

```text
33 passed
```

回归测试覆盖：

- 恰好达到 20/20 与低于门槛；
- 未批准 Gate、Threshold 和 Component Rule 篡改；
- Corpus ID、Rule Pack 和 Matrix Schema Version 错配；
- Row/Scenario 重复、标签冲突和缺失 Case；
- Semantic Fingerprint 伪造、折叠和重复；
- Eligible Negative 自报值篡改；
- Matrix 越界和 Symbolic Link；
- Source Asset 跨 Case 错配和内部 Symbolic Link；
- Review Status 错配；
- 同一 Case 跨 Gate 合法复用；
- macOS `/tmp` 路径别名；
- 中英文、多格式和当前 Coverage 统计。

完整质量门禁：

```bash
scripts/check.sh
```

结果：

```text
Ruff check：通过
Ruff format --check：489 files already formatted
Mypy strict：Success，195 source files
Pytest：881 passed in 57.14s
```

## 8. 安全边界确认

本任务：

- 没有执行 Case Fixture、Source View、脚本、Hook、Skill 或 MCP Server；
- 没有连接网络；
- 没有读取或输出真实 Secret/Credential；
- 没有修改 Capability Rule Pack；
- 没有修改 Capability Risk Model；
- 没有修改 P2-15A/P2-15B Hard Gate 实现；
- 没有启用 `hard_gate=true`；
- 没有新增 `--fail-on`；
- 没有启用 CI Blocking；
- 没有把 `seeded` Label 伪装成 `reviewed` 或 `adjudicated`。

因此不涉及 Core Schema 或 Risk Model 决策变更，不需要新增 ADR。

## 9. 限制与下一步

`ready` 只说明当前 Seed Corpus 在唯一有效样本数量上达到候选门槛，不代表：

- Seed Labels 已经过真实独立 Reviewer；
- Precision/Recall 已经由生产分布验证；
- Hard Gate 已批准上线；
- 运行时 Tool、OAuth、Permission 或漏洞可利用性已得到证明。

下一步由 Agent 4 执行文档整合和最终 QA；随后仍必须由真实独立 Reviewer
完成 Blind Review 和 Adjudication，并重新运行 P2-CAL-04 与本 Coverage CLI，
再决定是否进入 P2-15A Report-only Hard Gate 评估。
