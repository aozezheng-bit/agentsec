# Agent 1 工作文档：Calibration Corpus Expansion

## 1. 任务身份

```text
Task ID: P2-CAL-04A-AGENT-01
工作目录：/Users/zaz/Desktop/大安全/ice/AgentSec
任务：扩充 Calibration Corpus 和 Gate Coverage Matrix
```

只处理 Calibration Corpus，不实现 Reviewer Pack、Coverage CLI 或文档整合。

## 2. 必须阅读

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/AGENTS.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/scope.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/calibration-adjudication-report.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/capability-calibration-hard-gate-enforcement-plan.md
```

## 3. 写入范围

允许修改：

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/calibration/cases/
/Users/zaz/Desktop/大安全/ice/AgentSec/calibration/fixtures/
/Users/zaz/Desktop/大安全/ice/AgentSec/calibration/corpus.json
/Users/zaz/Desktop/大安全/ice/AgentSec/calibration/gate-coverage-matrix.json
/Users/zaz/Desktop/大安全/ice/AgentSec/tests/test_calibration_corpus_expansion.py
```

不要修改：

```text
src/agentsec/calibration/
src/agentsec/capability_rules/
scripts/
calibration/confidence-reviews.json
calibration/adjudication-reviews.json
P2-15A 或 P2-15B 代码
```

## 4. 工作目标

为三个候选 Gate 生成安全、合成、不可执行的 Case：

```text
HG-CAPCHAIN-001：Positive >= 20，Negative/Near-miss >= 20
HG-PRODAUTO-001：Positive >= 20，Negative/Near-miss >= 20
HG-EXTERNALPROD-001：Positive >= 20，Negative/Near-miss >= 20
```

建议每个 Gate 生成 25～30 个 Positive 和 25～30 个
Negative/Near-miss，防止人工评审淘汰样本后不足。

## 5. Case 要求

### Positive

必须具备清晰的确定性 Facts 和 Evidence：

- `HG-CAPCHAIN-001`：execute、secret_access、external network；
- `HG-PRODAUTO-001`：production authority、没有 effective prompt/deny；
- `HG-EXTERNALPROD-001`：privileged external identity、production authority。

### Negative / Near-miss

每个 Near-miss 应尽量只缺少一个关键条件，例如：

```text
缺少 execute
缺少 secret_access
权限 target 不同
权限被 deny
存在有效 prompt
身份不是 privileged
权限不是 production
只有 Unknown，没有确定性证据
```

### 语言与格式

新增案例至少覆盖：

```text
中文
英文
中英双语
Markdown
JSON
YAML
TOML
Manifest Snapshot 或 Fact Bundle
```

## 6. 安全要求

- 不得包含真实 Secret、Token、Credential、Internal Host 或个人数据；
- 只使用 `.invalid`、`.example` 和占位符；
- 不得包含可执行 Command、Hook、Skill、Plugin 或 MCP 启动内容；
- 不执行 Fixture；
- 不连接网络；
- 所有 Evidence 必须是 value-free location；
- 不修改已有 Seed Review Labels；
- 不把任何新标签标记为 `reviewed` 或 `adjudicated`。

## 7. Coverage Matrix

新增：

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/calibration/gate-coverage-matrix.json
```

每行至少包含：

```text
gate_id
case_id
case_kind
expected_gate_condition
expected_rule_ids
language
format
is_positive
is_negative_or_near_miss
has_unknown
coverage
```

矩阵中不得写入真实敏感值。

## 8. 验收命令

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec
.venv/bin/python -c "from pathlib import Path; from agentsec.calibration import load_calibration_corpus; print(load_calibration_corpus(Path('calibration')).summary.total_cases)"
.venv/bin/pytest -q tests/test_calibration.py tests/test_calibration_runner.py tests/test_calibration_corpus_expansion.py
.venv/bin/ruff check .
.venv/bin/mypy src tests
```

## 9. 完成报告

必须报告：

```text
新增 Case 数量
新增 Fixture 数量
每个 Gate 的 Positive 数量
每个 Gate 的 Negative/Near-miss 数量
语言和格式分布
Unknown/Incomplete 数量
Corpus Loader 结果
测试结果
未完成的人工工作
```

不要声称这些案例已经经过人工评审。

## 10. 修复后附加验收要求

2026-08-21 复核后增加以下要求：

- 样本门槛按唯一 `semantic_fingerprint` 统计，不能只按 Case ID；
- Relevant Unknown 和 Incomplete Case 不计入 Eligible Negative；
- Matrix 必须包含 `is_eligible_negative`、`semantic_fingerprint` 和实际
  `source_asset_path`；
- 每个声明的 Markdown/JSON/YAML/TOML/Manifest 格式必须存在对应的安全、
  不可执行 Source View；
- Machine-generated Case 必须标记 `machine-generated-draft`，Review 状态保持
  `seeded`；
- Expanded Corpus 使用独立 Corpus ID 和 Labels Version，避免覆盖原 61-Case
  Seed Corpus 的身份语义。
