# Agent 3 工作文档：Gate Coverage Check CLI

## 1. 任务身份

```text
Task ID: P2-CAL-04A-AGENT-03
工作目录：/Users/zaz/Desktop/大安全/ice/AgentSec
任务：实现 Gate Calibration Coverage Check CLI
```

本任务依赖 Agent 1 生成的 `gate-coverage-matrix.json`。

## 2. 必须阅读

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/AGENTS.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/scope.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/calibration-adjudication-report.md
```

## 3. 写入范围

允许修改：

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/scripts/check-gate-calibration-coverage.py
/Users/zaz/Desktop/大安全/ice/AgentSec/tests/test_calibration_corpus_expansion.py
```

可以在必要时新增只读数据模型，但不要修改已有 P2-CAL-01～04 模型。

不要修改：

```text
src/agentsec/capability_rules/
calibration/cases/
calibration/fixtures/
calibration/confidence-reviews.json
calibration/adjudication-reviews.json
P2-15A 或 P2-15B 代码
```

## 4. CLI 目标

新增：

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/scripts/check-gate-calibration-coverage.py
```

推荐用法：

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec
.venv/bin/python scripts/check-gate-calibration-coverage.py \
  --corpus calibration \
  --matrix calibration/gate-coverage-matrix.json
```

## 5. 输出要求

每个 Gate 至少输出：

```text
gate_id
positive_count
negative_count
near_miss_count
unknown_count
incomplete_count
language_distribution
format_distribution
coverage_status
missing_sample_count
```

示例：

```text
HG-CAPCHAIN-001
  positive: 25
  negative: 12
  near_miss: 13
  status: ready
```

## 6. 退出码

建议：

```text
0 = 所有候选 Gate 达到最低样本要求
2 = Corpus 或 Matrix 不完整
4 = 输入格式、路径或 Schema 非法
5 = 工具执行失败
```

特别要求：

```text
样本不足时必须返回非 0
不能因为当前风险分数高就返回通过
不能因为 Confidence 高就绕过样本门槛
不能启用 CI Blocking
```

## 7. 安全要求

- Matrix 文件按不可信输入处理；
- 路径必须 root containment-safe；
- 拒绝 symlink；
- 不执行 Case Fixture；
- 不连接网络；
- 不读取真实 Secret；
- 不生成或修改 Reviewer Labels；
- 不修改 Rule Pack 或 Risk Model。

## 8. 测试要求

必须测试：

```text
达到 20/20 时退出码为 0
低于 20/20 时退出码非 0
未知 Gate ID 被拒绝
重复 Case ID 被拒绝
Positive 与 Negative 标签冲突时被拒绝
路径越界被拒绝
symlink 被拒绝
中英文和多格式统计正确
```

## 9. 完成报告

必须报告：

```text
CLI 文件
支持的参数
退出码定义
覆盖统计结果
测试命令和结果
没有修改 Rule、Risk Model、Hard Gate 的确认
```
