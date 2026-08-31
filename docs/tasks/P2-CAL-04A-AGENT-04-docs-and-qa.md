# Agent 4 工作文档：Documentation, Integration and QA

## 1. 任务身份

```text
Task ID: P2-CAL-04A-AGENT-04
工作目录：/Users/zaz/Desktop/大安全/ice/AgentSec
任务：整合文档、Reviewer 流程、验收记录和最终质量门禁
```

本任务必须在 Agent 1、Agent 2、Agent 3 完成后执行。

## 2. 必须阅读

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/AGENTS.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/scope.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/calibration-adjudication-report.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/decisions/0037-independent-adjudication-and-gate-candidates.md
```

## 3. 写入范围

允许修改：

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/calibration-adjudication-reviewer-pack.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/phase2-scope.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/phase2-integration-plan.md
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/capability-calibration-hard-gate-enforcement-plan.md
/Users/zaz/Desktop/大安全/ice/AgentSec/calibration/README.md
/Users/zaz/Desktop/大安全/ice/AgentSec/schemas/README.md
/Users/zaz/Desktop/大安全/ice/AgentSec/README.md
/Users/zaz/Desktop/大安全/ice/AgentSec/CHANGELOG.md
/Users/zaz/Desktop/大安全/ice/AgentSec/tests/test_phase2_calibration_docs.py
```

不要修改：

```text
src/agentsec/calibration/
src/agentsec/capability_rules/
P2-15A 或 P2-15B 代码
Reviewer Labels 内容
Adjudication Labels 内容
```

## 4. 文档必须说明

新增或更新文档中必须明确：

```text
P2-CAL-04A 只准备案例和 Reviewer Pack
真实 Reviewer 必须由人工招募
Seed Labels 不能作为生产评审结果
Reviewer A/B 必须盲评
P2-CAL-04A 不产生 Hard Gate 资格结论
每个 Gate 至少 20 Positive + 20 Negative/Near-miss
当前没有启用 hard_gate=true
当前没有启用 CI Blocking
当前没有启用 --fail-on
```

## 5. 需要新增的文档

建议新增：

```text
/Users/zaz/Desktop/大安全/ice/AgentSec/docs/calibration-adjudication-reviewer-pack.md
```

内容至少包括：

1. Reviewer 招募要求；
2. Reviewer A/B 独立评审流程；
3. Ground Truth 隔离策略；
4. Label 生命周期：pending → reviewed → adjudicated；
5. 分歧处理流程；
6. FP/FN 分类说明；
7. Case 复用和 Gate 统计规则；
8. 人工评审结束后的 CLI 使用方式；
9. P2-15A 前置条件；
10. 安全边界。

## 6. 质量门禁

必须运行：

```bash
cd /Users/zaz/Desktop/大安全/ice/AgentSec
/Users/zaz/Desktop/大安全/ice/AgentSec/.venv/bin/ruff check .
/Users/zaz/Desktop/大安全/ice/AgentSec/.venv/bin/ruff format --check .
/Users/zaz/Desktop/大安全/ice/AgentSec/.venv/bin/mypy src tests
/Users/zaz/Desktop/大安全/ice/AgentSec/.venv/bin/pytest
/Users/zaz/Desktop/大安全/ice/AgentSec/scripts/check.sh
```

如果某个命令失败：

- 不得忽略失败；
- 必须记录错误；
- 必须判断是否由本任务引入；
- 必须修复或明确阻塞原因。

## 7. 文档测试

新增测试至少验证：

```text
关键文档存在
P2-CAL-04A Task ID 存在
三个 Gate ID 存在
20/20 样本要求存在
Seed Label 限制存在
report_only 存在
hard_gate=true 未被启用的说明存在
```

## 8. 完成报告

必须输出：

```text
文档变更清单
Reviewer Pack 使用说明
Coverage CLI 使用说明
测试命令和结果
当前样本统计
当前人工工作缺口
P2-15A 是否仍被阻塞
```

必须明确：

```text
P2-CAL-04A 完成不等于真实 Reviewer 评审完成
P2-CAL-04A 完成不等于 Hard Gate 通过
```
