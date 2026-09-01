# P3-17 人工反馈与标签（FP/FN 闭环）

- Task: P3-17（人工反馈与标签；ADR-0106）
- Date: 2026-08-31
- Mode: report-only；起草机制无需人工，标签确认需要人工
- Status: 机制与 AI 起草草稿已交付；**confirmed/ 反馈集等待人工确认后生成**

## 闭环链路

```text
P3-12/P3-13 冻结场景包（含 P3-11A 金标准继承）
→ build_semantic_feedback_draft(packs, adapter): 一次 Shadow 运行的
   预期 vs 预测差集 → FP/FN 草稿行（status=draft）
→ 起草包（本目录 draft/）+ 中文复核表 REWIEW-WORKSHEET.zh.md
→ 人工逐行确认（confirm/reject）+ 填写 reviewer_id 与独立性声明
→ import-p3-17-feedback.py（fail-closed）→ confirmed/semantic-feedback-set.json
→ evaluate_feedback_resolution(set, packs, adapter): 后续运行中
   每行 resolved / unresolved / unevaluated + resolution_rate
```

## 为什么需要人工（本仓库铁律）

`LLM output is evidence, not an authorization decision`——FP/FN 标签
的质量声明不能由 AI 单方宣布。与 P3-11A 相同，唯一被接受的溯源为
`ai_draft_human_confirmed`（AI 起草 + 人工逐行确认）或
`human_authored`；`ai_assisted` 直接被 `SemanticFeedbackSet` 拒绝。

## 起草包内容（draft/）

- `feedback-draft-submission.template.json`：54 行 false_negative 草稿
  （来源：offline fixture 回放——fixture 输出零判断，因此全部预期判断
  均为漏报候选；确定性、可复现：`scripts/build-p3-17-feedback-pack.py`）
- `REVIEW-WORKSHEET.zh.md`：中文复核表（含 P3-11C Kimi 试路背景：
  45 例金标准上 Precision=0.394/Recall=0.378，FP=57/FN=61）

## 人工确认步骤（推荐：一条命令的交互式评审）

```bash
.venv/bin/python scripts/review-p3-17-feedback.py
```

交互式逐行评审：每行展示案例脱敏文本、预期判断与进度标记；
`c` 确认 / `r` 拒绝（可附备注）/ `s` 统计 / `a` 全确认剩余 / `q`
保存退出；进度自动落盘可断点续评。全部行判定后自动生成
`review-submission.completed.json` 并调用导入器产出确认集（见
`REVIEW-GUIDE.zh.md`，含键位、恢复、边界与常见问题）。

### 手工路径（fallback）

1. 复核表中逐行判断，修改 template JSON 每行 `status` 为
   `confirmed` / `rejected`（可填 `note`）
2. 填写 `reviewer_id` 与 `independence_statement`（≥20 字符）
3. 运行导入脚本生成确认集：

```bash
.venv/bin/python scripts/import-p3-17-feedback.py \
  --submission pilots/semantic-feedback-p3-17/review-submission.completed.json \
  --output pilots/semantic-feedback-p3-17/confirmed
```

导入 fail-closed：未填 reviewer、声明过短、每行未 resolved
（confirmed/rejected 之外的中间态）、未知行、digest 不一致均拒绝。

## 使用闭环（机制演示，测试覆盖）

```python
loop = evaluate_feedback_resolution(feedback_set, packets, adapter)
# FP 行 resolved ⇔ 该判断不再被预测；FN 行 resolved ⇔ 预期判断被检出；
# 调用失败 → unevaluated，evaluation_complete=false
```

## 权限边界

```text
report_only / blocks / calibration_authority /
rule_publication_authority / policy_authority / ci_authority /
gate_authority / runtime_verified          全部 false
```

反馈与解决率均为人工评审证据；不构成校准、规则发布、Policy、CI、
Hard Gate 或运行时权限，也不构成任何离线 fixture 的质量声明。
