# P2-15A-PILOT-01：Joint Expert Review Evidence Formalization + Pilot Subset Import

- Task ID: `P2-15A-PILOT-01`
- Status: Complete for source development
- Completion date: 2026-08-24
- Enforcement mode: `report_only`
- CI blocking: disabled
- P2-15A: remains blocked pending formal independent human review

## 1. 任务目标

把两位专家共同完成的 50 条 Pilot 评审结论，从普通 Pilot 标签文件正式转换为
**Joint Expert Review Evidence**，同时保证它不会被误判为
**Reviewer A/B Independent Evidence**。

本任务是工程形式化，不执行评审、不生成标签、不改变任何规则、评分、
Hard Gate 或 P2-15A/P2-15B 代码。

## 2. 关键区分

```text
Joint Expert Review Evidence（本任务产物）
  = 两位专家共同评审得出的单一共识标签集
  ≠ Reviewer A/B Independent Evidence（ADR-0037/0038 要求的独立盲评）
```

因此该证据：

```text
不能计算 Reviewer A/B Agreement 或 Cohen's Kappa
不能作为正式 P2-CAL-04 Human Evidence 导入
不能用于 P2-15A Hard Gate 资格结论
只能作为 Pilot / Shadow 证据，用于流程验证和规则可理解性校准
```

## 3. 实现内容

### 3.1 Joint Expert Review 元数据

导入输入必须在 Pilot 标签模板之上携带 `joint_panel` 元数据块，缺失或
字段非法即拒绝导入：

```json
{
  "joint_panel": {
    "evidence_mode": "joint_expert_review",
    "review_panel_id": "expert-panel-001",
    "reviewer_count": 2,
    "independent_initial_labels": false,
    "adjudication_required": false,
    "qualification": "pilot_only"
  }
}
```

校验规则（`src/agentsec/calibration/pilot_review.py`）：

```text
evidence_mode 必须等于 joint_expert_review
review_panel_id 必须匹配 ^[a-z0-9][a-z0-9-]{2,62}$
reviewer_count 必须为 2～16 的整数（拒绝 bool）
independent_initial_labels 必须为 false
adjudication_required 必须为 false
qualification 必须为 pilot_only
```

### 3.2 Pilot Subset Import

新增独立导入操作，不复用正式 431 条 Pack 的 importer：

```bash
PYTHONPATH=src .venv/bin/python scripts/pilot-review.py \
  --operation import-joint-panel \
  --input calibration/pilot-review-100/joint-panel-pilot-input.json \
  --output calibration/pilot-review-100/joint-expert-evidence.json
```

产物格式：`agentsec-joint-expert-review-evidence`，Schema `0.1.0`，包含：

```text
evidence_id：内容寻址 SHA-256（joint-evidence-sha256:...）
joint_panel：联合评审元数据
question_set_reviewer_id：所答问题集归属（reviewer-a）
pack_id / corpus_binding_hash / pilot_selection_id：来源绑定
reviewed_count 与完整评审行（保留全部不可变绑定字段）
boundary：formal_human_evidence=false、p2_cal_04_human_evidence=false、
  reviewer_independence=false、reviewer_agreement_computable=false、
  hard_gate_qualification=false、ci_blocking=false、fail_on=false
```

输出写入与现有 merge/adjudication-template 一致：不存在才创建、
`O_EXCL`、mode 0600、失败即清理。

### 3.3 来源绑定与防篡改

导入复用完整 Pilot 绑定链（`_validate_pilot_labels`，strict 模式）：

```text
Reviewer Pack manifest 文件级 SHA-256
Pilot Selection 绑定（selection_id 内容寻址）
每行不可变字段：corpus_binding_hash、pack_id、question_set_sha256、
  review_case_fingerprint、source_sha256、review_case_id、review_id、rule_id
```

Case、Corpus 或 Reviewer Pack 任一发生变化，导入即失败关闭。

## 4. 50 条真实结论的转换记录

转换前：50 条联合专家结论存放在
`calibration/pilot-review-100/reviewer-a-labels.template.json` 中并标记为
`status=reviewed`，存在被误判为 Reviewer A 独立证据的风险。

转换后：

```text
calibration/pilot-review-100/joint-panel-pilot-input.json
  带 joint_panel 元数据的形式化输入（审计留痕）
calibration/pilot-review-100/joint-expert-evidence.json
  正式 Joint Expert Review Evidence（50 条，内容寻址）
calibration/pilot-review-100/reviewer-a-labels.template.json
  50 行已复位为 pending，恢复为干净的盲评模板
```

证据统计：

```text
reviewed_count: 50
规则分布：CAP-CHAIN-001 ×44、CAP-APPROVAL-001 ×2、
  CAP-AUTONETWORK-001 ×2、CAP-AUTOPROD-001 ×2
结论分布：match 25 / no_match 21 / uncertain 4
Evidence ID:
  joint-evidence-sha256:7afbca43f6d6b2c43fad9992db68fbc304711a56e5d0e886ea8cc8acc70457d1
```

## 5. 明确边界

```text
本任务不执行评审、不生成或修改任何人类标签内容
Joint Evidence 不计入 P2-15A 的 20/20 评审样本资格
不计算 Reviewer Agreement / Kappa
不启用 hard_gate=true、CI Blocking 或 --fail-on
不修改 Capability Rule Pack、Risk Model 或任何评分语义
正式资格路径仍是 ADR-0037/0038 的 Reviewer A/B 独立盲评 + Adjudication
```

## 6. 验证

```text
tests/test_pilot_joint_panel_import.py：18 个测试
  happy path、checked-in 证据可复现回归、缺失/非法 joint_panel、
  篡改 corpus 绑定、篡改行不可变字段、无 reviewed 行、
  输出已存在、CLI 端到端、CLI 参数缺失
tests/test_pilot_review_cli.py / test_pilot_review_selection.py：回归通过

独立校验（不读取 Ground Truth）：
PYTHONPATH=src .venv/bin/python scripts/pilot-review.py \\
  --operation validate-joint-panel \\
  --input calibration/pilot-review-100/joint-expert-evidence.json
```

`validate-joint-panel` 会重新检查 evidence ID 内容哈希、Pack/Corpus/Selection
绑定、Pilot Selection 子集边界、行顺序、行不可变字段、Evidence Path、行数和
全部 pilot-only boundary。它不生成 P2-CAL-04 统计，也不改变任何 Gate 或 CI
状态。

## 7. 后续工作

```text
Joint Evidence 用于修复规则/文档/证据问题（Pilot 用途）
正式 P2-15A 仍需：招募两名独立 Reviewer 完成 431 题盲评
→ Adjudicator 裁决 → P2-CAL-04 human mode → 再评估 Gate 资格
```
