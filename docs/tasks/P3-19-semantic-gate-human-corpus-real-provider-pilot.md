# P3-19：Semantic Gate Human Corpus Expansion / Real Provider Pilot

- **状态**：代码链路完成；真实 Provider 外呼待组织审批与运行
- **日期**：2026-09-01
- **依赖**：P3-05、P3-07、P3-10、P3-11、P3-18
- **权限模式**：Shadow-only / report-only

## 目标

为每一个 Semantic Gate 建立可审计、脱敏、Digest 绑定的人工评测语料，并在明确
opt-in、端点、凭据、预算、数据驻留和保留策略审批后，运行一次 Gate-specific
Real Provider Pilot。Pilot 的输出只能作为质量和语义 Evidence，不能直接进入
Finding、Rule、Policy、CI、Hard Gate、Waiver、Runtime Authority 或 Release。

## 已交付

### P3-19-01：Gate-specific Human Corpus Contract

实现：`src/agentsec/semantic/gate_corpus.py`

- `SemanticGateHumanCase`：Positive、Eligible Negative、Near-miss、Unknown；
- `SemanticGateHumanCorpus`：Gate/Signal 绑定、Case ID 唯一性、Evidence Digest；
- 只接受脱敏、长度受限的 Evidence，拒绝 URL、凭据、Token 和控制字符；
- `SemanticGateCorpusReviewer`：Reviewer ID、独立性声明、审核时间、来源；
- Corpus ID 和 SHA-256 可重算，篡改会被拒绝；
- Corpus 的全部权限字段固定为 report-only / no-authority。

Schema：

- `schemas/semantic-analysis/semantic-gate-human-corpus.schema.json`
- `schemas/semantic-analysis/semantic-gate-review-submission.schema.json`

### P3-19-02：Review / Adjudication Import

支持 `SemanticGateReviewSubmission` 和 `SemanticGateAdjudication`。导入器会：

1. 验证 Reviewer 与 Corpus/Gate 绑定；
2. 要求每位 Reviewer 覆盖全部 Case；
3. 检测 Reviewer 之间的分类分歧；
4. 分歧没有 Adjudication 时 fail-closed；
5. 只写入最终 Gate 类别、Match 预期和 Confidence，不修改 Evidence 文本；
6. 生成新的 Corpus Digest。

AI 只能生成 draft，不能直接产生最终 Corpus。

### P3-19-03：Gate Coverage / Qualification Integration

`SemanticGateInput.HUMAN_CORPUS` 已接入 P3-18 `SemanticGateQualificationRunner`。
当 Candidate 声明该输入时，Runner 检查：

- 至少 20 条 Positive；
- 至少 20 条 Eligible Negative/Near-miss；
- 没有 Unknown 或未裁决 Case；
- Corpus 与 Candidate Gate ID 一致；
- Corpus Case Count 与 Provider Quality Report 一致；
- Corpus Digest 可重算。

不足的证据是 `pending`，完整性或质量矛盾是 `fail`；资格结果仍然只代表
Evidence 资格，不授予任何执行权限。

### P3-19-04/05：Real Provider Pilot

实现：`src/agentsec/semantic/real_provider_pilot.py`

- `SemanticGatePilotConfig`：端点、Provider/Model、Credential 环境变量、案例预算；
- 数据驻留、保留策略、费用、Review Owner 和 Approval ID 审批位；
- `SemanticGatePilotRunner.preflight()`：默认 fail-closed；
- `SemanticGatePilotRunner.run()`：每个 Case 至多一次调用，默认最多 40 个 Case；
- 支持注入 Adapter 的离线测试，不需要网络；
- Real Provider 结果复用现有 Semantic Evaluation Report，不保存原始 Prompt/Response；
- 报告仅记录 Provider/Model、Digest、调用数量、质量指标、错误码和权限边界。

Schema：

- `schemas/semantic-analysis/semantic-gate-pilot-config.schema.json`
- `schemas/semantic-analysis/semantic-gate-pilot-report.schema.json`

## CLI

校验 Corpus：

```bash
PYTHONPATH=src .venv/bin/python scripts/check-semantic-gate-corpus.py \
  --corpus <human-corpus.json> --format text
```

预检或运行 Pilot（默认不会外呼）：

```bash
PYTHONPATH=src .venv/bin/python scripts/run-semantic-gate-pilot.py \
  --corpus <human-corpus.json> \
  --gate-candidate <gate-candidate.json> \
  --provider-id <PROVIDER_ID> \
  --model-id <MODEL_ID> \
  --credential-env <CREDENTIAL_ENV> \
  --format json
```

真实外呼必须显式提供全部参数：

```bash
PYTHONPATH=src .venv/bin/python scripts/run-semantic-gate-pilot.py \
  --corpus <human-corpus.json> \
  --gate-candidate <gate-candidate.json> \
  --provider-id <PROVIDER_ID> \
  --model-id <MODEL_ID> \
  --endpoint https://<approved-host>/<approved-path> \
  --credential-env <CREDENTIAL_ENV> \
  --allow-live \
  --data-residency-approved \
  --retention-policy-approved \
  --cost-approved \
  --review-owner-id <OWNER_ID> \
  --approval-id <APPROVAL_ID> \
  --max-cases 40 --max-calls 40 \
  --format json --output <pilot-report.json>
```

等价 CLI：

```bash
agentsec semantic gate-pilot --corpus <human-corpus.json> ...
```

没有 `--allow-live`、HTTPS Endpoint、Credential 环境变量或组织审批时，命令只
输出 `preflight_blocked`，并且不会访问网络。

## 当前证据限制

- 仓库已有 P3-11C 真实 Provider 基线，但它不是当前 Gate-specific Corpus 的资格结论；
- 真实质量资格仍需使用当前 Candidate、当前 Prompt/Model、当前 Corpus 重新运行；
- AI 起草 + 人工确认不等同于两位独立专家双盲评审；
- `qualified` 也不等于 authorized；
- 本任务不实现运行时漏洞证明、自动规则发布或生产 Hard Gate。

评审导入：

```bash
PYTHONPATH=src .venv/bin/python scripts/import-semantic-gate-review.py \
  --corpus <reviewed-base-corpus.json> \
  --review <reviewer-a.json> \
  --review <reviewer-b.json> \
  --adjudications <adjudications.json> \
  --output <final-human-corpus.json>
```

将 Corpus 接入 P3-18 Qualification：

```bash
PYTHONPATH=src .venv/bin/python scripts/run-semantic-gate-qualification.py \
  --candidate <gate-candidate-requiring-human-corpus.json> \
  --quality-report <quality-report.json> \
  --provider-promotion <provider-promotion.json> \
  --evidence-confidence <confidence.json> \
  --human-corpus <final-human-corpus.json> \
  --positive-cases 20 --eligible-negative-cases 20 \
  --format json --output <qualification.json>
```

## 当前 Pilot 执行状态（2026-09-01）

41 Case Final Corpus 已达到覆盖要求：20 条 Positive、20 条 Eligible Negative、1 条
Near-miss、0 条 Unknown、0 条 Unresolved、2 位 Reviewer。使用新的 Candidate 执行
Preflight 后，结果已保存为：

```text
pilots/semantic-gate-p3-19/real-provider-pilot-preflight-p3-19-2026-09-01.json
```

状态为 `preflight_blocked`，不是质量失败。阻塞原因是当前本地环境没有真实 Endpoint、
Credential、`--allow-live` 和组织审批。该次执行确认了 Corpus/Candidate 绑定、Digest、
Human Review 完整性和调用预算均通过，并确认没有网络访问。

因此本任务的工程链路已完成，但 `Real Provider Evaluation Report` 尚未产生。不得将
Preflight 结果表述为 Provider 质量指标或 Gate Qualification 结论。
