# P3-19 Pilot Pack

This directory contains only a non-live configuration template. It intentionally
contains no endpoint, credential, raw prompt, model response, or quality claim.

Before a real run, supply a current Gate-specific human corpus and candidate,
obtain the organizational approvals described in
`docs/tasks/P3-19-semantic-gate-human-corpus-real-provider-pilot.md`, and invoke
`agentsec semantic gate-pilot --allow-live` explicitly.

评审包已准备完成：

```text
human-corpus-draft.json       # 40 条待评审 Case，当前全部标记为 draft/unknown
reviewer-a/cases.json         # Reviewer A 专用副本
reviewer-a/review-worksheet.tsv
reviewer-a/submission.template.json
reviewer-b/cases.json         # Reviewer B 专用副本
reviewer-b/review-worksheet.tsv
reviewer-b/submission.template.json
```

两位专家只需要分别使用自己的目录，填写 `review-worksheet.tsv`，然后将结果转换
到 `submission.template.json` 的 `decisions` 数组中。不要互相查看评审结果。

> 注意：`submission.template.json` 是合法 JSON，`decisions` 初始为空。专家完成
> Worksheet 后，需要将 40 条 Decision 写入该数组；每条 Decision 可额外包含
> `expected` 语义候选数组，用于后续 Provider Precision / Recall 评估。

两位 Reviewer 的完整操作流程：

- `reviewer-a/WORKFLOW.zh.md`
- `reviewer-b/WORKFLOW.zh.md`

当前两位专家结果已经导入：

```text
adjudications.json
human-corpus-final.json
REVIEW-DIFF.zh.md
review-diff.json
ADJUDICATION-WORKFLOW.zh.md
```

最终 Corpus 当前为 19 条 Positive、20 条 Eligible Negative、1 条 Near-miss。由于
P3-18 要求至少 20 条 Positive，仍需补充 1 条独立 Positive Case；详见
`coverage-gap-report.zh.md`。

新增 Case `p3-19-41` 已准备为独立补充评审包：

```text
supplemental-case-41-corpus-draft.json
reviewer-a-case-41/cases.json
reviewer-a-case-41/review-worksheet.tsv
reviewer-a-case-41/submission.template.json
reviewer-a-case-41/WORKFLOW.zh.md
reviewer-b-case-41/cases.json
reviewer-b-case-41/review-worksheet.tsv
reviewer-b-case-41/submission.template.json
reviewer-b-case-41/WORKFLOW.zh.md
```

该 Case 当前不包含预设人工答案。两位专家完成后，将提交文件分别命名为
`submission.completed.json`，再由项目负责人进行单 Case Adjudication 或确认采用
一致结果。完成后将把该 Case 合并到 `human-corpus-final.json`，使 Positive 覆盖达到
20 条。

Case 41 评审完成后，先导入补充 Corpus：

```bash
PYTHONPATH=src .venv/bin/python scripts/import-semantic-gate-review.py \
  --corpus pilots/semantic-gate-p3-19/supplemental-case-41-corpus-draft.json \
  --review pilots/semantic-gate-p3-19/reviewer-a-case-41/submission.completed.json \
  --review pilots/semantic-gate-p3-19/reviewer-b-case-41/submission.completed.json \
  --output pilots/semantic-gate-p3-19/supplemental-case-41-final.json
```

若 Case 41 两位专家存在分歧，再增加：

```text
--adjudications pilots/semantic-gate-p3-19/adjudications-case-41.json
```

然后合并到已确认的 40 Case Corpus：

```bash
PYTHONPATH=src .venv/bin/python scripts/merge-semantic-gate-corpus.py \
  --base pilots/semantic-gate-p3-19/human-corpus-final.json \
  --supplement pilots/semantic-gate-p3-19/supplemental-case-41-final.json \
  --output pilots/semantic-gate-p3-19/human-corpus-final-41.json
```

合并前，补充 Corpus 必须已经完成人工评审；脚本拒绝合并仍处于 `draft` 的补充 Case。

## 2026-09-01 Pilot 执行记录

已使用 41 Case Final Corpus 和要求 `human_corpus` 的当前 Candidate 执行一次
Real Provider Pilot preflight：

```text
real-provider-pilot-preflight-p3-19-2026-09-01.json
```

Preflight 结果为 `preflight_blocked`，这是预期的安全结果。当前环境没有配置：

- `THETA_API_KEY`；
- 经批准的 HTTPS Endpoint；
- `--allow-live` 明确外呼开关；
- 数据驻留、保留策略和费用审批；
- Review Owner 和 Approval ID。

本次执行未访问网络、未读取凭据值、未调用模型、未保存 Prompt/Response。
