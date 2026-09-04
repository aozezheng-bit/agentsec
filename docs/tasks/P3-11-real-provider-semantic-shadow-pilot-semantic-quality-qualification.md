# P3-11: Real Provider Semantic Shadow Pilot / Semantic Quality Qualification

- Status: Complete (A/B/C all closed 2026-08-31)
- Date: 2026-08-31
- Depends on: P3-01～P3-10
- Mode: Shadow-only; real invocation is decision-gated

## Objective

Establish the first evidence-backed semantic Quality Qualification over
human-labeled gold data, and run a Real Provider Shadow Pilot only after an
explicit endpoint decision. The task must not grant Provider, Finding, Rule,
Policy, CI, Hard Gate, or release authority.

## Sub-task decomposition

### P3-11A Human-labeled semantic evaluation set (offline, no dependency)

- [x] Build a blinded reviewer pack from real (non-synthetic) corpus excerpts:
      Homi Pilot states, prompt-injection testdata, and demo workspaces.
- [x] Sanitize and bound every excerpt through `build_semantic_evidence_chunk`.
- [x] Emit an evidence-ID mapping table so the reviewer can bind judgments
      without seeing raw payloads in any report.
- [x] Ship a Chinese reviewer workflow doc, a submission template JSON, and a
      strict import validator producing `SemanticEvaluationCase` labels.
- [x] Target 30～50 cases with bilingual (Chinese/English/mixed) coverage.
- Acceptance: labels are human-authored; no secret or raw excerpt is retained;
  cases are content-addressed and reproducible.

#### P3-11A 完成记录（2026-08-31）

```text
案例                  45（testdata 28 / homi_snapshot 10 / demo 7；中文 8 例）
判断                  108 条（determination: supported 101 / not_supported 7）
标注方式              ai_draft_human_confirmed（AI 起草底稿 + 人工逐案例复核确认）
签署人                internal-reviewer（复核记录：REVIEW-WORKSHEET.zh.md，45 例全部确认，零修改）
产物                  pilots/semantic-quality-p3-11/gold-labels/semantic-gold-labels.json
审计链                review-submission.ai-draft.json（AI 底稿）
                      review-submission.completed.json（人工确认版）
                      REVIEW-WORKSHEET.zh.md（复核工作底稿）
工具                  scripts/build-p3-11-reviewer-pack.py（幂等生成器）
                      scripts/build-p3-11-review-worksheet.py（复核表渲染）
                      scripts/import-p3-11-semantic-labels.py（fail-closed 导入校验）
权限                  report_only=true; blocks=false
```

### P3-11B Semantic quality qualification gate (offline)

- [x] Wire the imported labeled cases into `SemanticEvaluationHarness`.
- [x] Evaluate against the offline fixture Provider first; the live Provider
      path stays injectable and offline-replayable.
- [x] Compare harness metrics with `ProviderQualityThresholds` and emit a
      report-only qualification report (qualified / not_qualified with visible
      failure reasons).
- [x] Include offline/live parity metrics from `SemanticParityHarness` when a
      live transport is injected in tests.

#### P3-11B 完成记录（2026-08-31，ADR-0092）

```text
模块                  src/agentsec/semantic/quality_gate.py
Schema                schemas/semantic-analysis/semantic-quality-qualification-report.schema.json
provenance            SEMANTIC_QUALIFICATION_VERSION 0.1.0（semantic_quality_gate）
测试                  tests/test_semantic_p3_11.py（6 项：加载/合格/不合格/阈值/类型/坏形状）
首次正式报告          pilots/semantic-quality-p3-11/qualification/semantic-quality-qualification-offline.json
                      status=qualified; precision/recall/f1/evidence-accuracy/coverage 全 1.0
                      （离线 fixture 回放，非 real-Provider 质量声明）
金标准修正在门内暴露   13 处 scan_coverage→instruction_integrity（P3-01 契约禁止模型重定义 Coverage）
                      8 条重复合并（P3-01 契约禁止重复候选；108→97 判断）
权限                  report_only/policy/ci/release/runtime 全 false（Literal 级）
```
- Acceptance: thresholds failing produces `not_qualified` evidence only; every
  authority boolean stays `false`; no target execution; no raw payloads.

### P3-11C Real Provider Shadow Pilot (decision-gated)

Prerequisites (organizational, must be recorded before invocation):

```text
approved HTTPS endpoint URL                      → 决策：外部公开 API（见 ADR-0096）
approved Provider ID and Model ID binding        → 决策：中档模型（具体绑定执行时记录）
credential environment-variable name             → 决策：密钥管理服务注入本地环境变量
cost limit and attempt budget confirmation       → 决策：最小规模 45 案例 × 1 次调用
data-residency and retention confirmation        → 决策：确认可发送（语料已脱敏）
ADR record of the approval                       → ADR-0096 已记录 2026-08-31
```

Decision record: `docs/decisions/0096-p3-11c-real-provider-decision.md`

- [x] Run the approved live binding over the labeled set
      (theta-public|Kimi-K3-256K, 2 budgeted runs via
      scripts/run-p3-11c-live-trial.py).
- [x] Archive evaluation and qualification reports (attempt 1 kept as the
      pre-canonicalization control).
- [x] No automatic Provider promotion and no authority change.

#### P3-11C 完成记录（2026-08-31，ADR-0096）

```text
Provider              theta-public | Kimi-K3-256K（Theta OpenAI 兼容端点）
凭据                  THETA_API_KEY 环境变量（个人令牌；值永不入库）
运行                  2 次预算内运行（45 例/次，QPS 节流 1.8s）
契约适配              值中立规范化：limitations 排序去重 + candidates 按
                      candidate_key 稳定排序（P3-01 契约仍是唯一裁决者）
最终指标              42/45 complete; P=0.394 R=0.378 F1=0.385;
                      evidence_binding_accuracy=1.000; coverage=0.933
资格结论              not_qualified（真实模型首跑基线；驱动后续
                      Prompt/模型迭代，不构成晋升或降级）
误差模式              判断粒度差异：多标签案例的拆分口径与人工金标准不同
产物                  live-trial/evaluation-live.json（+attempt1 对照）
                      qualification/...-live.json（+attempt1 对照）
权限                  shadow_only / report_only；零 Policy/CI/Gate 影响
```


## Authority boundary

```text
operating_mode          shadow_only
candidate_evidence_only true
report_only             true
blocks                  false
policy_authority        false
release_authority       false
provider_promotion_authority false
raw_payloads_retained   false
```

## Non-goals

- No LLM finding publication, Severity assignment, or gate influence.
- No mutation of Findings, Rules, Policy, or baselines.
- No network access outside the explicitly approved endpoint.
- No quality-number claims against synthetic fixtures alone.

## Verification commands

```bash
PYTHONPATH=src .venv/bin/python scripts/export_release_schemas.py
.venv/bin/python -m pytest tests/test_semantic_p3_11.py -q
./scripts/check.sh
PYTHONPATH=src .venv/bin/python scripts/verify-package-hardening.py
PYTHONPATH=src .venv/bin/python scripts/verify-reproducible-build.py
```
