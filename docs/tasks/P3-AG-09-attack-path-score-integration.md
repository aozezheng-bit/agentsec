# P3-AG-09：Attack Path Report 与 Capability Score 集成

## 目标

将已验证的 Attack Path Evidence Association Report（以及可选的、绑定到同一
Association Report 的 Calibration Report）以**报告型上下文**接入 `agentsec score`。
本任务不把静态攻击路径直接转换为风险分数，也不新增任何授权能力。

## 输入

```bash
agentsec score PROJECT \
  --before BEFORE-MANIFEST.json \
  --attack-path-report ASSOCIATION-REPORT.json \
  [--attack-path-calibration CALIBRATION-REPORT.json] \
  --format json|text|sarif
```

- `--attack-path-report` 必须是
  `agentsec-attack-path-evidence-association-report` `0.1.0`。
- `--attack-path-calibration` 必须是
  `agentsec-attack-path-calibration-report` `0.1.0`，并且其
  `association_report_sha256` 必须等于输入 Association Report 的规范化摘要。
- 输入通过有大小上限、拒绝符号链接、拒绝非 JSON 和严格 Pydantic Schema 的
  reader 加载；扫描项目内容仍不会被执行。

## 输出契约

`AttackPathScoreContext` 的格式为
`agentsec-attack-path-score-context` `0.1.0`，嵌入 Agentic Assessment JSON 的
`attack_path` 字段，并在 Text/SARIF 中提供摘要元数据。输出包括：

- Association / Path Report 摘要及规范化 SHA-256；
- path、association、Finding association、Semantic association 数量；
- `supports`、`partially_supports`、`duplicates`、`unmatched` 四类关系计数；
- 可选 Calibration 摘要、评审样本数量和 Accuracy；
- `scoring_mode=context_only`、`numeric_score_effect=0.0`；
- `calibration_qualified=false`、`report_only=true`、`runtime_verified=false`，以及
  全部 authority 字段为 `false`。

## 安全与评分边界

1. Attack Path Context 不修改 Technical、Drift、Governance 或 Overall Score。
2. 不修改 Severity、Finding、Confidence、Hard Gate、CI exit code 或 Release state。
3. Calibration Accuracy 即使为 `1.0` 也不自动转成资格或风险加分。
4. 静态路径仍然不能证明运行时可达性、真实攻击成功或可利用性。
5. `duplicates` 仅表示证据关联关系，不代表新增 Finding。
6. 报告不保留源码全文、Token、Credential、Endpoint 或 Secret。

## 验收

- 无 Attack Path 输入时，已有 Score 输出保持兼容，`attack_path=null`。
- 有效 Association Report 可进入 JSON/Text/SARIF 输出。
- Calibration Digest 不匹配时 fail-closed，返回 Artifact Error。
- 不带 Association Report 单独传 Calibration 时返回 Configuration Error。
- 集成前后四个分数、Severity、Hard Gate 和 CI 行为保持一致。
- 独立 Schema、Provenance ownership、API 导出和 CLI 测试通过。
