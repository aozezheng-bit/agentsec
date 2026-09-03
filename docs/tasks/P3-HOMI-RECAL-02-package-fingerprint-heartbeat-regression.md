# P3-HOMI-RECAL-02：包一致性与 HEARTBEAT 回归

- 日期：2026-09-03
- 状态：本地实现完成；Homi 远端发现导出边界回归，修复见 P3-HOMI-RECAL-07，需重新复验
- 目标：解决“版本号相同但实现内容不同”的可观测性问题，并为
  `HEARTBEAT.md` 模板误报提供可重复的本地回归契约。

## 已完成

### 1. 构建/包身份指纹

Homi 报告目录新增 `homi-build-fingerprint.json`，包含：

- `package_version`
- `adapter_version`
- `profile_model_version`
- `pilot_format_version`
- `combination_rule_pack_version`
- `rule_pack_version`
- `build_commit`
- `build_commit_source`
- `implementation_digest`
- `package_digest`
- 文件数量和摘要算法

摘要均由 AgentSec 自身已打包资源计算，不读取被扫描 Workspace，不执行
Git 命令，不访问网络，也不暴露环境变量原值。构建流水线可以通过
`AGENTSEC_BUILD_COMMIT` 注入经过格式校验的提交号；未注入时明确输出
`build_commit=unavailable`。

### 2. CLI 指纹命令

```bash
agentsec homi fingerprint --format json
agentsec homi fingerprint --format text
```

Homi Skill 同步增加 `commands/fingerprint.sh`，要求在发布、升级和报告比对
前记录 `implementation_digest` 与 `package_digest`。`0.4.0` 版本字符串本身
不再被视为包内容一致性的充分证据。

### 3. 报告呈现

Homi Pilot 的 JSON、Markdown 和 HTML 保持原有内容契约和历史回放字节稳定；
构建身份由同一输出目录中的指纹 Sidecar 提供。该 Sidecar 只展示版本、提交号
和摘要，不展示源文件内容、Workspace 路径或 Secret。这样不会修改已冻结的
外部 Pilot 报告，也不会破坏历史回放证据。

### 4. Heartbeat 模板回归

现有适配器契约继续保持；同时兼容 Homi 导出视图的文件边界包装：

- 纯文档/模板 Heartbeat（含 `=== HEARTBEAT.md ===` 导出边界标记）→
  `empty`/`example_only`，`tasks_present=false`，不触发 `HOMI-COMB-002`；
- 含真实任务的 Heartbeat → `present`，可按确定性规则触发
  `HOMI-COMB-002`；
- 两类结果均保持 `runtime_verified=false` 和 report-only。

## 本地验证

```text
Homi 相关定向测试：以候选分支最终验证结果为准（新增导出边界回归）
构建指纹新增测试：5 passed
Ruff（本轮文件）：passed
```

## 尚未完成

Homi 远端尚未更新。待发布审批后，应在 Homi 端执行：

1. `agentsec homi fingerprint --format json`；
2. 对比已审阅的 `package_digest`、`implementation_digest` 和版本向量；
3. 对纯模板 Heartbeat 和真实任务 Heartbeat 分别执行 Smoke Test；
4. 保存远端输出作为外部证据；
5. 在确认摘要一致后，才进入后续 Operationality 和评分口径校准。

本任务不改变 Finding 的 Severity、Evidence Confidence 或 CI/Hard Gate 权限。
