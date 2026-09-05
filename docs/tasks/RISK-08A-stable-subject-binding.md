# RISK-08A：Stable Homi Subject Identity Binding

- 日期：2026-09-04
- 状态：本地实现完成；未提交、未推送、未重建 Candidate
- 前置任务：RISK-08
- 决策：`docs/decisions/0121-stable-homi-subject-identity-binding.md`

## 目标

使用平台提供的稳定 `subject_id` 绑定 Snapshot、Drift 和 Unified Risk，删除
`project_name + 文件名集合` 伪身份判断。

## 合同

```text
subject_id: ^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$
```

属性：

- 必填；
- 由平台显式提供；
- 不从扫描内容推断；
- 进入 Snapshot Digest；
- 不进入 Workspace Fingerprint；
- 不包含 Secret；
- 不代表 AgentSec 已认证该身份。

`project_name` 仅供展示。项目改名不改变 Snapshot Digest，也不改变 Agent 身份。

## 身份判断

```text
baseline.subject_id == current.subject_id
  → 允许计算 Verified / Drift

baseline.subject_id != current.subject_id
  → identity_mismatch
  → 不输出跨 Agent Risk Drift
```

文件删除、文件新增、标准文件缺失和 Project Name 修改均属于同一 subject 下的状态变化，
不得用于推断“换了 Agent”。

## CLI

```bash
agentsec homi snapshot create <workspace> \
  --subject-id homi:agent:<immutable-id> \
  --output baseline.json

agentsec homi snapshot verify <workspace> \
  --subject-id homi:agent:<immutable-id> \
  --baseline baseline.json

agentsec homi drift <workspace> \
  --subject-id homi:agent:<immutable-id> \
  --baseline baseline.json

agentsec homi risk <workspace> \
  --subject-id homi:agent:<immutable-id> \
  --baseline baseline.json \
  --baseline-context homi-operation-context.json
```

缺少 `--subject-id` → CLI 配置错误。不同 Subject → 报告 `identity_mismatch`，不是普通 Drift。

## Skill

```text
snapshot.sh <create|verify> <subject-id> <workspace> [args...]
drift.sh <subject-id> <workspace> <baseline-snapshot>
risk.sh <subject-id> <workspace> [baseline-snapshot] [baseline-operation-context]
```

## 安全边界

- 不读取 Workspace 生成 subject；
- 不使用 IDENTITY.md 中 Name/Avatar/Emoji；
- 不把文件相似度当身份；
- 不迁移或猜测旧 Snapshot 身份；
- 不执行 DID、OAuth、登录或运行时身份认证；
- report-only、runtime-unverified、non-blocking 不变。

## 验证结果

```text
Snapshot / Drift / Risk / CLI / Skill / Provenance / Versioning: 71 passed
Ruff check: passed
Ruff format: passed
Mypy（受影响模块）: passed
Snapshot / Drift / Risk / Skill Request JSON: syntax valid
```

手工 Smoke Test：

- 同一 `subject_id`、同一文件、不同 `project_name` → `verified`，Snapshot Digest 不变；
- 不同 `subject_id`、相同文件和相同名称 → `identity_mismatch`；
- 同一 `subject_id` 删除标准文件 → `drifted`，不误报身份变化；
- 旧 Snapshot 缺少 `subject_id` → Decoder 失败关闭。
