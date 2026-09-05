# ADR-0121：Homi Snapshot 使用稳定 subject_id 绑定 Agent 身份

- 日期：2026-09-04
- 状态：Accepted（本地候选；未提交、未发布）
- 任务：RISK-08A

## 背景

旧 Snapshot 使用以下条件判断两次扫描是否属于同一 Agent：

```text
project_name 相同 + 标准文件名集合相同
```

该条件不可信：`project_name` 是调用者可修改的展示字段；不同 Agent 可以具有相同名称和
相同六类文件；同一 Agent 也可能改名或删除文件。结果会把跨 Agent 比较误报为 Drift，或
把同一 Agent 的正常文件变化误报为 Identity Mismatch。

## 决策

1. Snapshot 新增必填 `subject_id`。
2. `subject_id` 必须由 Homi/平台/受信调用方显式提供，AgentSec 不从 Workspace、IDENTITY.md、项目名、文件哈希或 LLM 推断。
3. 当前合同接受 1～128 位稳定不透明标识：

```text
^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$
```

4. `subject_id` 进入 Snapshot canonical payload 和 `snapshot_digest`。
5. `workspace_fingerprint` 继续只描述文件内容，不包含身份。
6. `project_name` 降为展示元数据，不进入 Snapshot digest，不参与身份判断。
7. Snapshot Verification 和 Drift 仅使用：

```text
baseline.subject_id == current.subject_id
```

8. 同一 subject 改名、增删文件或修改文件 → Drift/Verified，不是 Identity Mismatch。
9. 不同 subject 即使文件和名称完全相同 → `identity_mismatch`，禁止计算跨 Agent Drift Risk。
10. `agentsec homi snapshot|drift|risk` 和 Skill 包装命令必须显式传 `--subject-id`。
11. AgentSec 只绑定调用方提供的标识，不证明该标识真实归属，不实现 DID、登录认证或平台身份签名。

## 版本影响

- Homi Snapshot：`0.1.0 → 0.2.0`
- Homi Drift Report：`0.1.0 → 0.2.0`
- Homi Risk Report：`0.2.0 → 0.3.0`

旧 Snapshot 缺少 `subject_id`，新 Decoder 失败关闭。需要平台使用稳定 Agent ID 重新创建基线，
不能将旧基线自动迁移并猜测身份。

## 推荐平台映射

优先使用 Homi 内部不可变 Agent/员工主键：

```text
homi:agent:<immutable-id>
```

禁止使用：

- Agent 展示名称；
- 用户可编辑昵称；
- Workspace 路径；
- AGENTS.md/IDENTITY.md 内容；
- 文件摘要单独充当身份；
- 模型生成标识。
