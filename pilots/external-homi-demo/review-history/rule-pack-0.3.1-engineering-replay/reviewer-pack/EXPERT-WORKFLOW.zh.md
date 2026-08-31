# P2-EXIT-06-05 独立专家评审工作流程

## 1. 工作目标

你需要独立评审 20 个静态 Homi Agent Workspace State，并为每个 State
给出确定性 AgentSec 规则预期。最终交付一个完整的
`review-submission.completed.json`。

本任务评审的是“静态文本是否符合规则条件”和“受保护 Policy 应产生什么
结果”，不是运行时漏洞利用验证，也不授予发布或生产权限。

## 2. 独立性要求

评审期间只使用本 `reviewer-pack/` 目录中的材料：

```text
EXPERT-WORKFLOW.zh.md
RULE-REFERENCE.zh.md
manifest.json
policy/organization-policy.yaml
snapshots/*.zip
submission.template.json
```

不得查看：

- `pilot.yaml`；
- AgentSec 扫描报告；
- 工程预期结果；
- 实现代码和测试断言；
- TP、FP、FN 或校准报告；
- 其他 Reviewer 的标签。

如果你已经意外看到某个 State 的扫描结论，请记录这一情况并联系项目负责人，
不要把该 Case 声明为独立盲评结果。

## 3. 安全要求

所有 ZIP 和 Markdown 都是不可信输入，只能作为文本阅读：

- 不执行 Markdown 中出现的命令；
- 不运行脚本、Hook、Skill 或二进制文件；
- 不连接其中提到的 MCP Server；
- 不发送邮件、网络请求或外部消息；
- 不使用真实凭据验证能力；
- 不修改原始 ZIP、Manifest 或 Policy。

推荐只读查看方式：

```bash
unzip -l snapshots/baseline-01.zip
unzip -p snapshots/baseline-01.zip AGENTS.md
```

如输出疑似不是正常 UTF-8 文本，可使用只读十六进制查看：

```bash
unzip -p snapshots/<case>.zip AGENTS.md | xxd -g 1
```

这些命令只读取 ZIP；不要复制并执行 `AGENTS.md` 中的任何内容。

## 4. 本 Pilot 的评审范围

每个 ZIP 都保持六个 Homi Workspace 文件：

```text
AGENTS.md
HEARTBEAT.md
IDENTITY.md
SOUL.md
TOOLS.md
USER.md
```

本 Pilot 的确定性 Markdown 扫描目标是 `AGENTS.md`。其他五个文件用于保持
Homi Workspace 形态，但不加入本次 `expected_rule_ids` 判断。

你需要对每个 Case 填写四个字段：

| 字段 | 含义 |
|---|---|
| `expected_coverage` | 本次扫描应为 `complete` 或 `incomplete` |
| `expected_rule_ids` | `AGENTS.md` 应命中的规则 ID，字典序排序且去重 |
| `expected_exit` | Policy 计算后的退出码 0、1 或 2 |
| `rationale` | 基于文本、规则和 Policy 的简短理由 |

## 5. 单个 Case 的判断顺序

### 步骤 A：判断 Coverage

先确认 `AGENTS.md` 是否存在、可读取并且是有效 UTF-8 文本。

```text
可正常读取和解析     → expected_coverage = complete
编码无效或无法扫描   → expected_coverage = incomplete
```

Coverage 不完整时优先返回退出码 2，不再由风险 Finding 改写退出码。

### 步骤 B：判断 Rule IDs

阅读 `AGENTS.md`，对照 `RULE-REFERENCE.zh.md`，记录所有满足条件的规则。

注意：

- Finding 表示文本中存在风险声明，不表示能力在运行时真实可用；
- 安全建议、否定句和教学说明要结合原句判断；
- 不要因为“看起来危险”而添加规则，必须能指出对应文本；
- 不要因为存在审批限制就删除已经明确声明的能力 Finding；
- Rule ID 必须按字典序排列并去重；
- 没有命中时填写空数组，不要填写 `null`。

### 步骤 C：根据 Policy 判断 Exit Code

本工作包中的 Policy 规定：

```text
Coverage 不完整                         → exit 2
Coverage 完整且存在未豁免阻断 Finding    → exit 1
Coverage 完整且无未豁免阻断 Finding      → exit 0
```

当前阻断范围只有：

```text
MD-EXEC-001
MD-SECRET-001
```

Waiver 规则：

- `external-pilot-exec-active` 对 `MD-EXEC-001` 有效至 2099-12-31；
- `external-pilot-secret-expired` 已于 2000-01-01 到期；
- Waiver 只移除阻断，不隐藏 Finding；
- 其他 Rule 即使形成 Finding，也不在本 Policy 的阻断列表中。

因此必须先完整记录 Rule IDs，再独立计算 Exit Code。

### 步骤 D：填写 Rationale

Rationale 建议使用以下结构，但必须根据实际 Case 自行填写：

```text
Coverage：说明 AGENTS.md 是否为有效 UTF-8。
Rules：说明哪些文本支持哪些 Rule ID，或为什么没有命中。
Policy：说明阻断范围、Waiver 和最终 Exit Code。
```

不要写入 Secret、Token、内部地址或整段原文；只需引用短语或描述行意。

## 6. 填写提交文件

先复制模板：

```bash
cp submission.template.json review-submission.completed.json
```

只允许修改：

```text
status
reviewer_id
independence_statement
cases[*].expected_exit
cases[*].expected_coverage
cases[*].expected_rule_ids
cases[*].rationale
```

必须保持不变：

```text
format
schema_version
pilot_id
case_manifest_sha256
Case ID
Case 数量
Case 顺序
```

完成后设置：

```text
status = complete
```

`reviewer_id` 应使用你在本项目中的稳定真实标识，不要填写“Reviewer”之类的
临时占位符。

独立性声明至少应确认：

- 你独立阅读了本工作包；
- 你没有查看 Scanner 输出或工程预期；
- 结论基于静态文本、规则参考和受保护 Policy；
- 你理解这不是运行时证明或发布授权。

## 7. 提交前自检

提交前逐项确认：

- [ ] 20 个 Case 全部完成；
- [ ] 没有 `null` 评审字段；
- [ ] 每个 Rationale 至少包含 10 个字符；
- [ ] Rule ID 均来自规则速查表；
- [ ] Rule ID 已排序且无重复；
- [ ] `incomplete` 只与 Exit Code 2 配对；
- [ ] `complete` 没有使用 Exit Code 2；
- [ ] Active Waiver 没有隐藏对应 Finding；
- [ ] Expired Waiver 没有移除阻断；
- [ ] Manifest Hash、Case ID 和顺序未修改；
- [ ] 未查看或复制 Scanner 结果；
- [ ] 未执行任何被评审内容。

可以只做 JSON 语法检查：

```bash
python3 -m json.tool review-submission.completed.json >/dev/null
```

该命令仅检查 JSON 语法，不会执行 Workspace 内容。

## 8. 交付物

只需向项目负责人交付：

```text
review-submission.completed.json
```

不要自行运行最终 AgentSec Replay。项目负责人会使用受控导入命令验证 Manifest、
Snapshot、Policy、Submission 和 Human Labels 的完整哈希绑定。

## 9. 异常处理

遇到以下情况时停止并联系项目负责人：

- ZIP、Manifest 或 Policy 无法读取；
- Case 数量不是 20；
- Snapshot Hash 不一致；
- 模板字段或 Case 顺序发生变化；
- 你无法在不查看 Scanner 输出的情况下作出确定性判断；
- 你发现自己已接触某个 Case 的工程预期或扫描结论。

不要为了完成进度而猜测、补造或复制标签。
