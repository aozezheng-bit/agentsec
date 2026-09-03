# P3-HOMI-RECAL-03：Operationality 状态契约

- 日期：2026-09-03
- 状态：本地实现完成；Homi 端复核待发布审批
- 目标：把“静态声明看起来有风险”和“当前运行时已经具备可达能力”分开，避免
  把静态 High 直接解释成当前已生效的 High。

## 状态定义

| 状态 | 定义 | 当前静态扫描能否产生 |
|---|---|---:|
| `template` | 示例、占位符、文档模板或仅用于说明的内容 | 可以 |
| `latent` | 有静态意图或不完整信号，但没有明确可操作路径/运行时权限证明 | 可以 |
| `active` | 存在明确静态能力、任务或控制文件写入声明，但仍没有运行时证明 | 可以 |
| `runtime_attested` | 有独立、可复现、受信任的运行时证明 | 当前不能 |

## 设计边界

- Operationality 不替换 Severity；
- Operationality 不替换 Evidence Confidence A/B/C/D；
- 静态 Homi 报告固定 `runtime_verified=false`，因此当前不会生成
  `runtime_attested`；
- `template` 不代表文件不存在，而是代表内容仅为模板/示例；
- `latent` 不等于安全，也不等于漏洞成立；它表示仍需要更强证据；
- `active` 只表示静态声明更具体，不代表实际权限已启用；
- 只有经过独立运行时 Attestation，未来才允许进入 `runtime_attested`。

## 交付形式

为保持已冻结的 Homi Pilot `0.2.0` 历史报告字节稳定，本任务不直接向旧 Pilot
JSON 增加字段，而生成独立 Sidecar：

```text
homi-operationality.json
```

Sidecar 绑定：

- `source_report_sha256`：对应 Pilot JSON 的 SHA-256；
- `source_report_format`：必须是 `agentsec-homi-report-only-pilot`；
- 每个 capability/persona signal 的状态、Operationality、Confidence、Evidence
  Method、Evidence Location；
- 四类状态计数；
- `report_only=true`、`runtime_verified=false`、`ci_blocked=false`。

这保证了：报告升级不会偷偷改变旧验收证据，同时新系统可以读取更丰富的状态。

## 当前确定性映射

- `example_only` 或模板分类方法 → `template`；
- 明确静态声明（`present` / `conditional`）→ `active`；
- `unknown`、`absent`、运行时未验证信号 → `latent`；
- 用户资料持久化、长期记忆、自演化和身份自分配等泛化模板意图 → `latent`；
- `runtime_attested` 仅保留为未来状态，静态侧禁止伪造。

## 本地验证

```text
Operationality 单元测试：2 passed
Homi + Provenance + Posture + Calibration 定向测试：82 passed（含历史回放）
```

## 后续

P3-HOMI-RECAL-04 将在不改变现有 Severity 的前提下，为 Finding 增加“潜在影响”与
“当前安全态势”的分离展示，并消费本 Sidecar 的 Operationality。
