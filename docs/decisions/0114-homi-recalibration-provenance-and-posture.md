# ADR-0114：Homi 重校准采用 Provenance / Operationality / Posture Sidecar

- Status: Accepted for `P3-HOMI-RECAL-02～05`
- Date: 2026-09-03
- Scope: Homi report-only integration

## Context

Homi 远端曾出现：版本字符串都是 `0.4.0`，但纯模板
`HEARTBEAT.md` 仍触发 `HOMI-COMB-002`。仅比较版本号无法证明两套运行时
加载了相同实现。与此同时，静态组合 Finding 的潜在影响分被误读为当前
Agent 已经具备同等强度的运行时风险，尤其是初始化模板中的用户资料、人格
自演化和身份初始化话术。

已接受的历史 Homi Pilot `0.2.0` JSON 及外部证据需要继续保持字节级回放能力，
因此不能直接重写旧报告契约。

## Decision

1. 采用独立的 `homi-build-fingerprint.json` 记录包版本、适配器/画像/规则包
   版本、构建提交号、实现摘要和包摘要；`0.4.0` 字符串不再作为内容一致性
   的充分证明。
2. 采用 `homi-operationality.json` 表达：
   - `template`：模板或示例；
   - `latent`：静态意图存在但没有明确可操作证据；
   - `active`：明确静态声明存在但没有运行时证明；
   - `runtime_attested`：预留给独立运行时证明，静态扫描不得伪造。
3. 采用 `homi-posture.json` 分离：
   - 原始静态最高潜在影响；
   - 校准后潜在影响；
   - 当前安全态势；
   - 当前态势分。
4. 采用 `homi-calibration.json` 对 `HOMI-COMB-003/004` 进行确定性校准，
   保留原始 Finding 和理由码，不直接修改冻结 Pilot JSON。
5. 所有 Sidecar 固定：`report_only=true`、`runtime_verified=false`、
   `ci_blocked=false`。LLM 不参与这些字段、Finding、Score、Policy 或
   Gate 决策。

## Consequences

### Positive

- 可以用摘要而不是版本字符串核验 Homi 远端包一致性；
- 初始化模板不会直接被呈现为当前已生效的高风险运行时能力；
- 历史外部证据不被重写；
- 规则校准有机器可读理由和原始 Finding 追溯链；
- Potential Impact、Severity、Evidence Confidence、Operationality 和
  Runtime Verified 保持独立。

### Trade-offs

- 一个报告目录包含多个绑定 Sidecar，消费端需要按 SHA-256 绑定读取；
- 当前仍不能证明 Tool、OAuth、Permission、Scheduler 或 Exploit 的运行时可达性；
- 远端 Homi 更新前，只有本地代码和 Wheel 验证完成，不能宣称已同步。

## Rejected alternatives

- **只升级包版本号**：不能排除相同版本号对应不同代码；
- **直接把静态 8.0 折扣成当前分数**：没有可审计标准，容易产生伪精确；
- **删除模板 Finding**：会丢失原始证据和校准可追溯性；
- **让 LLM 决定抑制或阻断**：违反 AgentSec 确定性规则与权限边界。
