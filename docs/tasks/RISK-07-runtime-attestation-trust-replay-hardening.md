# RISK-07：Runtime Attestation Trust / Replay Hardening

- **日期**：2026-09-04
- **状态**：本地实现完成；保持 report-only；未向 Homi 发布
- **前置任务**：RISK-06 Runtime Attestation / Evidence Reconciliation

## 目标

RISK-06 只验证 Runtime Attestation 结构和来源绑定。RISK-07 增加可信发行者、签名、时效和防重放校验，避免任意外部 JSON 通过 `verification_status=verified` 伪造运行时证据。

## 信任链

```text
外部批准的运行时验证器
  → 生成脱敏 Runtime Attestation
  → 使用 Trusted Issuer / key_id 对应密钥签名
  → AgentSec 读取外部 Trust Registry
  → 从明确的环境变量读取密钥
  → 校验签名、时间窗口、Issuer、Key、Nonce
  → 写入 Trust Verification Report
  → 将 Trust Decision 绑定到 RISK-06 Evidence Reconciliation
```

AgentSec 不从被扫描 Workspace 读取密钥，不执行被扫描 Agent，不访问网络，不调用 Tool、OAuth、MCP、Scheduler 或 LLM。

## Attestation 0.2

新增字段：

- `key_id`：支持同一 `issuer` 多把并存密钥轮换；
- `signature_algorithm`：当前只支持无外部依赖的 `hmac_sha256`；
- `issued_at`、`expires_at`：UTC RFC3339 秒级时间；
- `nonce`：16～128 字符唯一随机值；
- `signature`：64 位小写 HMAC-SHA256；
- `attestation_id` 覆盖除签名外全部内容；签名覆盖规范化完整 unsigned payload。

Attestation 本身 `evidence_confidence` 固定为 D。只有通过信任校验并完成对账，Reconciliation 才能产生 A/B：

| 条件 | Reconciliation Confidence |
| --- | ---: |
| Trust 失败、缺少 Registry、签名/时效/重放失败 | D |
| Trust 通过，但 Context/RISK-04 对账 partial 或 conflict | B |
| Trust 通过，所有操作匹配且 Context 覆盖完整 | A |

## Trusted Issuer Registry

格式：`agentsec-runtime-trust-registry`。

Registry 只保存：`issuer`、`key_id`、算法、`secret_env_var`、撤销状态、发行有效期、最大 Attestation 年龄和时钟偏差。禁止保存密钥值。

支持：

- `active` / `revoked` Key；
- 同一 Issuer 多个 Key ID；
- 环境变量缺失、密钥过短 → 失败关闭；
- Registry 自身 report-only，不产生权限或 CI 权威。

## 防重放 Store

默认文件：`<report-dir>/homi-runtime-replay-store.json`。

只保存：

- `issuer`；
- `key_id`；
- `nonce_sha256`；
- `attestation_sha256`；
- `accepted_at`；
- `expires_at`。

Store 使用：

- symlink 拒绝；
- 1 MiB 文件大小限制；
- 最多 4096 条；
- 过期 Entry 自动清理；
- `O_CREAT | O_EXCL` 锁文件；
- 临时文件、fsync、`os.replace` 原子更新；
- 权限 0600；
- 读写异常 → `replay_store_error`，不接受运行时证据。

相同 `(issuer, nonce_sha256)` 再次出现 → `replayed`，不产生可信结果。

## CLI

```bash
agentsec homi reconcile-runtime \
  --report-dir /tmp/agentsec-homi-report \
  --attestation /tmp/runtime-attestation.json \
  --trust-registry /tmp/runtime-trust-registry.json \
  --replay-store /tmp/agentsec-homi-report/homi-runtime-replay-store.json \
  --force
```

输出：

```text
homi-runtime-trust-verification.json
homi-runtime-reconciliation.json
homi-runtime-replay-store.json
```

省略 Registry 时仍生成 `status=missing` Trust Report，并将对账固定为 `unverified` / D，便于 report-only 诊断，不伪造运行时可信度。

## Report / Bundle

Combined Bundle 自动读取并绑定 Trust Verification 与 Reconciliation：

- `verification_id`；
- Issuer / Key ID；
- 签名、时效、重放状态；
- Trust reason codes；
- Trust → Reconciliation ID 绑定；
- Evidence Confidence；
- report-only 安全边界。

Trust 结果不改变 Finding、Risk Score、Policy、Hard Gate、CI、身份认证或权限。

## Schema / API

新增：

```text
schemas/runtime/runtime-trust-registry.schema.json
schemas/runtime/runtime-trust-verification.schema.json
schemas/runtime/runtime-replay-store.schema.json
```

Python API：

```text
TrustedRuntimeIssuer
RuntimeTrustRegistry
DeterministicRuntimeTrustVerifier
RuntimeReplayStore
sign_runtime_attestation
```

## 验证

覆盖：正确签名、错误签名、未知 Issuer、未知 Key、撤销 Key、密钥缺失、时效、未验证声明、首次 Nonce、重放、Store symlink/锁/原子写入、敏感值最小化、Trust 绑定、Bundle 展示和 Authority 常量。

```bash
PYTHONPATH=src .venv/bin/pytest -q tests/test_runtime_attestation.py tests/test_runtime_homi_integration.py tests/test_runtime_trust.py
.venv/bin/ruff check src tests scripts/export_release_schemas.py
.venv/bin/mypy src tests
```

## 限制

当前使用 HMAC-SHA256 作为无外部依赖的合同基线，不等价于 KMS、硬件根信任或非对称身份认证。真实 Pilot 仍需组织批准的 Endpoint、密钥管理、数据驻留、保留周期、脱敏协议和运行时验证器。
