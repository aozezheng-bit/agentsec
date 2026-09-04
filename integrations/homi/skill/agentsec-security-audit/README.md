# AgentSec Security Audit Skill

This is the Homi/OpenClaw integration wrapper for the AgentSec CLI. It keeps orchestration and presentation guidance in `SKILL.md`; deterministic analysis remains in the installed `agentsec` package.

## Install

Install a pinned AgentSec wheel in the Homi runtime, then copy or mount this directory under the workspace's `skills/` directory:

```text
<workspace>/skills/agentsec-security-audit/
```

## Quick test

```bash
commands/scan.sh /path/to/homi-workspace
commands/report.sh /path/to/homi-workspace /tmp/agentsec-homi-report
commands/manifest.sh /path/to/homi-workspace
commands/fingerprint.sh
commands/reconcile-runtime.sh /tmp/agentsec-homi-report /tmp/runtime-attestation.json
```

The commands are read-only with respect to the target workspace and delegate all analysis to AgentSec.

`fingerprint.sh` records the exact AgentSec package/build identity used by the
runtime.  Compare its `implementation_digest` and `package_digest` when
checking whether two Homi installations are actually running the same code;
the human-readable package version alone is insufficient.

## Report artifacts

`agentsec homi report` produces a paired set of machine and human artifacts:

```text
homi-pilot-report.json  # stable machine-readable contract
homi-pilot-report.md    # Markdown review summary
homi-pilot-report.html  # self-contained browser-viewable report
homi-build-fingerprint.json  # package/build identity for consistency checks
homi-operationality.json  # legacy signal operationality sidecar
homi-risk-state.json  # RISK-02 file/signal template/latent/active/unknown state
homi-operation-context.json  # RISK-03 structured operation context extraction
homi-context-risk.json  # RISK-04 context-aware deterministic risk Findings
homi-risk-score.json  # RISK-05 potential/residual/posture/drift scores
homi-posture.json  # potential impact vs current posture sidecar
homi-calibration.json  # calibrated HOMI-COMB-003/004 Finding decisions
homi-runtime-trust-verification.json  # trusted issuer/signature/time/replay result
homi-runtime-reconciliation.json  # external Runtime Attestation reconciliation
homi-runtime-replay-store.json  # hashed nonce replay markers; no raw nonce/secret
```

The HTML is suitable for opening directly in Homi or a local browser. It is
built from the same report object as JSON/Markdown, so the three formats share
the same Findings, capability states, Unknown counts, and authority flags.

`homi-context-risk.json` is produced from the exact Operation Context Set. It
matches concrete combinations of action, target, data sensitivity, trigger,
purpose, authorization, and controls. Public-web reads of public data,
persona text, and long-term memory do not become high-risk Findings by
themselves. The sidecar is report-only, contains no numeric score, and is
bound to `homi-operation-context.json` by a canonical SHA-256 digest.

`homi-risk-score.json` is the RISK-05 report-only quantification sidecar. It
keeps potential impact, residual risk after bounded explicit controls, current
posture, and baseline-relative risk drift separate. Static scans keep the
current posture score null; they do not prove runtime exposure. A baseline is
required before risk drift is calculated.

### Runtime Attestation 对账

AgentSec 不执行被扫描 Agent，也不自行生成运行时证明。运行时证据必须由
Homi 沙箱、平台遥测或其他经组织批准的外部系统产生，并且只能提交脱敏后的
`runtime-attestation.json`。AgentSec 只验证其格式、权威边界和哈希绑定，然后
生成 `homi-runtime-reconciliation.json`：

```bash
commands/reconcile-runtime.sh \
  /tmp/agentsec-homi-report \
  /tmp/runtime-attestation.json
```

For trusted verification, provide a registry that stores only issuer metadata
and an environment-variable name. The secret value stays outside files and
reports:

```bash
export AGENTSEC_RUNTIME_TRUST_REGISTRY=/tmp/runtime-trust-registry.json
export AGENTSEC_RUNTIME_REPLAY_STORE=/tmp/agentsec-homi-report/homi-runtime-replay-store.json
export RUNTIME_ATTESTATION_KEY='use-an-approved-secret-manager-value'
commands/reconcile-runtime.sh /tmp/agentsec-homi-report /tmp/runtime-attestation.json
```

The command writes both `homi-runtime-trust-verification.json` and
`homi-runtime-reconciliation.json`. A trusted result requires registered
issuer/key, matching HMAC-SHA256 signature, valid `issued_at`/`expires_at`, and
first-use nonce. Missing registry, bad signature, expired evidence, revoked
key, store failure, or replay fails closed to `runtime_verified=false` and
Evidence Confidence D. Trust remains report-only: it grants no permission,
does not authenticate identity, and cannot block CI.

对账会绑定三类来源：Homi Pilot Snapshot、Operation Context、RISK-04 Context
Risk。只有外部证据已验证、所有声明操作均匹配、上下文覆盖完整且没有冲突时，
对账状态才是 `reconciled`，并可将该**证据**标记为 Confidence A。该结果仍然
是 report-only：不授予 Tool/OAuth/Permission，不认证 Agent 身份，不修改 Policy，
不阻断 CI，也不证明漏洞可利用性。未观察、未声明、动作/目标不匹配和 Unknown
都保留在报告中，不会静默视为安全通过。

For before/after reports:

```text
commands/homi-diff.sh before.json after.json html /tmp/homi-drift.html
```

The Capability Diff JSON artifact follows the strict
`schemas/capability-diff.schema.json` contract included in this Skill. Its
`authority` object is fixed to report-only semantics; it cannot be used as a
runtime attestation, authorization, or CI-blocking decision.

### 联合 HTML 报告

将当前 Pilot 与 Capability Diff 合并为一个中文优先的浏览器报告：

```bash
commands/bundle.sh /path/to/homi-pilot-report.json \
  /path/to/homi-capability-diff.json \
  /tmp/homi-security-report.html
```

该页面包含当前 Agent 快照、能力/功能解释、能力漂移、可选的四维评分视图、Findings、确定性整改建议和安全边界。若要显示评分雷达图，可在 CLI 中额外传入 `--score agentic-assessment.json`。
建议可以由 Homi 的 LLM 做脱敏后的语言润色，但 LLM 没有评分、Policy、Hard Gate 或 CI
决策权。

如果 Pilot 目录中存在同一 SHA-256 绑定的 Operationality、Posture 和 Calibration
Sidecar，联合报告会自动采用校准后的 Finding 展示，并同时保留原始静态影响分作为审计
参考。Sidecar 绑定失败时会拒绝生成联合报告。
