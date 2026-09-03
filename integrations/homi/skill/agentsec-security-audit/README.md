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
homi-operationality.json  # template/latent/active/runtime_attested sidecar
homi-posture.json  # potential impact vs current posture sidecar
homi-calibration.json  # calibrated HOMI-COMB-003/004 Finding decisions
```

The HTML is suitable for opening directly in Homi or a local browser. It is
built from the same report object as JSON/Markdown, so the three formats share
the same Findings, capability states, Unknown counts, and authority flags.

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
