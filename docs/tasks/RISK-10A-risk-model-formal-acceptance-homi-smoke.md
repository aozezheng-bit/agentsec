# RISK-10A：风险模型正式验收与 Homi Smoke Test

- 日期：2026-09-05
- 状态：完成；本地 Candidate 已重建并通过验收
- 前置：RISK-09A、RISK-10
- ADR：`docs/decisions/0125-risk-model-formal-acceptance-homi-smoke.md`

## 交付

- 正式验收脚本：`scripts/run-risk-model-acceptance.py`；
- 脚本测试：`tests/test_risk_model_acceptance.py`；
- 固定验收证据：`pilots/risk-model-acceptance-r10a/`；
- Candidate Installed-CLI Smoke：Homi Context Risk、Directional Drift、HTML；
- Source/Candidate 字节一致、双构建可复现、Wheel SHA-256 与 Provenance Bundle。

## 源码验收结果

```text
RISK-09 replay                 16/16 passed
baseline                       0.0 none
scenario-08                    CTX-RISK-002 / 8.0 high
scenario-10                    CTX-RISK-008 / 5.5 medium
scenario-12                    CTX-RISK-003/006 / 8.0 high
Authority                      report-only / runtime-unverified / non-blocking
Network / scanned execution    false / false
```

## Candidate 验收门槛

1. 从清洁临时源码副本构建 Wheel 与 sdist；
2. 两次固定 Epoch 构建字节一致；
3. Wheel/sdist 与当前 Source/Schema 字节一致；
4. 隔离虚拟环境安装，不使用网络；
5. Installed CLI 运行 Homi Smoke 并产生正确风险与 HTML；
6. 生成 SHA256SUMS、Release Manifest、Provenance Bundle；
7. Candidate Acceptance State Machine 返回 `candidate_go`；
8. 全量测试通过。

## 非声明

不声明远端发布、签名、SLSA Provenance、真实 Runtime Attestation、运行时漏洞证明或生产部署。

## 最终验证（2026-09-05）

```text
Full Pytest                         1768 passed
Ruff check / format                passed
Mypy strict                        passed (407 files)
RISK-10A source smoke              accepted
RISK-09 replay                     16/16 passed
Candidate reproducible build       byte-identical
Installed Wheel Homi smoke         passed
Release Manifest / Provenance      validated
Candidate Acceptance               candidate_go
acceptance_ready / ready_for_release true / true
```

Candidate 仍是本地 Evidence-only Artifact；未提交、未推送、未发布。
