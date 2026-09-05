# RISK-10A Homi Candidate Handoff

- Branch：`codex/risk-10a-candidate`
- Source Commit：`ef21355d9f4b72daa789a0cc19a49410631eae1b`
- Artifact Commit：`ec885f5d5e0485c471a80ffdcf877201ead8131d`
- Wheel SHA-256：`dacc6e0f6d7238d03f6f6b8b6c5b16647f654e403652163271e734a8a5eb0dd1`
- Candidate：`candidate_go`

Homi 拉取流程：

```bash
git fetch origin codex/risk-10a-candidate
git checkout ec885f5d5e0485c471a80ffdcf877201ead8131d
sha256sum dist/candidates/0.4.0-p3-rel-01/agentsec-0.4.0-py3-none-any.whl
```

期望 Wheel SHA-256：

```text
dacc6e0f6d7238d03f6f6b8b6c5b16647f654e403652163271e734a8a5eb0dd1
```

仅安装到隔离虚拟环境。不得覆盖平台现有 AgentSec 安装。静态报告保持 report-only，
不声明运行时权限、CI 阻断或生产发布。
