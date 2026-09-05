# RISK-10A Local Candidate Freeze

- 状态：`local_frozen_source_committed`
- Source Commit：`3a82e40ed37046a876643b7981a5580460be858b`
- Candidate：`candidate_go`
- `acceptance_ready=true`，`ready_for_release=true`
- Wheel SHA-256：`0e385ab5649656e1f91e67a76ce57aa7c3b74b91666135a2ef097df72e30dc94`
- sdist SHA-256：`64415c05418d8f1d30ff3a2129ed888a71aa8028b6a76e8166a2e5879d8199ad`
- Provenance SHA-256：`06daca555bd7ac32837e5545d4bbfb24af7493f413712b4905a25e8cc6307236`
- Full Pytest：1769 passed
- Snapshot Context Sidecar：passed
- Mypy：407 files passed
- Credential Pattern Audit：0 hit

Candidate 从固定 Source Commit 的两个隔离临时源码副本构建。Snapshot CLI 会自动输出
`homi-operation-context.json`，Risk CLI 可直接使用 Sidecar 做 baseline drift。
