# RISK-10A Homi Candidate Handoff

- Source Commit：`3a82e40ed37046a876643b7981a5580460be858b`
- Branch：`codex/risk-10a-candidate`
- Wheel SHA-256：`0e385ab5649656e1f91e67a76ce57aa7c3b74b91666135a2ef097df72e30dc94`

Homi 拉取该分支最新 Candidate 后，校验 Wheel SHA-256，并在隔离环境执行：

```bash
agentsec homi snapshot create <workspace> \
  --subject-id homi:agent:<immutable-id> \
  --output baseline.json
# 自动生成 homi-operation-context.json
agentsec homi risk <workspace> \
  --subject-id homi:agent:<immutable-id> \
  --baseline baseline.json \
  --baseline-context homi-operation-context.json
```
