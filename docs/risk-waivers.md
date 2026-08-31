# AgentSec Risk Waivers

- Task: `P2-28`
- Status: Complete
- Date: 2026-08-25
- Organization Policy Schema: `0.2.0`
- Organization Assessment Output: `0.2.0`
- ADR: `docs/decisions/0058-expiring-risk-waivers.md`

Waivers are explicit organization Policy records that remove CI blocking without
hiding Findings or Gate matches.

```yaml
waivers:
  - waiver_id: waiver-demo-exec
    owner: security-team
    reason: Temporary reviewed demonstration exception
    expires_on: 2026-12-31
    finding_ids: []
    rule_ids: [MD-EXEC-001]
    gate_ids: []
```

Every Waiver requires a stable ID, Owner, Reason of at least 10 characters,
Expiry date, and at least one Finding/Rule/Gate scope. Scope lists are OR
selectors. Unknown Rule/Gate IDs, duplicate Waiver IDs, missing fields, and
empty scope are rejected.

A Waiver is active through its `expires_on` date and expires on the following
day. Evaluation records the exact date. Expired Waivers remain visible but have
no effect.

Scan decisions expose matched, waived, and still-blocking Finding IDs plus
applied/expired Waiver IDs. Findings remain in Text/JSON/SARIF. Capability Gate
decisions expose `waived` and `waiver_ids`; a Waiver cannot qualify an
unqualified Gate or bypass Coverage/Unknown checks.

Example:

```bash
agentsec scan PROJECT \
  --policy policies/organization-policy-waiver-example.yaml
```

P2-28 does not add automatic approval, remote waiver services, signatures, or
runtime exploitability claims.
