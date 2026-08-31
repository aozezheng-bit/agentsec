# P2-28: Risk Waivers

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-27

Delivered Owner/Reason/Expiry Waivers scoped to Finding IDs, Markdown Rule IDs,
and qualified Capability Gate IDs. Active Waivers suppress blocking only;
expired Waivers automatically reactivate enforcement. See
`docs/risk-waivers.md` and ADR-0058.


## Verification

```text
P2-28/Organization/Capability targeted: 23 passed
Ruff check: passed
Ruff format: passed — 272 files
Mypy strict: passed — 252 source files
Pytest: 1132 passed
Active Rule Waiver: Finding remains visible, blocking removed for waived scope
Expired Waiver: automatically inactive, blocking restored
Capability Gate Waiver seam: qualification/coverage checks remain before waiver
```
