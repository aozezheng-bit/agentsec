# ADR-0058: Expiring Finding/Rule/Gate Risk Waivers

- Status: Accepted
- Date: 2026-08-25
- Task: P2-28

## Decision

1. Add `waivers` to Organization Policy Schema `0.2.0`.
2. Require `waiver_id`, `owner`, `reason`, `expires_on`, and at least one
   Finding/Rule/Gate selector.
3. Treat expiry as inclusive through the named date.
4. Waivers remove blocking only; they never remove Findings, evidence, or Gate
   matches.
5. Expired Waivers remain auditable and automatically lose effect.
6. A Gate Waiver cannot bypass Qualification, Coverage, or Unknown checks.
7. Record evaluation date, applied/expired Waiver IDs, waived Findings, and
   remaining blocking Findings in JSON/Text/SARIF.
8. Advance Organization Assessment `0.1.0 → 0.2.0`, SARIF Reporter
   `0.3.0 → 0.4.0`, and Capability CI Output `0.2.0 → 0.3.0`.
9. Keep Rule, Severity, Confidence, Gate qualification, and runtime boundaries
   unchanged.
