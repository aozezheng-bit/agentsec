# Release Agent Demo Acceptance Record

- Release: AgentSec 0.1.0
- Date: 2026-08-19
- Status: Accepted for the local Phase 1 PoC release
- Audiences: developers and management

## Common acceptance

| Criterion | Result |
|---|---|
| Runs in under eight minutes | Pass |
| Uses the normal CLI and production engines | Pass |
| Requires no external network service | Pass |
| Contains no real credential, endpoint, or personal data | Pass |
| Executes no scanned Script, Hook, Skill, command, or MCP declaration | Pass |
| Can write live output to a fresh temporary directory | Pass |
| Has deterministic fixed-metadata offline output | Pass |
| Frozen output is protected by SHA-256 checksums | Pass |

## Developer acceptance

| Criterion | Result |
|---|---|
| Safe baseline has Complete Coverage and zero Findings | Pass |
| Risky drift shows two modified Assets | Pass |
| Risky scan produces direct file/line Evidence | Pass |
| JSON validates as Assessment Output 0.2.0 | Pass |
| Prompt Injection remains input data | Pass |
| Malformed input is Incomplete with exit `2` | Pass |
| Remediation returns to zero current Findings | Pass |
| Risky Findings still return exit `0` under report-only policy | Pass |

## Management acceptance

A viewer can answer:

1. Two control Assets changed.
2. The drift declares shell, credential, network, production, deployment, hidden
   instruction, and executable-tool behavior while weakening approval.
3. The potential blast radius includes release integrity, deployment credentials,
   production systems, and external data exposure.
4. AgentSec does not enforce a block; the human recommendation is to hold the
   release until remediated.
5. Ten Findings across nine Rule IDs provide file/line Evidence.
6. Restore approval and local review behavior; remove shell, credential, network,
   production, hidden, deployment, and executable-reference declarations.
7. The PoC does not prove runtime capability or global Agent safety.

## Policy confirmation

```text
enforcement_mode=report_only
ci_blocking_enabled=false
global_safety_claimed=false
```

No Demo command uses an unsupported enforcing option.
