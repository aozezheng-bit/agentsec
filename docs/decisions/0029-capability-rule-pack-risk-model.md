# ADR-0029: Independent Capability Rule Pack and Risk Model 0.1.0

- Status: Accepted
- Date: 2026-08-20
- Task: P2I-02
- Capability Rule Pack: `0.1.0`
- Capability Risk Model: `0.1.0`
- Agent Manifest Schema: `0.3.0` (unchanged)

## Context

P2-08 through P2-11 produce a final Agent Manifest with normalized tools,
permissions, controls, credential-free runtime identities, relationships,
Unknowns, Coverage, and source provenance. Phase 1 Markdown Rules cannot safely
represent combinations across those structured facts because their `RuleContext`
is intentionally asset-local and text-oriented.

A combination engine must detect conditions such as execution plus secret access
plus external network without treating every Agent-wide fact as mutually
reachable. It must also keep Severity and Evidence Confidence independent,
preserve incomplete Coverage, avoid secret-bearing evidence, and remain
report-only.

The Phase 1 Rule Pack `0.3.0` and Risk Model `0.4.0` are already released
interfaces. Silently inserting structured capability meanings into those
versions would make existing Markdown assessments semantically ambiguous.

## Decision

1. Introduce an independent `agentsec.capability_rules` package whose Rule
   context contains only a finalized `AgentManifest` and deterministic indexes.
2. Add independent versions:

   ```text
   CAPABILITY_RULE_PACK_VERSION = 0.1.0
   CAPABILITY_RISK_MODEL_VERSION = 0.1.0
   ```

3. Keep Phase 1 `RULE_PACK_VERSION = 0.3.0` and
   `RISK_MODEL_VERSION = 0.4.0` unchanged.
4. Add six initial stable Rule IDs:

   ```text
   CAP-APPROVAL-001
   CAP-CHAIN-001
   CAP-COVERAGE-001
   CAP-DELEGATE-001
   CAP-EXTERNAL-001
   CAP-PERSIST-001
   ```

5. Use correlation precedence rather than an Agent-wide Cartesian product:

   ```text
   same target
   parent/child tool family
   same source declaration
   explicit relationship
   Agent-wide declaration
   incomplete Coverage / relevant Unknown
   ```

   The first built-in pack emits same-target, parent/child, Agent-wide, and
   incomplete/Unknown correlations. Same-source and explicit-relation values are
   reserved in the public vocabulary for reviewed future Rules.
6. Map correlation to Evidence Confidence:

   | Correlation | Confidence |
   |---|---|
   | Same target | B |
   | Parent/child tool family | C |
   | Same source | C |
   | Explicit relation | C |
   | Agent-wide | D |
   | Incomplete Coverage / relevant Unknown | D |

7. Map correlation scope to reviewed static likelihood independently from
   Confidence:

   | Correlation | Likelihood |
   |---|---|
   | Same target / parent-child / same source / explicit relation | Moderate |
   | Agent-wide / incomplete analysis | Low |

   Correlation affects likelihood because it represents a reachability
   precondition. Confidence is still reported separately and is never a score
   multiplier or downgrade.
8. Reuse the existing explicit NIST SP 800-30 likelihood-impact matrix, NIST
   semi-quantitative values, AgentSec representative scores, FIPS-style
   high-water-mark impact, and FIRST CVSS qualitative Severity ranges. Record the
   additional capability-correlation policy in every Finding's mapping basis.
9. Store one reviewed impact vector per Capability Rule. Compute overall impact
   by high-water mark and never average impact dimensions or Findings.
10. Keep the first release report-only:

    ```text
    hard_gate = false
    CI blocking = false
    ```

    No P2I-02 Rule emits Critical or activates a Hard Gate. Future gate
    conditions require a separate ADR and Capability Risk Model version change.
11. Retain value-free evidence only:

    ```text
    scope
    root_id
    relative path
    field_path
    line range
    content_sha256
    ```

    Do not require an excerpt and do not serialize commands, endpoints, Header
    values, environment-variable values, credentials, or parsed source values.
12. Execute Rules with per-Rule atomic failure isolation. A failed Rule emits no
    partial Findings from that Rule, does not hide other Rule results, and makes
    the Rule run incomplete.
13. Provide reviewed English and Simplified Chinese titles, descriptions, and
    remediation recommendations for every built-in Rule.
14. Keep processing deterministic and free of filesystem, shell, network, MCP,
    environment, memory-store, import, or LLM dependencies.

## Consequences

### Positive

- Structured capability combinations no longer depend on Markdown keyword
  proximity.
- Same-target and parent/child evidence is distinguished from Agent-wide
  inference.
- Agent-wide fallback produces at most one combination Finding per Rule path
  instead of a Cartesian explosion.
- Severity, Confidence, correlation, limitations, versions, and evidence remain
  independently reviewable.
- Incomplete Coverage can never be presented as a complete capability
  assessment.
- Phase 1 release semantics remain frozen.

### Negative

- The initial pack is deliberately small and cannot recognize every capability
  taxonomy or cross-Agent path.
- Delegation and persistence Rules are Agent-wide D-confidence findings until
  independently resolved Sub-Agent and memory-flow manifests exist.
- Static identity and permission declarations do not prove runtime grants,
  reachability, or successful exploitation.
- Capability Findings do not yet have a public JSON/Text report wrapper or CLI;
  P2I-03 and P2I-04 own those delivery contracts.
- No Hard Gate or CI enforcement is active in P2I-02.
