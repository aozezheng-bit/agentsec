# ADR-0056: Explicit High/Critical Severity `--fail-on`

- Status: Accepted
- Date: 2026-08-25
- Task: P2-26
- Fail-On Policy: `0.1.0`
- Fail-On Report Output: `0.1.0`
- SARIF Reporter: `0.2.0`

## Context

AgentSec has stable exit code `1` reserved for risk-policy blocking, deterministic
Finding Severity, explicit Coverage status, SARIF output, and a separate
qualified Capability Gate enforcement command. The P2-26 requirement is to make
the main scan usable in CI with `high` and `critical` thresholds.

The implementation must not:

- turn default scans into blocking scans;
- use SARIF `level` as policy authority;
- allow incomplete Coverage to appear as a clean allow or authoritative block;
- use Confidence to lower Severity;
- bypass Capability Gate Qualification;
- silently introduce organization defaults before P2-27;
- mutate the existing canonical Assessment JSON contract unnecessarily.

## Decision

1. Add only this command surface in P2-26:

   ```text
   agentsec scan PROJECT --fail-on high
   agentsec scan PROJECT --fail-on critical
   ```

2. Keep `--fail-on` optional and CLI-only. Absence preserves exact report-only
   scan behavior.
3. Support only `high` and `critical`:

   ```text
   high     → High + Critical Findings
   critical → Critical Findings only
   ```

4. Evaluate final AgentSec Finding Severity. Do not evaluate numeric score,
   Evidence Confidence, SARIF level, CVSS score, LLM output, or runtime state.
5. Make Coverage precedence explicit:

   ```text
   incomplete → exit 2, blocks=false
   threshold match with complete Coverage → exit 1
   no threshold match with complete Coverage → exit 0
   ```

6. Keep matched Finding IDs sorted and unique. Do not copy evidence excerpts or
   source values into the decision.
7. Add strict `FailOnDecision`, versioned as `0.1.0`, with threshold, basis,
   decision, exit code, Coverage, block state, highest observed Severity,
   matched Finding IDs, and trusted rationale.
8. For Text, prepend a trusted decision summary and render the Assessment with
   an explicit fail-on Policy header.
9. For JSON, create an independent wrapper:

   ```text
   format = agentsec-assessment-fail-on
   format_version = 0.1.0
   ```

   It embeds the unchanged canonical Assessment Output and a strictly validated
   decision. The decoder recomputes the decision and rejects inconsistency.
10. For SARIF, record the decision in run/invocation/Result properties. The
    SARIF Reporter advances `0.1.0 → 0.2.0`.
11. Do not add `--fail-on` to `capability assess`. Capability blocking remains
    behind `capability enforce --policy` and accepted Gate Qualification.
12. Keep Config Schema, Domain Schema, Assessment Output, Rule Pack, Risk Model,
    CVSS Gate, and Capability contracts unchanged.
13. Add `FAIL_ON_POLICY_VERSION=0.1.0` and
    `FAIL_ON_REPORT_OUTPUT_VERSION=0.1.0`.

## Security boundaries

- scanned content cannot select or change the threshold;
- policy evaluation has no Shell, filesystem-write, network, MCP, model, or
  runtime-identity dependency;
- static Severity blocking is not described as runtime exploitability proof;
- D Confidence does not reduce High/Critical Severity;
- incomplete Coverage wins over risk threshold matches;
- Result IDs, not source excerpts, are retained in the decision;
- LLM and SARIF consumers have no authorization authority;
- organization policy and waivers require later explicit contracts.

## Consequences

### Positive

- CI can use stable exit code `1` without parsing Text or SARIF levels;
- `high` and `critical` have simple reviewable semantics;
- default users retain report-only behavior;
- JSON and SARIF retain machine-readable decision provenance;
- the canonical Assessment Output and frozen release artifacts do not need a
  schema/version change;
- Capability Qualification remains protected.

### Trade-offs

- the JSON output format differs when `--fail-on` is enabled because it becomes
  a decision wrapper;
- only AgentSec Severity is supported; CVSS and Overall Score thresholds remain
  deferred;
- policy must be repeated on each invocation until P2-27 adds organization
  configuration;
- P2-26 has no waiver mechanism; P2-28 must add Owner/reason/expiry governance.
