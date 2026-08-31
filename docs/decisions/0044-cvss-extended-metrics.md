# ADR-0044: CVSS Temporal, Environmental, Threat, and Supplemental Metrics

- Status: Accepted
- Date: 2026-08-24
- Task: `P2-21`
- Depends on: ADR-0043

## Context

P2-20 calculates CVSS v4.0 Base Scores locally, but real vulnerability records
may also carry CVSS v3.1 Temporal/Environmental metrics or CVSS v4.0
Threat/Environmental/Supplemental metrics. Treating these values as unknown or
silently discarding them loses important provenance. Overwriting the Base Score
would make it impossible to distinguish intrinsic vulnerability severity from
context-dependent scoring.

The project needs one strict vector boundary, deterministic local calculation,
and a report model that retains both Base and effective extended results.

## Decision

1. Upgrade the CVSS Adapter from `0.2.0` to `0.3.0`.
2. Extend vector parsing with the supported v3.1 Temporal/Environmental and
   v4.0 Threat/Environmental/Supplemental metric groups.
3. Accept metrics in input order but emit them in the version's canonical order.
4. Keep Base Metrics mandatory and reject unknown or duplicate metrics.
5. Calculate v3.1 Temporal Score and Environmental Score locally, including
   Temporal multipliers when Environmental Metrics are present.
6. Calculate v4.0 Threat and Environmental effective scores using the local
   MacroVector calculator and modified metrics.
7. Retain v4.0 Supplemental Metrics as validated report data; they do not alter
   the numeric score in this task.
8. Add `effective_score`, `effective_severity`, and `score_type` to the nested
   Domain `CvssBase` object.
9. Keep `base_score` and Base Severity unchanged and separately visible.
10. Allow callers to provide expected Base and effective Score/Severity values;
    reject mismatches.
11. Increment `DOMAIN_SCHEMA_VERSION` from `0.5.0` to `0.6.0` and
    `ASSESSMENT_OUTPUT_VERSION` from `0.4.0` to `0.5.0`.
12. Keep AgentSec Risk Model, Evidence Confidence, Hard Gate, and CI semantics
    unchanged.

## Consequences

### Positive

- Existing CVSS extended vectors can be reused without discarding metrics.
- Base and context-dependent scores remain distinguishable.
- All calculated values have explicit local provenance.
- Supplemental data is retained without pretending it changes the score.
- Text and JSON consumers can explain why the effective score differs from the
  Base Score.

### Negative

- Domain and Assessment output versions change.
- The vector parser and calculator carry more standards-derived metric tables.
- CVSS v3.1 and v4.0 extended scoring must be maintained separately.
- Supplemental semantics beyond numeric retention remain future work.

## Rejected alternatives

### Replace Base Score with the effective score

Rejected because consumers need the intrinsic Base result and the contextual
result at the same time.

### Average Base and Environmental/Threat Scores

Rejected because these are different CVSS views, not independent AgentSec risk
signals to average.

### Treat Supplemental Metrics as numeric modifiers

Rejected for this task because Supplemental Metrics are retained as report data
and do not belong in the Base/Threat/Environmental numeric calculation here.

### Infer Temporal or Environmental values from scanner evidence

Rejected because untrusted static evidence cannot establish exploit maturity,
organizational requirements, or other external context.
