# ADR-0011: Independent A/B/C/D Evidence Confidence and Risk Model 0.3.0

- Status: Accepted
- Date: 2026-08-19
- Task: P1-22

## Context

P1-21 produces `ScoredFinding` values with versioned Likelihood, Impact, score,
and Severity. The final Domain `Finding` also requires `EvidenceConfidence` and
hard-gate state.

Static Markdown matches can indicate high potential impact while providing weak
evidence that the declared capability exists or is reachable at runtime. If weak
confidence automatically lowers Severity, dangerous declarations can appear
safe. If lexical matches are described as verified behavior, the scanner creates
false assurance.

NIST SP 800-30 requires uncertainty and confidence to be communicated and ties
confidence to available information quality, quantity, and relevance. It does
not define an A/B/C/D Agent-scanning scale, so AgentSec must explicitly identify
its own engineering policy.

The project version vector has a Risk Model version but no independent
Confidence-model version. Confidence semantics therefore need a reviewed version
decision.

## Decision

Adopt these P1-22 decisions:

1. Introduce immutable `ConfidenceProfile`, `ConfidenceAssessment`, and
   `ConfidenceFinding` objects plus a `ConfidenceEngine` Protocol and
   `DeterministicConfidenceEngine` implementation.
2. Preserve `ScoredFinding` unchanged and attach Confidence in a new intermediate
   object rather than constructing the final Domain `Finding` before P1-23.
3. Keep hard-gate state absent; P1-23 retains ownership of that field.
4. Define A as runtime verification, stable red-team reproduction, actual tool
   enumeration, or signed attestation.
5. Define B as resolved effective configuration, deterministic structured-rule
   evidence, or a traceable source-code path.
6. Define C as LLM semantic analysis that retains exact evidence and structured
   context.
7. Define D as keyword, bounded regex, local context, parser indicator, static
   reference, or partial-scan inference.
8. Encode the source method to A/B/C/D mapping in one deterministic
   `confidence_for_method()` function.
9. Reject any profile or assessment whose method and declared level disagree.
10. Give every Rule Pack `0.2.0` Rule ID one explicit Confidence profile.
11. Assign all current built-in Markdown profiles D because none resolves
    effective runtime configuration or verifies execution.
12. Preserve method distinctions among keyword, regex, contextual lexical,
    parser indicator, and static reference evidence.
13. Permit bounded trusted Evidence field-prefix overrides only when prefixes are
    unique and non-overlapping. Use `reference:` for the `MD-TOOL-001` static
    reference method.
14. Never use scanned excerpt wording to upgrade Confidence.
15. Require non-empty trusted rationale and limitations in every profile and
    assessment.
16. Preserve score and Severity exactly. Confidence is neither a multiplier nor
    a reason to lower risk.
17. Reject unknown Rule IDs, category mismatches, duplicate profiles, and
    duplicate Finding IDs with fixed safe errors.
18. Keep assignment deterministic and free of filesystem, shell, network,
    scanned imports, Skill, MCP, and LLM dependencies.
19. Increment `RISK_MODEL_VERSION` from `0.2.0` to `0.3.0` because Confidence
    mapping changes the interpretation of a complete risk result.
20. Keep Domain Schema and Rule Pack versions at `0.2.0` because existing Domain
    confidence fields and Rule semantics do not change.

## Consequences

### Positive

- High potential impact remains High even when evidence is preliminary.
- Reviewers can distinguish a static lexical signal from effective configuration
  or runtime proof.
- Every grade is traceable to a specific evidence-production method, rationale,
  limitation, and version.
- Current Markdown rules no longer need an ambiguous default Confidence chosen by
  a reporter.
- Attacker-authored claims of verification cannot self-upgrade a Finding.
- P1-23 can add hard-gate metadata without changing risk or Confidence objects.

### Negative

- All current production Findings are D, so users must not mistake the first PoC
  for runtime validation.
- Stronger A/B/C levels require later parsers, resolvers, semantic analysis,
  runtime tests, or attestation infrastructure.
- The current Confidence Engine does not accept project-level Coverage as an
  input. This is safe for all-D built-ins but must be revisited before B/A output.
- Custom profiles are trusted scanner policy and can overstate Confidence if
  approved incorrectly; registry review and versioning remain necessary.
- Final Domain Findings and CLI reports remain blocked on P1-23 hard-gate
  metadata and later integration tasks.
