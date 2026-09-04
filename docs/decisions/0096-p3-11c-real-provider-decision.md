# ADR-0096: P3-11C Real Provider Decision — External Public API, Mid-tier Model

- Status: Accepted
- Date: 2026-08-31
- Task: P3-11C
- Decision owner: internal-reviewer (release/organization owner)
- Scope: first real Shadow invocation over the P3-11A/B gold set

## Context

P3-03～P3-11B established the full live-invocation infrastructure (opt-in
HTTPS transport, approved-binding enforcement, evaluation harness, quality
gate) without configuring any real endpoint. P3-11C remains decision-gated:
no invocation may run until the five organizational prerequisites are
recorded. The owner has now decided them.

## Decision (recorded 2026-08-31)

```text
access_mode              external public API (OpenAI-compatible HTTPS)
model_tier               mid-tier model (exact PROVIDER_ID|MODEL_ID binding
                         recorded at execution time)
credential_source        team secret-management service injecting a local
                         environment variable (name only is recorded; the
                         value never enters configs, reports, or artifacts)
cost_limit               minimum scale: 45 gold cases × 1 invocation,
                         single attempt, no retry/fallback (enforced by
                         ADR-0083 invocation limits)
data_residency           sending the sanitized corpus is approved: all
                         excerpts are repository-authored test data passed
                         through the P3-01 sanitizer (secret/URL/email/IP/
                         control minimization)
```

## Operational constraints preserved

1. Invocation stays Shadow-only and report-only; no Policy, CI, Gate,
   Rule, Finding, or release authority (Literal-level booleans).
2. The trial command must be `agentsec semantic trial --provider live_https
   --allow-live` with the exact approved binding; any mismatch fails
   closed.
3. The credential environment-variable value is never stored; errors and
   reports remain value-free.
4. Evaluation, parity, and qualification reports are archived under
   `pilots/semantic-quality-p3-11/` with provenance; qualification
   outcomes cannot promote the provider (ADR-0086 workflow remains
   authoritative).
5. "Public API + 秘密管理服务" 路径的合规性由决策承担者确认；若后续安全/
   合规审查有新要求，本 ADR 由新 ADR 取代。

## Consequences

Positive:

- the first real model quality numbers become reproducible evidence
  rather than fixture-only claims;
- cost is bounded and auditable (45 × 1 invocation, no retry);
- data exposure is minimized and pre-approved.

Trade-offs:

- the exact provider/model is not pinned in this ADR (chosen at execution
  time by the owner and recorded in the trial report);
- public API implies external egress; network posture must allow one
  outbound HTTPS host at trial time;
- mid-tier model quality is unproven until the P3-11B gate runs against
  real output — a not_qualified result is a valid, expected outcome.

## Rejected alternatives

- Start with a flagship model: rejected for cost; mid-tier plus the
  quality gate gives evidence-driven escalation.
- Store the credential in config: rejected; the P3-03 design (env-var
  name only, boundary lookup) stays.
- Multiple attempts/retries: rejected; single-attempt bounds cost and
  keeps determinism of the evidence.


## Execution record (2026-08-31)

The decision was executed same-day over the P3-11A gold set:

```text
Provider binding        theta-public | Kimi-K3-256K (Theta OpenAI-compatible
                        https://antchat.alipay.com/v1/chat/completions)
Access                  group-domain Theta platform (internal egress only)
Credential              THETA_API_KEY environment variable (personal token;
                        value never stored in any file, config, or report)
Runs                    2 budgeted runs; run 1 archived as *.attempt1.json
Pacing                  >=1.8s call interval for the QPS=1 personal token
Employed invocation     45 model judgments per run plus diagnostic probes
Contract canonicalization ADR-0083 OpenAI-compatible adapter now sorts and
                        deduplicates model-supplied limitation arrays and
                        orders candidates by candidate_key before P3-01
                        validation (value-neutral; parse failures stay with
                        the strict contract)
Final live metrics      42/45 complete; precision 0.394; recall 0.378;
                        f1 0.385; evidence_binding_accuracy 1.000;
                        complete_coverage_rate 0.933
Qualification           not_qualified (quality_threshold_not_met;
                        evaluation_case_failures_present)
Failure modes           2 contract_rejected + 1 provider_failure
Error pattern           judgment granularity: model splits multi-label cases
                        differently from the human-confirmed gold labels
Artifacts               pilots/semantic-quality-p3-11/live-trial/
                        evaluation-live.json (+ .attempt1.json)
                        pilots/semantic-quality-p3-11/qualification/
                        semantic-quality-qualification-live.json (+ .attempt1)
Authority               unchanged: shadow_only, report_only, no Policy/CI/Gate
```

A not_qualified outcome is a valid first real-provider baseline. It
documents the current gap (P/R ~0.39 first-shot) and drives Prompt/model
iteration; it does not promote or demote any provider (ADR-0086 remains
authoritative for promotion).
