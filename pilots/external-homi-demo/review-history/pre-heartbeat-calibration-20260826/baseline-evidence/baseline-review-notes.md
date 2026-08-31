# Baseline Review Notes

These notes separate deterministic scanner output from human interpretation. They
are not independent TP/FP/FN labels and do not change the report.

## Candidate calibration issue: HEARTBEAT template classification

The supplied `HEARTBEAT.md` is documentation-style content. It contains a fenced
example telling the operator to keep the file empty to skip API calls, plus a
Related-documentation link. It does not contain a concrete periodic task such as
an inbox, calendar, network, or message action.

The current Homi Profile classified it as:

```text
heartbeat_schedule = present
tasks_present = true
```

This activated `HOMI-COMB-002` and produced a declared simulation path. This is a
**candidate false positive / parser-classification calibration item**, not a
confirmed runtime risk. P2-EXIT-06-03 or the next Homi rule-tuning task should
add a near-miss fixture for fenced/comment-only Heartbeat templates and determine
whether the correct state is `example_only` or structurally disabled.

## Candidate calibration issue: template placeholders

`IDENTITY.md` and `USER.md` contain fill-in guidance and placeholder fields. The
Profile correctly records template presence, but some lexical signals contribute
to self-modification and persistence combinations. These findings remain
Confidence D and report-only. Human review should determine which signals are
intended platform behavior and which are template-only near misses.

## Likely valid policy observation

`AGENTS.md` prioritizes runtime-provided startup context and discourages default
manual rereads, while `SOUL.md` broadly says continuity files should be read each
session. The deterministic `startup_read_policy_conflict` observation is
traceable and AGENTS.md precedence resolves the authority question. Whether this
should make the whole Profile `partial` is a separate product-policy decision.

## Review status

```text
independent reviewer labels complete = false
TP/FP/FN adjudication complete = false
runtime verification complete = false
```
