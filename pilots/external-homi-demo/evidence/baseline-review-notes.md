# Baseline Review Notes After P2-EXIT-06-03A

These notes separate deterministic scanner output from human interpretation.
They are not independent TP/FP/FN labels.

## Heartbeat template calibration: resolved

The supplied `HEARTBEAT.md` is documentation-style content: a fenced example
instructs the operator to keep the file empty and add tasks later, followed by a
Related-documentation link. It contains no concrete periodic action.

After P2-EXIT-06-03A the deterministic classification is:

```text
Homi file state                 example_only
heartbeat_schedule              example_only
Evidence method                 static_template_classification
tasks_present                   false
api_calls_enabled_by_file       false
HOMI-COMB-002                   not emitted
HOMI-SIM-001                    blocked_example_only
runtime_verified                false
```

The active PR-03 snapshot contains concrete email, calendar, and weather tasks
and now produces:

```text
heartbeat_schedule              example_only → present
HOMI-COMB-002                   added
HOMI-SIM-001                    blocked_example_only → declared_path
```

This closes the detection-saturation issue recorded before calibration. The old
reports are preserved under
`review-history/pre-heartbeat-calibration-20260826/`.

## Remaining template calibration candidates

`IDENTITY.md` and `USER.md` still contain fill-in guidance and placeholder
fields. Their self-modification and persistence signals remain Confidence D and
report-only. Independent human TP/FP/FN review is still required in
P2-EXIT-06-05.

## Review status

```text
Heartbeat engineering calibration complete = true
Independent reviewer labels complete       = false
TP/FP/FN adjudication complete              = false
Runtime verification complete               = false
```
