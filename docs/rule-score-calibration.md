# AgentSec Rule and Score Calibration v1

- Task: `P2-31`
- Status: Complete
- Date: 2026-08-25
- Report Output: `0.1.0`
- Calibration generation: `v1`
- ADR: `docs/decisions/0060-pilot-driven-rule-score-calibration.md`

## Purpose

P2-31 turns P2-30 Pilot evidence into a deterministic Rule-by-Rule calibration
report and verifies that the complete P2-18 through P2-24 scoring chain still
matches its frozen replay suite.

It does not automatically edit or publish Rules, change risk mappings, or use an
LLM to authorize CI decisions.

## Run

```bash
PYTHONPATH=src .venv/bin/python scripts/run-rule-score-calibration.py \
  --agentsec .venv/bin/agentsec
```

The command performs two fresh replays:

1. all eight P2-30 Pilot scenarios through the real P2-29 CI Runner;
2. all seven P2-24 Agentic scoring replay cases.

It writes:

```text
calibration/pilot-rule-score/rule-score-calibration-report.json
calibration/pilot-rule-score/rule-score-calibration-report.md
```

Frozen Schema:

```text
schemas/calibration/rule-score-calibration-report.schema.json
```

## Rule calibration result

```text
Built-in Markdown Rules: 15
Positive Pilot coverage: 9
Rules requiring more data: 6
Rules requiring FP review: 0
Rules requiring FN review: 0
Pilot FP/FN: 0/0
```

The nine positively covered Rules retain their current deterministic condition
and reviewed risk profile. These six Rules have no positive P2-30 Pilot scenario
and remain `more_data`:

```text
MD-DESTRUCT-001
MD-EXEC-002
MD-MEMORY-001
MD-OBFUSC-001
MD-PRIV-002
MD-SELF-001
```

`more_data` does not disable a Rule, lower its Severity, remove CI eligibility,
or imply that the Rule is incorrect. Existing unit, corpus, and integration
regression tests remain active.

## Score calibration result

The fresh seven-case score replay exactly matches the frozen suite:

```text
critical-gate-floor
cvss-high-water
incomplete-coverage
remediation-drift
risky-default
risky-reviewed
safe-no-change
```

Coverage includes:

```text
Critical Hard Gate floor
CVSS high-water score
Incomplete Coverage
Risk remediation
Default risky governance context
Reviewed risky governance context
Safe no-change state
```

Every stage remains bound by its existing SHA-256 fingerprints.

## Version decision

P2-31 makes no semantic Rule or scoring modification:

```text
Rule Pack current/candidate: 0.3.0 / 0.3.0
Risk Model current/candidate: 0.4.0 / 0.4.0
Rule Pack action: retain_current
Risk Model action: retain_current
publish_rule_changes: false
publish_score_changes: false
internal_mvp_ready: true
external_calibration_required: true
```

Changing a version without evidence would imply semantics changed when they did
not. Future FP/FN or scoring-policy evidence requires a separate ADR and version
impact review.

## Limitations

- Pilot evidence is curated internal-integration evidence;
- six Rules lack a positive Pilot scenario;
- score replay proves deterministic stability, not financial-loss calibration;
- static findings do not prove runtime reachability or exploitability;
- 100% Pilot Precision/Recall must not be generalized to production.

## P2-32 handoff

P2-32 may package the retained Rule Pack `0.3.0`, Risk Model `0.4.0`, P2-31
calibration report, P2-30 Pilot report, Organization Policy, CI examples, SARIF,
and known limitations into the internal MVP release candidate.
