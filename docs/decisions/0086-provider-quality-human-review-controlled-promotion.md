# ADR-0086: Provider Quality, Human Review, and Controlled Shadow Promotion

- Status: Accepted
- Date: 2026-08-31
- Task: P3-05

Provider promotion requires deterministic quality thresholds, independent Human
Review A/B, adjudication for disagreements, and an explicit owner approval.
The only promotable state is `approved_shadow`; no state grants production,
Policy, CI, Hard Gate, runtime, Rule, or release authority.
