# P2-31: Rule and Score Calibration

- Status: Complete
- Date: 2026-08-25
- Depends on: P2-30

Replayed all eight Pilot scenarios and seven frozen Agentic scoring cases. Nine
of fifteen Markdown Rules have positive Pilot coverage with no FP/FN and retain
their current profiles. Six uncovered Rules remain `more_data`. The frozen
scoring chain matches exactly.

Decision:

```text
Calibration generation: v1
Rule Pack: retain 0.3.0
Risk Model: retain 0.4.0
Automatic Rule publication: false
Automatic score publication: false
Internal MVP ready: true
External calibration still required: true
```

## Verification

```text
Pilot replay: 8/8 passed
Scoring replay: 7/7 exact match
Markdown Rules evaluated: 15
Retain current / More data: 9 / 6
Pilot FP/FN: 0 / 0
P2-31 targeted tests: 5 passed
P2-30/P2-31/Scoring targeted suite: 28 passed
Ruff check: passed
Ruff format: passed — 739 files
Mypy strict: passed — 257 source files
Pytest: 1148 passed
```

## Boundary

`internal_mvp_ready=true` means the current deterministic versions passed the
internal evidence gate. It does not convert internal Pilot metrics into
production accuracy and does not remove the requirement for external
calibration after release.
