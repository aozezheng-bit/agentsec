# P2-EXIT-06-05A: External Human Review False-negative Calibration

- Status: Complete
- Date: 2026-08-26
- Parent: P2-EXIT-06-05
- ADR: `docs/decisions/0081-external-human-review-rule-pack-patch.md`

## Human Evidence validation

```text
Reviewer ID                 codefuse-agentsec-expert-reviewer
Review status               complete
Cases                       20/20
Manifest binding            valid
Submission digest binding   valid
Human Label digest binding  valid
Independent statement       present
```

## First reviewed Replay

```text
Passed Cases   19/20
TP             21
FP             0
FN             4
Precision      1.00
Recall         0.84
```

Only `baseline-01` differed. Exit and Coverage decisions agreed; the scanner
missed four Expert-supported Rule declarations.

Evidence:

```text
pilots/external-homi-demo/final-pilot/review-diagnostics/
  pre-calibration-pilot-report.json
  pre-calibration-gap-report.json
```

## Calibration decision

```text
Preserve independent Human Labels       yes
Automatically rewrite labels            no
Patch deterministic Rule triggers       yes
Rule Pack                               0.3.0 → 0.3.1
Risk Model change                       no
Policy/CI authority change              no
```

## Required completion

- exact Homi baseline regression passes;
- all existing safe/risky corpus tests pass;
- engineering external Pilot is regenerated;
- reviewed final Replay reaches 20/20 with FP=0 and FN=0;
- P2-EXIT-08A is rerun using the final accepted Pilot report.


## Completion result

Rule Pack `0.3.1` added bounded coverage for the four Expert-supported
statements without changing Rule IDs, risk scores, Confidence, Policy scope, or
CI authority.

```text
Reviewed Replay Cases  20/20 passed
TP                     25
FP                     0
FN                     0
Precision              1.0
Recall                 1.0
Acceptance ready       true
Phase 3 Entry           ready_for_candidate
```

Durable evidence:

```text
pilots/external-homi-demo/final-pilot/review-diagnostics/
pilots/external-homi-demo/review-history/rule-pack-0.3.1-engineering-replay/
pilots/external-homi-demo/final-pilot/final-results/
```


## Completion verification record

```text
Ruff check              pass
Ruff format             pass; 1001 files
Strict configured Mypy pass; 293 source files
Full Pytest             1301 passed
Package hardening       pass
Reproducible build      byte_identical=true
Wheel SHA-256           23c12df2886c6237a85eb8f9b8d3f07b43c8d4f90aa431e0e5e0bb8fe10f69a7
sdist SHA-256           d4ffbfe4cca76a16ca334608bab6458af71057161f8492e6e57a5cc42a4869bd
Artifact signature      not_claimed
SLSA provenance         not_claimed
```
