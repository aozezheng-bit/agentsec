# ADR-0049: Shadow Gate Demo and Coverage Report

- Status: Accepted for source development; Shadow-only
- Date: 2026-08-24
- Task: `P2-15A-PILOT-03`
- Depends on: ADR-0037, ADR-0038, ADR-0039, ADR-0048
- Demo Report Schema: `0.1.0`
- Enforcement: report-only

## Context

P2-15A-PILOT-02 proves that `HG-CAPCHAIN-001` can evaluate a deterministic
Capability Finding without changing risk or enforcement. Developers and
management still need a reproducible way to see both sides of the decision:

```text
why an explicit chain matches;
why Agent-wide, Unknown, and incomplete-Coverage cases do not match;
how much calibration coverage exists;
what the seeded Matrix expects before real human review.
```

The demo must not execute scanned assets or treat seeded Matrix labels as human
approval.

## Decision

1. Add `scripts/run-shadow-gate-demo.py` as the P2-15A-PILOT-03 report CLI.
2. Add `scripts/run-shadow-gate-demo.sh` as the presenter-friendly wrapper.
3. Construct five inert deterministic scenarios in memory/temp storage:
   same-target match, parent-child match, Agent-wide no-match, Unknown
   no-match, and incomplete-Coverage no-match.
4. Reuse the existing bounded Gate Coverage Check for Corpus/Matrix validation
   rather than duplicating its trust and path-safety rules.
5. Add Matrix expected Match/No-match rows to the report as value-free metadata:
   case IDs, case kinds, conditions, Coverage, Unknown flags, review status,
   language, source format, semantic fingerprint, and safe source asset path.
6. Add report format `agentsec-capability-shadow-gate-demo`, version `0.1.0`,
   with strict explicit boundaries for Shadow-only operation.
7. Return exit code `0` when the Demo passes and Coverage is ready; return `2`
   when the Demo passes but Coverage needs more data; return `4` for invalid
   input/output; return `5` for a Demo contract failure.
8. Keep all output private and non-clobbering with `O_EXCL` and mode `0600`.
9. Do not count seeded Matrix metadata as Human Evidence, do not calculate
   precision/recall from it, and do not use it to qualify a formal P2-15A Gate.

## Alternatives rejected

### Use only the existing Coverage Check

Rejected. Coverage statistics do not demonstrate the live Shadow Gate decision
path or explain match/no-match rejection reasons.

### Use only a live demo

Rejected. A live demo without Corpus/Matrix coverage leaves sample sufficiency
and Unknown boundaries implicit.

### Execute real project fixtures or MCP servers

Rejected. Demo assets remain untrusted data. The demo uses inert static inputs and
never executes scanned code, network, commands, Skills, Hooks, or MCP servers.

### Treat seeded expected labels as reviewer outcomes

Rejected. Seeded Matrix values are expected calibration metadata. They are not
independent human review, Adjudication, Agreement, or P2-15A qualification.

## Consequences

### Positive

- The Shadow Gate behavior can be shown to developers and management in under a
  minute.
- Match/no-match reasons and Coverage/Unknown boundaries are visible in one
  machine-readable report.
- The report can be replayed offline and stored as a private artifact.

### Negative

- The report reflects static deterministic behavior only.
- Current Matrix rows remain seeded until independent human review is complete.
- Coverage readiness does not imply Gate precision, recall, runtime reachability,
  or production approval.

## Verification

```text
tests/test_shadow_gate_demo.py
  - five deterministic scenarios
  - 25/25 matrix Match/No-match distribution
  - 25 positive / 21 eligible negative coverage
  - Chinese Text output and secret boundary
  - private non-clobbering artifact output

scripts/check.sh
  - Ruff
  - Ruff format
  - strict Mypy
  - full Pytest
```
