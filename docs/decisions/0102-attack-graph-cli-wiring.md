# ADR-0102: Attack Graph CLI Wiring

- Status: Accepted
- Date: 2026-08-31
- Task: P3-AG-04B
- Scope: safe application and CLI composition of the static Attack Graph report

## Context

P3-AG-01 through P3-AG-04 provide typed graph contracts, a Manifest builder,
a deterministic path matcher, and a value-free Text/JSON report. Those APIs
were not reachable through the installed `agentsec` command, so developers could
not run Attack Path analysis on a Homi workspace without writing custom Python.

## Decision

Add `DeterministicAttackGraphAnalysisEngine` as the application seam. It accepts
the existing `AgentAnalysisRequest`, runs the existing `AgentAnalysisPipeline`,
builds a graph from the validated Manifest, attaches paths using
`AttackPathMatcher`, and creates the P3-AG-04 report. The CLI adapter
`agentsec attack-graph PROJECT` only parses options, renders the validated report,
and delegates safe artifact output to `ReportArtifactWriter`.

The CLI supports Text and canonical JSON output, explicit project/user/Codex
roots, stable Agent ID input, no-clobber output, and same-kind validated
`--force` replacement. Incomplete Manifest Coverage maps to exit `2`; graph or
required analysis failures map to exit `5`; artifact failures map to exit `4`.

## Authority boundary

The command and application service preserve:

```text
report_only=true
blocks=false
runtime_verified=false
reachability=not_proven
exploitability=not_proven
finding_authority=false
rule_publication_authority=false
policy_authority=false
ci_authority=false
hard_gate_authority=false
release_authority=false
```

No semantic model or live Provider is invoked. No Finding is created or changed.
No Rule Pack, Policy, Hard Gate, or CI decision is modified.

## Consequences

### Positive

- Homi and Codex developers can run the complete static Attack Graph path from
  the installed CLI.
- The application seam is injectable and independent of Typer.
- Existing path/report contracts remain the source of truth.
- Output artifacts receive the existing bounded, atomic, same-kind validation.

### Trade-offs

- P3-AG-04B does not associate paths with Findings; that remains P3-AG-05.
- Static paths do not prove runtime reachability or exploitability.
- Two pattern families remain vocabulary-only until the Manifest builder emits
  `writes_to` and `installs` edges.
- A new Candidate distribution must be rebuilt and inspected before claiming
  the installed package contains this CLI.

## Rejected alternatives

- Put graph traversal in the Typer command: rejected; CLI adapters must not own
  analysis semantics.
- Add a new graph JSON format: rejected; P3-AG-04 canonical report remains the
  only report contract.
- Let a graph path block CI: rejected; static Attack Graph output remains
  report-only and deterministic Policy remains the enforcement authority.
