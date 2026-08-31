# ADR-0067: External Pilot Evidence Contract

- Status: Accepted for P2-EXIT-06 implementation
- Date: 2026-08-25
- Scope: report-only external Agent repository Pilot

## Context

The internal Pilot contract resolves every project and Policy path inside the
AgentSec repository. That is safe for checked-in integration fixtures but cannot
collect evidence from a real external Agent repository. Reusing the internal
fixture mode would either reject the real project or incorrectly represent an
internal Demo as external evidence.

P2-EXIT-06 requires at least 20 scan states, at least 10 pull-request states,
three deterministic exercises, independent human TP/FP/FN labels, and explicit
performance/Coverage evidence. The target repository must remain untrusted and
must not be able to select the Policy, Qualification, Waiver, or authorization
source.

## Decision

Extend the versioned Pilot contract `0.1.0` additively with:

- `scan_kind: baseline | pull_request`;
- explicit drill labels for risky change, incomplete Coverage, and Waiver
  lifecycle;
- external scope targets and required drill set;
- a separate bounded `agentsec-pilot-human-labels` `0.1.0` contract;
- `status=evidence_pending` until external scope and complete independent labels
  are present.

The runner receives these roots explicitly:

```text
AgentSec control root     owns the plan, labels, runner, and reports
--target-root             external Agent repository, untrusted input
--trust-root              protected Policy root, separate from target
```

External Policy paths are relative to `--trust-root`; target paths are relative
to `--target-root`. Both roots must be existing non-symlink directories and must
be different. A protected Policy digest can be passed through to the trusted
CI wrapper with `--expect-policy-sha256`.

The runner invokes only the AgentSec-controlled CI wrapper. It never executes
external project code, hooks, skills, commands, or MCP servers. Human labels
contain only expected exit, Coverage, and deterministic Rule IDs; they do not
replace scanner findings or grant CI authority.

## Alternatives rejected

1. **Copy the external repository into `testdata/`** — destroys external
   provenance and can hide path/trust-root failures.
2. **Discover Policy from the external project** — lets the target modify its
   own trust source.
3. **Use LLM labels or runtime claims** — violates Phase 2 authority boundaries.
4. **Mark the internal eight-case Pilot as external** — false evidence claim.
5. **Fail the collection run when labels are not yet available** — prevents
   report-only evidence collection; instead the report is explicitly pending.

## Consequences

Positive:

- real-project collection is possible without weakening trust-root separation;
- the report cannot be accepted accidentally before human review and scope
  completion;
- one CLI supports collection and reviewed acceptance runs;
- the external template is reproducible for a later project onboarding.

Trade-offs:

- the public Pilot schemas gain optional fields while retaining `0.1.0` because
  the additions are backward-compatible and existing internal artifacts remain
  valid;
- actual external acceptance still requires a project owner, protected Policy
  root, and independent Reviewer outside this repository.

## Authority boundary

This ADR does not add CI blocking, production authorization, runtime exploit
validation, LLM semantic analysis, automatic Rule publication, or Waiver
approval. Those remain outside the Pilot.
