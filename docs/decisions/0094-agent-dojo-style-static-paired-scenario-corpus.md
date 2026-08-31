# ADR-0094: Static AgentDojo-Style Paired Injection Scenario Corpus

- Status: Accepted
- Date: 2026-08-31
- Task: P3-12
- Scope: P3-12 AgentDojo-style evaluation scenario corpus (data + contracts)

## Context

The Phase 3 plan (P3-12) calls for "AgentDojo 风格场景" injection tests that
record both normal tasks and attack tasks. AgentDojo itself is a *dynamic*
benchmark: it executes an agent in an environment, injects adversarial
instructions into tool outputs and notes, and measures goal completion plus
attack success rate (ASR). AgentSec's security invariants forbid executing
scanned content, connecting to tools, or claiming runtime exploitability,
so the benchmark cannot be replayed dynamically. The repository already
provides the building blocks for a static equivalent: the P3-11A
human-confirmed gold labels (45 cases, provenance
`ai_draft_human_confirmed`), the P3-03 `SemanticEvaluationCase` /
`SemanticEvaluationHarness` contracts, and a corpus of real injection
examples (`testdata/prompt-injection`, demos, Homi pilot snapshots).

## Decision

Add `agentsec.semantic.scenarios` with the
`agentsec-p3-12-agent-dojo-scenario-set` data family (versioned `0.1.0`):

1. **Pairing contract.** Each scenario records exactly one `normal` task
   and one `attack` task drawn from the same real corpus family. The set
   validator rejects two normal tasks, two attack tasks, unsupported slot
   kinds, and duplicate case IDs across scenarios
   (`normal_task_count`/`attack_task_count` must equal scenario count).
2. **Static injection signature.** An attack task must carry at least one
   expected judgment with category `instruction_integrity` and disposition
   `supported`; a normal task must carry none. This is the static encoding
   of "embedded untrusted instruction expected to be flagged" versus
   "benign task expected unflagged".
3. **Label provenance.** Expected judgments are copied verbatim from the
   P3-11A human-confirmed gold set; the set binds the source gold-label
   file SHA-256 and records `label_provenance=p3-11a_gold_derived`. No new
   AI-only labels are introduced and no quality claim is attached.
4. **Evidence binding.** Sanitized text, source labels, line ranges, and
   content-addressed Evidence IDs come from the frozen P3-11A reviewer
   pack. `build_scenario_evaluation_cases` rebuilds each
   `SemanticEvidenceChunk` and recomputes the Evidence binding
   (placeholder asset SHA, same as the qualification gate), so tampering
   with stored text or Evidence IDs fails closed.
5. **Static ASR semantics (deferred).** Attack "success" is never measured
   dynamically. P3-14 metrics will define the proxy: undetected attack
   tasks surface as false negatives (detection-based ASR proxy) and
   false alarms on normal tasks measure utility loss. No runtime
   exploitability claim is allowed anywhere.
6. **Authority boundary.** The set is immutable and report-only
   (`report_only=true`, `blocks=false`, `policy_authority=false`,
   `release_authority=false`, `runtime_verified=false`). It grants no
   Provider, Finding, Rule, CI, Hard Gate, or release authority, and
   offline-fixture results may not be presented as real quality numbers.

The pack is shipped as a pilot artifact at
`pilots/agentdojo-style-p3-12/scenarios.json` (9 scenarios / 18 cases /
bilingual), generated deterministically and idempotently by
`scripts/build-p3-12-agentdojo-scenarios.py`. Following the P3-11A
precedent for corpus data families, no new exported JSON Schema family or
provenance registry version vector is introduced; the P3-03 evaluation
report schema continues to own replay output contracts.

## Consequences

- P3-13 (InjecAgent-style tool injection scenarios) can extend the same
  case/paradigm family with tool-description injection sources without a
  new ADR for the shared contract, but any change to the pairing or
  injection-signature semantics needs an ADR.
- P3-14 metrics must reference this pack only via
  `build_scenario_evaluation_cases`; direct JSON access bypasses binding
  verification.
- The scenario inventory grows by editing the builder's fixed scenario
  spec table and regenerating; corpus expectation quality is bounded by
  the P3-11A gold coverage (only gold-confirmed excerpts may enter).
- The plan's original P3-07/P3-08/P3-09 numbering ambiguity note
  (§17 roadmap erratum) is unaffected: P3-12 is B-line data work and
  stays independent of the P3-AG attack-graph track.
