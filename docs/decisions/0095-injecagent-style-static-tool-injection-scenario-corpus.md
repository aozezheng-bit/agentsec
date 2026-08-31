# ADR-0095: Static InjecAgent-Style Tool-Injection Scenario Corpus

- Status: Accepted
- Date: 2026-08-31
- Task: P3-13
- Scope: P3-13 InjecAgent-style tool-injection evaluation scenario corpus

## Context

The Phase 3 plan (P3-13) calls for "InjecAgent 风格场景" tool injection
tests that record attack success rate. InjecAgent is a *dynamic*
benchmark: it embeds malicious instructions inside tool/API descriptions
and tool outputs of an executing tool-integrated agent, then observes
the real tool calls the agent makes (data forwarding, privilege
escalation, secret disclosure, destructive actions) to compute attack
success rates. AgentSec's invariants forbid executing scanned content or
claiming runtime tool reachability, so the benchmark cannot be replayed
dynamically.

P3-12 (ADR-0094) established the paired-scenario paradigm with an
instruction-integrity static signature for the AgentDojo adaptation, and
explicitly anticipated that P3-13 would extend the shared task-case
family while needing a new ADR once the injection-signature semantics
change — which they do: InjecAgent's distinguishing channel is the
*tool description / tool-integration surface*, not top-level agent
instructions.

## Decision

Add the `agentsec-p3-13-injecagent-scenario-set` data family (versioned
`0.1.0`) inside `agentsec.semantic.scenarios`, reusing the P3-12
`ScenarioTaskCase` / `ScenarioTaskKind` case paradigm and the shared
fail-closed Evidence-rebinding conversion:

1. **Tool-integration static signature.** An attack task must carry at
   least one expected judgment with category in {`code_execution`,
   `network_access`, `external_tooling`, `secret_access`,
   `destructive_action`} and disposition `supported`; a normal task must
   carry none. This is the static encoding of "injected instruction
   expected to commandeer tool use" versus "benign task expected to keep
   tool integration unflagged", complementary to P3-12's
   `instruction_integrity` signature.
2. **Intent taxonomy.** `InjecAgentIntent` maps the benchmark's two
   intent families onto static corpus facts: privacy attacks become
   `secret_disclosure`, taint forwarding becomes `data_forwarding`, and
   the remaining tool-integration intents are recorded as
   `tool_commandeering`, `external_tool_binding`, `destructive_action`,
   and `multi_capability_chain` (aggregated multi-capability injection).
3. **Pairing and provenance.** Each scenario pairs one benign normal
   task and one attack task; the set validator rejects unpaired slots,
   duplicate case IDs, and mismatched counts. Expected judgments are
   copied verbatim from the P3-11A human-confirmed gold set with
   `label_provenance=p3-11a_gold_derived` and the source gold file
   SHA-256 recorded. Two normal cases are intentionally shared with the
   P3-12 pack (same corpus, different pairing lens); case IDs must be
   unique only within a set.
4. ** Conversion.** `build_injecagent_evaluation_cases` shares the P3-12
   conversion path (rebuilt `SemanticEvidenceChunk` with recomputed
   content addressing), so tampered text or Evidence IDs fail closed.
   The converter requires the `InjecAgentScenarioSet` type and is
   separate from `build_scenario_evaluation_cases` to keep both pack
   contracts explicit.
5. **Static ASR semantics (deferred).** InjecAgent's dynamic attack
   success rate cannot be reproduced. P3-14 will compute the
   detection-based proxy: undetected attack tasks surface as false
   negatives, and false alarms on normal tasks measure utility loss. No
   runtime tool reachability, tool-call observation, or exploitability
   claim is allowed.
6. **Authority boundary.** The set is immutable and report-only
   (`report_only=true`, `blocks=false`, `policy_authority=false`,
   `release_authority=false`, `runtime_verified=false`); it grants no
   Provider, Finding, Rule, CI, Hard Gate, or release authority.

The pack is shipped as a pilot artifact at
`pilots/injecagent-style-p3-13/scenarios.json` (7 scenarios / 14 cases /
bilingual, six intents), generated deterministically and idempotently by
`scripts/build-p3-13-injecagent-scenarios.py`. Following the P3-11A
corpus-data precedent, no new exported JSON Schema family or provenance
registry version vector is introduced; the P3-03 evaluation report schema
continues to own replay output contracts.

## Consequences

- P3-14 metrics work can consume both packs
  (`build_scenario_evaluation_cases` and
  `build_injecagent_evaluation_cases`) to compute Instruction-channel and
  Tool-channel detection proxies separately.
- Growing the pack beyond the seven recorded scenarios requires new
  human-confirmed gold cases first; expectations may only be inherited,
  never AI-fabricated.
- `ScenarioError` messages were generalized from "AgentDojo scenario
  set" to "Scenario pack" since the exception now serves both families;
  the stable failure codes are unchanged.
- The scenario-count bounds and mapping notes stay aligned with ADR-0094
  constraints; any change to the tool-integration signature or pairing
  semantics requires a new ADR.
- The next ADR number is 0096.
