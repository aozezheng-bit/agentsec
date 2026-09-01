# ADR-0106: Human FP/FN Feedback Rows and the Closed Resolution Loop

- Status: Accepted
- Date: 2026-08-31
- Task: P3-17
- Scope: P3-17 human feedback and labels (FP/FN closed loop)

## Context

The Phase 3 plan (P3-17) requires "实现人工反馈和标签", with feedback data
supporting a false-positive / false-negative closed loop. P3-07 already
provides human-labeled *candidate calibration* (one labeled expectation per
model candidate key, TP/FP/FN/TN classification, agreement metrics) over a
run, and P3-11A established the human-in-the-loop label workflow
(blinded pack → AI draft → per-case human confirmation → fail-closed import,
provenance `ai_draft_human_confirmed`). Three gaps remain for a feedback
*loop* rather than a snapshot:

1. **Issue-level FP/FN rows as first-class data.** Calibration records
   metrics over a run; it does not persist the individual missed or
   over-flagged judgments as reviewable, digest-bound rows that survive
   beyond the run.
2. **Human confirmation workflow for misreports.** The P3-11A workflow
   labels expectations; misreport feedback needs the same
   `ai_draft_human_confirmed` discipline (AI may draft, humans confirm —
   `ai_assisted` is rejected outright because
   "LLM output is evidence, not an authorization decision").
3. **Resolution semantics.** Closed loop means: after a Provider/Prompt
   change, each previously labeled FP/FN row is checked again — an FP row
   is resolved when the judgment is no longer predicted; an FN row is
   resolved when the expected judgment is detected again.

The P3-11C real-provider trial (theta-public|Kimi-K3-256K over the 45-case
gold set: precision 0.394 / recall 0.378, FP=57 / FN=61) is the motivating
evidence that misreport feedback needs a durable, auditable loop.

## Decision

Add `agentsec.semantic.feedback` with the versioned
`agentsec-p3-17-semantic-feedback-set` and
`agentsec-p3-17-semantic-feedback-loop-report` families (version
`0.1.0`, report-family classification, frozen Schema exports under
`schemas/semantic-analysis/`):

1. **Row contract.** One `SemanticFeedbackCaseRow` targets one case
   judgment (kind, category, disposition) plus an issue type
   (`false_positive` / `false_negative`) with an aligned closed rationale
   vocabulary (`missed_judgment` / `overflagged_judgment`), the case's
   Evidence IDs, a status (`draft` / `confirmed` / `rejected`), and an
   optional bounded note. Rows cannot target `scan_coverage`
   (mirrors the P3-01 candidate rule).

2. **Deterministic drafting.** `build_semantic_feedback_draft(packs,
   adapter, source_pack_sha256)` replays the frozen P3-12/P3-13 packs
   (cases deduplicated across packs — the packs intentionally share
   normal cases per ADR-0095; divergent duplicates fail closed), diffs
   predicted signatures against the gold-inherited expectations, and
   emits DRAFT FP/FN rows with a draft digest, provider/model context,
   and per-case stable-error failures recorded as unevaluated cases.
   The shipped pilot draft uses an honest offline fixture that predicts
   nothing (all FN suspects), bound to the real pack digests.

3. **Human confirmation.** `build_semantic_feedback_set(draft,
   confirmed_row_ids, reviewer_id, independence_statement,
   label_provenance)` promotes confirmed rows into a `SemanticFeedbackSet`
   with a recomputed digest; the set rejects `ai_assisted` provenance and
   rejects drafts carrying non-confirmed rows. The shipped workflow ships
   a submission template plus a Chinese review worksheet
   (`pilots/semantic-feedback-p3-17/draft/`), and the fail-closed import
   script (`scripts/import-p3-17-feedback.py`) validates reviewer
   identity, the independence statement, per-row confirm/reject
   resolution, unknown rows, and the draft binding before emitting the
   confirmed set.

4. **Closed loop.** `evaluate_feedback_resolution(feedback, packs,
   adapter)` re-replays the same packs and classifies every row:
   resolved / unresolved / unevaluated (invocation failures keep
   `evaluation_complete=false`), with `resolution_rate` over evaluated rows
   and a loop digest binding the feedback digest plus run identity. Rows
   are value-free; no corpus text or raw payloads enter the report.

5. **Authority boundary.** Both families freeze `report_only`,
   and reject `blocks`, `calibration_authority`,
   `rule_publication_authority`, `policy_authority`, `ci_authority`,
   `gate_authority`, and `runtime_verified`: feedback and resolution are
   human-review evidence only — never calibration decisions, rule
   publication, Policy/CI changes, or quality claims.

## Consequences

- P3-18's limited LLM gate work can consume confirmed feedback sets only
  as evidence; any gate qualification still needs qualification-gate
  processes (ADR-0092) rather than feedback counts.
- The shipped confirmed set does not exist until a human reviewer
  completes the worksheet (draft has 54 FN rows); the mechanism and the
  AI draft are delivered, the label authority awaits human confirmation.
- Draft generation is deterministic and value-free; real FP/FN drafts
  from live providers require issue-level predicted signatures, which
  value-free evaluation reports do not retain — drafts therefore come
  from re-replays with a known adapter, not from stored reports.
- The next ADR number is 0107.
