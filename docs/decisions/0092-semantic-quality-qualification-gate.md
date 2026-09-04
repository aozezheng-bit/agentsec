# ADR-0092: Semantic Quality Qualification Gate over Human-Confirmed Gold Labels

- Status: Accepted
- Date: 2026-08-31
- Task: P3-11B
- Scope: report-only semantic quality qualification over the P3-11A gold set

## Context

P3-11A produced 45 human-confirmed gold-label cases (AI draft, human
per-item confirmation, provenance `ai_draft_human_confirmed`, reviewer
internal-reviewer). P3-03/P3-07 already provide a deterministic evaluation harness and
P3-05 provides provider quality thresholds, but no artifact decides and
records qualification over the imported gold set. During gate
construction, two label-corpus defects were exposed deterministically:

1. 13 cases judged `scan_coverage` — a category the P3-01 model-output
   contract forbids (Coverage is trusted state, not model output);
   the labels were remapped to `instruction_integrity`.
2. 8 duplicate judgments after category merge — the P3-01 output
   contract forbids duplicate candidates; duplicates were removed.

## Decision

Add `agentsec.semantic.quality_gate`:

- `GoldLabelCase` / `GoldLabelSet` strict models binding the importer
  artifact to pack-recorded evidence IDs, source locators, and sanitized
  text; `label_provenance=ai_assisted` is rejected outright;
  duplicates, sorted-unique violations, and ambiguity-without-uncertain
  are validation errors;
- `load_gold_labels(path)` fail-closed loader: rejects symlinks, bad
  JSON, unknown case IDs, and any case missing from the pack;
- the pack's already-sanitized text is hashed directly instead of
  re-running the sanitizer (re-sanitizing would double-escape and break
  evidence binding), and the chunk is reconstructed from stored fields;
- `SemanticQualityGate.qualify()` evaluates one Shadow Adapter via the
  P3-03 harness and compares deterministic metrics against
  `ProviderQualityThresholds`;
- `QualityGateReport` (`0.1.0`) records qualified / not_qualified,
  failed checks, reasons, metrics, thresholds, reviewer, and provenance.

## Authority boundary

Every authority boolean is a frozen literal `False`:

```text
report_only             true
policy_authority        false
ci_authority            false
release_authority       false
runtime_verified        false
```

Qualification is evidence for provider review only. It cannot promote a
provider, change Policy, block CI, or mutate Rules or Findings.

## Consequences

Positive:

- the gold set now has a deterministic, reproducible qualification path;
- label corpus defects are exposed by schema validation instead of
  silently skewing metrics;
- qualification is bound to the reviewer identity and label provenance,
  preventing AI-assisted-only labels from silently backing the gate.

Trade-offs:

- the gate reads the pack from `pilots/semantic-quality-p3-11/` by
  pack-path convention; relocated packs require explicit loader work;
- qualification over the offline fixture provider is not a
  real-provider quality claim (remains P3-11C, decision-gated);
- remapping `scan_coverage` to `instruction_integrity` is a recorded
  judgment-corpus correction, not a scanner change.

## Rejected alternatives

- Re-run the sanitizer on stored text: rejected—breaks evidence
  identity and double-escapes text.
- Rate `ai_assisted` labels as qualified input: rejected—would let an
  AI draft self-certify model quality.
- Gate authority over provider promotion: rejected—promotion stays
  with the ADR-0086 human review workflow.
