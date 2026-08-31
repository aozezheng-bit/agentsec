# Independent Adjudication Instructions

Use this phase only after Reviewer A and Reviewer B have submitted independent
labels. Compare rows by opaque `review_case_id` and `rule_id`; preserve the two
original submissions unchanged.

1. Re-read the canonical source, both human condition labels, and evidence.
2. Fill an adjudication row only when a human resolution is required. Keep its
   immutable Pack/Corpus/Source/question fingerprints unchanged.
3. Resolve `human_condition_label`, direct observation, policy/scope category,
   Confidence, Correlation, disposition, rationale, and evidence separately.
4. Do not calculate TP/FP/FN/TN. The trusted importer derives classification
   from the final human condition and a freshly recomputed detector result.
5. Preserve policy-accepted risk, out-of-scope, runtime uncertainty, and
   unresolved evidence as distinct concepts. Never authorize by majority vote.
6. Set `status=adjudicated` only after all required fields are complete and the
   row references exactly the Reviewer A and Reviewer B labels.

Adjudication cannot directly change or retire a Rule, activate a Hard Gate, or
enable CI blocking.
