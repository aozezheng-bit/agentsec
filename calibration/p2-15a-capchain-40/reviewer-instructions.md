# HG-CAPCHAIN-001 Independent Review — 40 Questions

This packet is for one independent Reviewer only. It contains 40 opaque Case
questions for `HG-CAPCHAIN-001`. The selection is balanced at 20 Positive and 20
eligible Negative/Near-miss Cases, but expected labels are intentionally not
included in the packet.

## Independence rules

- Do not open `calibration/corpus.json`, `calibration/gate-coverage-matrix.json`,
  `joint-expert-evidence.json`, or any Ground Truth file while reviewing.
- Do not compare answers with the other Reviewer.
- Do not use the prior Joint Expert Review conclusion as an answer key.
- Complete your own copy of `labels.template.json` only.
- Use `status=reviewed` only when the row is complete.
- Record direct evidence locations from the displayed Case source.
- Do not calculate TP/FP/FN/TN yourself.

## Required fields for every reviewed row

```text
human_condition_label: match / no_match / uncertain
observed_finding: present / absent / uncertain
category: standard / policy_accepted_risk / out_of_scope /
runtime_uncertainty / unresolved
confidence: A / B / C / D
correlation: same_target / parent_child / same_source / explicit_relation /
agent_wide / incomplete_coverage
disposition: keep / tune / shadow / retire / more_data
evidence_locations
finding_summary
rationale_code
review_notes
status: reviewed
```

## Review question

For each Case, decide whether the Rule condition is supported by the displayed
static evidence:

```text
execute + secret-access + external network
```

A `match` requires the condition to be supported by the Case evidence. A
`no_match` result is appropriate when one required capability is absent, denied,
unknown, or not correlated to the same target/family. Use `uncertain` only when
the evidence cannot support a safe deterministic decision, and choose an
uncertainty category.

## Provenance

```text
selection_id: gate-subset-selection-sha256:4ef30e1a30ca4e6d4c87b32f07328946e8fdef4034ca78e48f8aef203104b2ae
source_pack_id: reviewer-pack-sha256:58295690c13861a763ed9c202d39fe37642ac0f8d9d2d6e416886184a4a86d90
source_corpus_binding_hash: sha256:59e034541e3c1096f311404358031a5dc81fc880123351363713d66c2544ad79
review_count: 40
```

This packet is prepared for independent review. It is not yet formal Human
Evidence and does not enable a Hard Gate or CI blocking.
