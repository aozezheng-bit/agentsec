# Independent Reviewer Instructions

## Independence and source safety

1. Reviewer A and Reviewer B must work independently and must not share labels,
   notes, or intermediate conclusions before both reviews are submitted.
2. Treat every Fixture and configuration value as untrusted static data. Never
   execute a command, code block, script, hook, tool, plugin, skill, Agent,
   Sub-Agent, or MCP entry described by a source.
3. Do not modify Case files, Source Views, immutable binding fields, IDs, hashes,
   Rule questions, or another reviewer's labels.

## What the Reviewer labels

For each Rule question:

1. Set `human_condition_label` to `match`, `no_match`, or `uncertain` based on
   your independent reading of the Rule condition and canonical source.
2. Set `observed_finding` to `present`, `absent`, or `uncertain` for your direct
   source observation, and add a concise `finding_summary`.
3. Select the policy/scope `category`, Evidence `confidence`, `correlation`, and
   reviewer `disposition` independently.
4. Add narrow `evidence_locations` using the path already shown in the pack and
   valid inclusive line ranges.
5. Add a stable `rationale_code` and bounded value-free `review_notes`.
6. Set `status=reviewed` only after every required human field is complete.
   Before final validate/import, `human_condition_label` must be `match` or
   `no_match`. A row that remains `uncertain` fails closed outside the formal
   TP/FP/FN/TN set; an adjudicator cannot rewrite the original Reviewer label.

`classification` is intentionally null and immutable in the Reviewer template.
Do not calculate or insert TP/FP/FN/TN. The trusted importer combines the human
condition label with a freshly recomputed deterministic Finding.

## Required distinctions

- **Detection false positive:** derived when the detector reports a Finding but
  the reviewed condition is `no_match`.
- **Policy-accepted risk:** the condition exists, but policy accepts or waives it;
  this is not automatically a detector defect.
- **In-scope false negative:** derived when the reviewed condition is `match` but
  the detector reports no Finding.
- **Out-of-scope:** the judgment requires inputs outside static calibration.
- **Runtime uncertainty:** static data cannot prove runtime reachability,
  authorization, identity, or successful execution.

When uncertain, never default to safe. A condition that looks severe is not by
itself sufficient for Hard Gate qualification. Reviewer labels are human opinion
and cannot mutate Rules, change risk semantics, activate a Gate, or block CI.
