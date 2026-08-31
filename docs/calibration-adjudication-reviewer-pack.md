# P2-CAL-04A Independent Reviewer Pack and Human Adjudication Guide

- Task: `P2-CAL-04A`
- Status: Engineering preparation complete; independent human review not started
- Date: 2026-08-24
- Reviewer Pack Schema: `0.3.0`
- Adjudication Review Set Schema: `0.1.0`
- Adjudication Resolution Set Schema: `0.1.0`
- Adjudication Report Output: `0.3.0`
- Current enforcement: `report_only`

## 0. Scope statement

P2-CAL-04A prepares the expanded Calibration Corpus, the blinded Reviewer Pack,
and the Gate Calibration Coverage Check CLI. It does not perform the review
itself. The following statements are normative for every document and report in
this repository:

```text
P2-CAL-04A only prepares Cases and the Reviewer Pack
Real Reviewers must be recruited by humans; no Agent may simulate a Reviewer
Seed Labels cannot be used as production review results
Reviewer A and Reviewer B must perform blind, independent review
P2-CAL-04A produces no Hard Gate qualification conclusion
Each Gate requires at least 20 Positive + 20 Negative/Near-miss reviewed samples
hard_gate=true is currently not enabled anywhere in the product
CI Blocking is currently not enabled
P2-CAL did not implement --fail-on; P2-26 now provides an explicit local Severity threshold, but Seed Labels and unqualified Gate Candidates still cannot authorize it
```

Engineering completion of P2-CAL-04A is not human review completion, is not a
Hard Gate pass, and does not unblock P2-15A. See ADR-0037 and ADR-0038.

## 1. Reviewer recruitment requirements

Real Reviewers are an operational control; the toolchain validates artifacts but
cannot attest the people who produced them. Recruitment must satisfy:

```text
two human Reviewers (A and B) with no shared authorship of the Corpus
independence: no label, note, or intermediate conclusion is exchanged
  between Reviewer A and Reviewer B before both submissions are complete
competence: ability to read English and Simplified Chinese instruction assets
  and Markdown / JSON / YAML / TOML / Manifest source formats
availability: each Reviewer labels 216 Cases and 431 Rule questions
one human Adjudicator, distinct from both Reviewers, for disputed rows
```

A Reviewer must never inspect Corpus Ground Truth (`case.json`,
`facts.json`), the Gate Coverage Matrix, expected Confidence/Correlation values,
Gate Candidate status, or Rule tuning results before and during the review.
Reviewer identity and independence are process guarantees outside the CLI; the
Pack only makes leaked Ground Truth and tampered files detectable.

## 2. Reviewer A/B independent blind review process

The checked-in Pack at `calibration/reviewer-pack/` is built by
`scripts/build-reviewer-pack.py` and contains:

```text
reviewer-a/   216 opaque Review Cases + labels.template.json (431 questions)
reviewer-b/   216 opaque Review Cases + labels.template.json (431 questions)
adjudicator/  adjudication template and instructions
reviewer-instructions.md
case-matrix.json / case-matrix.csv
pack-manifest.json
```

Process:

1. Distribute to Reviewer A only `reviewer-a/`, `reviewer-instructions.md`, and
   `reviewer-label-schema.json`; distribute the corresponding Reviewer B files
   to Reviewer B.
2. Each Reviewer reads the canonical, value-free Review Case source and answers
   every Rule question independently: `human_condition_label`
   (`match` / `no_match` / `uncertain`), `observed_finding`, policy/scope
   `category`, Evidence `confidence`, `correlation`, `disposition`,
   `evidence_locations`, `rationale_code`, and bounded `review_notes`.
3. Reviewers never compute TP/FP/FN/TN. The `classification` field is null and
   immutable in the template; the trusted importer derives it from the human
   condition label and a freshly recomputed deterministic Finding.
4. A Reviewer sets `status=reviewed` only when every required field is complete.
   A row left `uncertain` fails closed: it stays outside the formal confusion
   matrix and cannot be rewritten by the Adjudicator.
5. Both submissions are collected before any comparison is shown to either
   Reviewer. Blind review ends only when both label sets are imported.

## 3. Ground Truth isolation strategy

Isolation is enforced by construction and verified by validation:

```text
opaque review_case_id values replace original Corpus Case IDs
no expected match/no_match outcome is present in the Pack
no expected Evidence Confidence or Correlation value is present in the Pack
no Gate Candidate status or Rule tuning result is present in the Pack
canonical Reviewer sources are regenerated from the validated Fact Bundle;
  untrusted Source View text is never copied verbatim
every Case and Label carries pack_id, corpus_binding_hash, source_sha256,
  question_set_sha256, and review_case_fingerprint bindings
pack-manifest.json binds the exact file set with path, SHA-256, size, mode,
  role, and reviewer_scope; extra, missing, changed, or symbolic-linked files
  are rejected
Ground Truth injection is rejected in JSON, Manifest, YAML, TOML, and Markdown
```

Any attempt to smuggle answers into a Reviewer directory (for example an added
`GROUND_TRUTH.txt`) fails closed with a validation error.

## 4. Label lifecycle

Every Case/Rule expectation label moves through one lifecycle:

```text
pending → reviewed → adjudicated
```

Concretely:

```text
pending (seeded): machine-generated placeholder shipped with the Corpus;
  status=seeded, not human evidence, never counts as production review
reviewed: a real Reviewer completed the independent blind label for the row
adjudicated: a human Adjudicator completed a resolution row for a disputed
  Case/Rule expectation; original Reviewer A/B rows remain unchanged
```

`status` transitions are human actions recorded through the import path. No
script, Agent, or LLM may relabel `seeded` rows as `reviewed` or `adjudicated`.
The `AdjudicationReviewSet` always retains the two original Reviewer
observations; final resolutions live in a separate `AdjudicationResolutionSet`
so disagreement history is never overwritten (ADR-0038).

## 5. Disagreement handling

1. The importer recomputes deterministic Findings and derives each Reviewer
   classification independently.
2. Consensus exists only when both Reviewers agree on classification, category,
   and disposition. There is no silent majority vote.
3. A disagreeing row is reported as `unresolved` with the conservative
   `more_data` disposition, and `adjudication_required=true` is recorded.
4. The Adjudicator re-reads the canonical source and both submissions, then
   files a resolution row only where a human resolution is required. A
   resolution referencing an already-agreed row is rejected.
5. When a matching `AdjudicationResolution` exists, the report keeps
   `agreement=false` for the original pair and separately records
   `adjudication_completed=true` plus the final resolved
   classification/category/disposition.
6. Rows that remain `uncertain` after Reviewer follow-up stay outside the
   formal TP/FP/FN/TN set; they fail closed rather than being forced into a
   classification.

## 6. FP/FN classification vocabulary

Calibration keeps these outcomes separate; they must never be averaged into one
"false positive" bucket:

```text
detection false positive: deterministic Finding emitted, but the reviewed
  condition is no_match; an implementation defect
policy-accepted risk: the condition exists, but policy accepts or waives it;
  not automatically a detector defect
in-scope false negative: the reviewed condition is match, but the detector
  emitted no Finding
out-of-scope uncertainty: the judgment needs inputs outside static calibration
runtime uncertainty: static data cannot prove runtime reachability,
  authorization, identity, or execution
unresolved reviewer disagreement: consensus was not reached
```

Rule tuning recommendations are derived deterministically: `more_data` when
sample thresholds are unmet, `tune` for reviewed detection FP or in-scope FN,
`shadow` for scope/Coverage/Unknown/Confidence limitations, otherwise `keep`.
`retire` is a possible human-reviewed disposition but the runner never retires
a Rule automatically.

## 7. Case reuse and Gate statistics rules

The three approved report-only Gate Candidates are:

```text
HG-CAPCHAIN-001       High: execute + secret access + external network
HG-PRODAUTO-001       High: production authority without effective approval
HG-EXTERNALPROD-001   Critical candidate: privileged external identity +
                      production authority
```

Statistics rules:

```text
each Gate needs at least 20 reviewed Positive Cases
each Gate needs at least 20 reviewed Negative/Near-miss Cases
one Case may be reused across Gates only when its Ground Truth contains every
  component Rule expectation of each referencing Gate
every Gate deduplicates and counts independently; a Case never counts twice
  inside the same Gate
counts use unique semantic fingerprints recomputed from validated Ground
  Truth, not Matrix-reported values
an eligible Negative requires negative_or_near_miss AND complete Coverage AND
  no relevant Unknown; Unknown boundary Cases stay visible but never satisfy
  the confirmed-negative threshold
```

Promotion thresholds per candidate (all report-only):

```text
precision >= 0.95
in-scope recall >= 0.90
reviewer Kappa >= 0.80
complete relevant Coverage
no relevant Unknown
no D-confidence evidence
Critical candidates require B-confidence evidence
```

Current checked-in draft volume (still `seeded`, verified by the Coverage
Check CLI with `overall_status=ready`):

| Gate ID | Positive unique | Eligible Negative/Near-miss unique | Unknown boundary |
|---|---:|---:|---:|
| `HG-CAPCHAIN-001` | 25 | 21 | 4 |
| `HG-PRODAUTO-001` | 25 | 21 | 4 |
| `HG-EXTERNALPROD-001` | 25 | 26 | 4 |

Sample volume readiness is not review readiness. All three candidates remain
`more_data_required` until independent human labels replace the Seed Labels.

## 8. CLI usage after human review completes

All commands treat inputs as untrusted, never execute Fixture content, create
outputs with mode `0600`, and refuse to overwrite existing files.

1. (Optional) rebuild a Pack into a new directory after Corpus changes:

   ```bash
   .venv/bin/python scripts/build-reviewer-pack.py \
     --corpus calibration \
     --output /safe/reviewer-pack
   ```

2. Validate completed submissions against the closed Pack:

   ```bash
   .venv/bin/python scripts/build-reviewer-pack.py \
     --operation validate \
     --corpus calibration \
     --pack /safe/reviewer-pack \
     --reviewer-a /safe/reviewer-a-labels.json \
     --reviewer-b /safe/reviewer-b-labels.json \
     --adjudications /safe/adjudication-labels.json
   ```

3. Import the three separated formal artifacts (AdjudicationReviewSet,
   ConfidenceReviewSet, AdjudicationResolutionSet):

   ```bash
   .venv/bin/python scripts/build-reviewer-pack.py \
     --operation import \
     --corpus calibration \
     --pack /safe/reviewer-pack \
     --reviewer-a /safe/reviewer-a-labels.json \
     --reviewer-b /safe/reviewer-b-labels.json \
     --adjudications /safe/adjudication-labels.json \
     --output /safe/human-adjudication-reviews.json \
     --confidence-output /safe/human-confidence-reviews.json \
     --resolution-output /safe/human-adjudication-resolutions.json
   ```

4. Rerun P2-CAL-04 in explicit human evidence mode from a safe Corpus copy.
   Human mode fails closed without the explicit Human Confidence report and
   never falls back to Seed Confidence labels:

   ```bash
   .venv/bin/python scripts/run-calibration-adjudication.py \
     --corpus /safe/calibration \
     --adjudications /safe/calibration/human-adjudication-reviews.json \
     --confidence-reviews /safe/calibration/human-confidence-reviews.json \
     --resolutions /safe/calibration/human-adjudication-resolutions.json \
     --evidence-mode human \
     --format json
   ```

5. Rerun the report-only Gate Calibration Coverage Check (exit `0` ready, `2`
   insufficient, `4` invalid input, `5` unexpected failure):

   ```bash
   .venv/bin/python scripts/check-gate-calibration-coverage.py \
     --corpus calibration \
     --matrix calibration/gate-coverage-matrix.json \
     --format json
   ```

Even in human mode the report remains `report_only`: it removes the
`seed-labels-not-independent` reason only when non-seeded review and Confidence
inputs pass validation, and it never activates a Hard Gate.

### 8.1 Optional Demo-first Pilot Review

For the first Chinese Capability Drift Demo, an optional 100-question pilot
selection is available at:

```text
calibration/pilot-review-100/
```

It contains 44 `CAP-CHAIN-001` questions (20 Positive, 20 eligible
Negative/Near-miss, and 4 relevant Unknown boundary questions) plus two
questions for each of the other 28 Rule IDs. This reduces the first human
review workload while preserving both outcomes for every Rule and prioritizing
the Demo Track.

The pilot is not a substitute for the closed 431-question Pack. It is intended
for human usability, rule-language, evidence-location, and preliminary
semantic calibration. Its labels must not be marked as formal P2-CAL-04 human
evidence, and the current full Pack importer rejects incomplete 100-question
submissions. P2-15A remains blocked until the approved full or explicit subset
import path has two independent human submissions, Human Confidence, and
Adjudication. `scripts/pilot-review.py` may validate/report Pilot progress,
compare two completed Pilot submissions, create a human-only disagreement
worksheet, and create a non-clobbering full-template progress snapshot; it does
not import Pilot rows into the formal P2-CAL-04 evidence contract.

## 9. P2-15A preconditions

P2-15A Report-only Hard Gate evaluation may start only after all of the
following are true:

```text
two real independent Reviewers completed blind review of the full Pack
a real human Adjudicator resolved every disputed decisive row
the P2-CAL-04 report was rerun in human evidence mode
each Gate Candidate meets 20 Positive + 20 Negative/Near-miss reviewed samples
precision >= 0.95, in-scope recall >= 0.90, reviewer Kappa >= 0.80
complete relevant Coverage, no relevant Unknown, no D-confidence evidence;
  Critical candidates require B-confidence evidence
the Coverage Check CLI reports overall_status=ready on the reviewed Corpus
a separate ADR approves the Capability Risk Model 0.1.0 -> 0.2.0 change
```

Until then P2-15A remains blocked, and `hard_gate=true`, CI blocking, and
`--fail-on` remain disabled.

## 10. Security boundaries

```text
no Fixture, Source View, script, hook, Skill, plugin, Sub-Agent, Rule, or MCP
  server is executed
no network, MCP, OAuth, or live service is contacted
no real Secret, Credential, Header, environment, host, or personal value is
  read or emitted; Pack content is synthetic and value-free
no Capability Rule Pack or Capability Risk Model semantic is modified
no Seed Label is relabeled as reviewed or adjudicated
no LLM output is treated as an authorization decision
enforcement_mode=report_only
ci_blocking_enabled=false
hard_gate_eligibility_decided=false
automatic_rule_publication=false
```

Human labels and adjudications are evidence for deterministic reporting, not
authorization. They cannot mutate a Rule, activate a Gate, or block CI without
the separate P2-15A/P2-15B reviews.
