# P2-CAL-04A-AGENT-02 Completion Report

- Task ID: `P2-CAL-04A-AGENT-02-FIX-02`
- Parent task: `P2-CAL-04A-AGENT-02`
- Task: Independent Reviewer Pack, Import Provenance, and Human Evidence Mode
- Status: Complete for source development
- Completion date: 2026-08-21
- Enforcement mode: `report_only`
- CI blocking: disabled
- Reviewer Pack Schema: `0.3.0`
- Adjudication Resolution Schema: `0.1.0`
- Adjudication Report Output: `0.3.0`

## 1. Delivered files

Implementation and tests:

```text
scripts/build-reviewer-pack.py
scripts/run-calibration-adjudication.py
scripts/export_release_schemas.py
src/agentsec/calibration/adjudication_models.py
src/agentsec/calibration/adjudication_validation.py
src/agentsec/calibration/adjudication_loader.py
src/agentsec/calibration/adjudication_runner.py
src/agentsec/calibration/adjudication_reporting.py
src/agentsec/calibration/confidence_loader.py
tests/test_reviewer_pack.py
tests/test_calibration_adjudication.py
tests/test_confidence_calibration.py
```

Contracts and generated artifacts:

```text
calibration/reviewer-pack/
schemas/calibration/calibration-adjudication-resolution-set.schema.json
schemas/calibration/calibration-adjudication-report.schema.json
docs/decisions/0038-independent-review-import-provenance.md
```

No Capability Rule, Capability Risk Model, P2-15A/P2-15B enforcement, runtime
verification, LLM behavior, or automatic Rule publication was added.

## 2. Reviewer Pack result

```text
Reviewer A Cases: 216
Reviewer B Cases: 216
Rule questions per Reviewer: 431
Reviewer rows per Reviewer: 431
Pack Schema: 0.3.0
Pack ID: reviewer-pack-sha256:58295690c13861a763ed9c202d39fe37642ac0f8d9d2d6e416886184a4a86d90
```

The Pack covers every current Corpus Case/Rule expectation. Reviewer identities
remain opaque and original positive/negative/near-miss Case IDs are excluded.

## 3. Closed Pack integrity boundary

`pack-manifest.json` records every distributed file except itself with:

```text
path
sha256
size
mode
role
reviewer_scope
```

Validation recomputes the complete expected Pack and rejects:

```text
extra files
missing files
changed files
extra or missing directories
symlink files or directories
file mode other than 0600
directory mode other than 0700
changed Case, Source, Template, Schema, Matrix, README, or Instructions
```

A post-build `reviewer-a/GROUND_TRUTH.txt` or any other undeclared file is now
rejected with exit code `4`.

## 4. Source isolation and binding

The builder never copies untrusted Source View text verbatim. It validates any
existing JSON, Manifest JSON, YAML, TOML, or Markdown Source View against an
exact whitelist and the validated Fact Bundle, then regenerates canonical
value-free Reviewer output.

Every Case and Label carries:

```text
pack_id
corpus_binding_hash
source_sha256
question_set_sha256
review_case_fingerprint
```

Ground Truth injection, secret-like material, stale Source content, path
traversal, symlinks, and old Label reuse after Corpus/Source/Question changes are
rejected.

## 5. Independent Review and Resolution separation

Reviewer A and Reviewer B submit independent human condition labels. They never
supply TP/FP/FN/TN. The importer recomputes deterministic observations and
produces an `AdjudicationReviewSet` containing the original two reviewed
classifications.

An adjudicator no longer overwrites or impersonates the two Reviewers. Completed
resolutions are emitted separately as:

```text
agentsec-capability-calibration-adjudication-resolution-set
```

P2-CAL-04 now records separately:

```text
classification/category/disposition agreement
adjudication_required
adjudication_completed
final resolved classification/category/disposition
```

Original disagreement remains visible even when a final resolution exists.
A resolution for an already agreed row is rejected.

## 6. Human Confidence evidence

The import operation also emits the existing versioned:

```text
agentsec-capability-confidence-review-set
```

using the two original Reviewer Confidence and Correlation labels for current
matching Case/Rule expectations. Adjudication does not replace both Reviewer
Confidence grades and therefore cannot fabricate Cohen's Kappa.

P2-CAL-04 adds explicit evidence modes:

```text
seed
human
```

Human mode requires:

```text
non-seeded AdjudicationReviewSet
explicit human ConfidenceCalibrationReport
optional AdjudicationResolutionSet
```

It never silently falls back to `calibration/confidence-reviews.json`.
`seed-labels-not-independent` is emitted only in seed mode. Human Gate Candidate
Confidence grades and Kappa come from the supplied human Confidence report.

## 7. CLI usage

Build a new Pack into a non-existing directory:

```bash
.venv/bin/python scripts/build-reviewer-pack.py \
  --corpus calibration \
  --output /safe/reviewer-pack
```

Validate completed submissions:

```bash
.venv/bin/python scripts/build-reviewer-pack.py \
  --operation validate \
  --corpus calibration \
  --pack /safe/reviewer-pack \
  --reviewer-a /safe/reviewer-a-labels.json \
  --reviewer-b /safe/reviewer-b-labels.json \
  --adjudications /safe/adjudication-labels.json
```

Import the three separated formal artifacts:

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

Run P2-CAL-04 in explicit human evidence mode after copying the artifacts into a
safe Corpus workspace:

```bash
.venv/bin/python scripts/run-calibration-adjudication.py \
  --corpus /safe/calibration \
  --adjudications /safe/calibration/human-adjudication-reviews.json \
  --confidence-reviews /safe/calibration/human-confidence-reviews.json \
  --resolutions /safe/calibration/human-adjudication-resolutions.json \
  --evidence-mode human \
  --format json
```

All new files are mode `0600`, are created exclusively, and are never
silently overwritten.

## 8. Verification

Targeted public seams:

```text
Reviewer Pack build / validate / import CLI
P2-CAL-04 Runner seed / human evidence modes
Adjudication Resolution JSON codec and Schema
ConfidenceReviewSet import and human Kappa path
```

Final verification:

```text
Reviewer Pack security tests: 22 passed
Reviewer/Adjudication/Confidence/Version/Release integration: 53 passed
Ruff check: passed
Ruff format --check: 558 files already formatted
Mypy strict: no issues in 196 source files
Full Pytest: 904 passed in 86.92s
```

## 9. Remaining human work and limitations

Engineering completion does not equal human review completion. The project still
requires two real independent Reviewers and a real Adjudicator. Reviewer identity
and independence are process controls; this CLI validates artifacts but does not
cryptographically attest the people who produced them.

The current formal TP/FP/FN/TN adapter requires a decisive independent human
`match` or `no_match`. A Reviewer row that remains `uncertain` fails closed and
stays outside the formal confusion matrix until Reviewer follow-up records a
decisive label. An adjudicator may resolve a disagreement but cannot rewrite an
original uncertain Reviewer submission.

Fact Bundle replay still does not prove parser recall, Framework Adapter recall,
runtime Tool/OAuth/Permission reachability, or exploitability. All output remains
report-only and cannot activate a Hard Gate or CI block.
