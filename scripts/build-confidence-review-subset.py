"""Build the blind 20-case Confidence-only review package for P2-15A-QUAL-02."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

PACKAGE_SOURCE = Path("calibration/p2-15a-capchain-40")
TASK_ID = "P2-15A-QUAL-02"
GATE_ID = "HG-CAPCHAIN-001"
RULE_ID = "CAP-CHAIN-001"
SCHEMA_VERSION = "0.1.0"
FORMAT = "agentsec-confidence-recalibration-package"
SUBMISSION_FORMAT = "agentsec-confidence-recalibration-submission"
MAX_JSON_BYTES = 8 * 1024 * 1024


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _hash_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("JSON exceeds bounded size")
    payload: object = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON object required")
    return payload


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _file_record(root: Path, path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _hash_bytes(data),
        "bytes": len(data),
    }


def _workflow(reviewer_id: str) -> str:
    other = "reviewer-b" if reviewer_id == "reviewer-a" else "reviewer-a"
    return f"""# P2-15A-QUAL-02 Confidence-only Review — {reviewer_id}

## Scope

You are {reviewer_id}. Review only the 20 opaque Cases in this directory.
This is a Confidence-only calibration task. Do not re-evaluate Match/No-match.

## Independence

Only access this directory:

```text
confidence-review-20/{reviewer_id}/
```

Do not access:

```text
confidence-review-20/{other}/
calibration/corpus.json
calibration/gate-coverage-matrix.json
calibration/p2-15a-capchain-40/human-evidence/
calibration/pilot-review-100/
calibration/reviewer-pack/
confidence-reviews.json
```

Do not use Ground Truth, Seed Labels, prior Confidence labels, or another
Reviewer's result. Do not fill TP/FP/FN/TN and do not modify any original
40-case review file.

## Editable fields

Only edit these three fields in each row:

```text
confidence
confidence_rationale
status
```

All other fields are immutable bindings and must remain unchanged.

## Confidence definitions

| Grade | Definition |
|---|---|
| A | Runtime Attestation or reproducible runtime proof only |
| B | Same normalized Target plus direct static Source evidence |
| C | Parent/Child, same-source, or explicit relation indirect static evidence |
| D | Agent-wide, incomplete Coverage, Unknown, or unresolved reachability |

Static Source evidence alone must never be graded A.

## Procedure

For every `cases/<review_case_id>/case.json`:

1. Read `review_questions`.
2. Read only the sibling `source.*` file.
3. Determine whether the evidence is runtime or static.
4. Apply the definitions above.
5. Write a concise `confidence_rationale`.
6. Set `status` to `reviewed`.

## Output

Submit only:

```text
{reviewer_id}-confidence-20-completed.json
```

The output must preserve:

```text
format = agentsec-confidence-recalibration-submission
schema_version = 0.1.0
task_id = P2-15A-QUAL-02
reviewer_id = {reviewer_id}
```

## Self-check

```text
20 Cases present
20 statuses are reviewed
confidence is A/B/C/D for every row
confidence_rationale is non-empty for every row
no Match/No-match changes
no TP/FP/FN/TN
no immutable binding changes
no access to {other}
```

## Independence declaration

```text
I independently completed the 20 Confidence-only Cases as {reviewer_id};
I did not view {other}, Ground Truth, Seed Labels, prior Confidence Evidence,
or the Qualification Report. I did not change Match/No-match labels.
```
"""


def build(repository_root: Path, output: Path) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists; choose a new directory")
    source_root = repository_root / PACKAGE_SOURCE
    manifest = _read(source_root / "package-manifest.json")
    selection = _read(source_root / "selection.json")
    resolutions = _read(
        source_root / "human-evidence/human-capchain-40-resolutions.json"
    )
    resolution_rows = resolutions.get("resolutions")
    if not isinstance(resolution_rows, list):
        raise ValueError("Human Resolution rows are invalid")
    selected_ids = [
        row["review_case_id"]
        for row in resolution_rows
        if row.get("human_condition_label") == "match"
    ]
    if len(selected_ids) != 20 or len(set(selected_ids)) != 20:
        raise ValueError("Confidence subset must contain exactly 20 blind Cases")
    selection_items = {item["review_case_id"]: item for item in selection["items"]}
    if set(selected_ids) - set(selection_items):
        raise ValueError("Confidence subset Case is absent from the source selection")

    output.mkdir(parents=True)
    selected_items = [selection_items[case_id] for case_id in selected_ids]
    selected_items.sort(key=lambda item: item["sequence"])
    subset_selection = {
        "format": "agentsec-confidence-recalibration-selection",
        "schema_version": SCHEMA_VERSION,
        "task_id": TASK_ID,
        "gate_id": GATE_ID,
        "rule_id": RULE_ID,
        "source_package_id": manifest["package_id"],
        "source_selection_id": selection["selection_id"],
        "review_count": 20,
        "reviewer_scopes": ["reviewer-a", "reviewer-b"],
        "expected_labels_included": False,
        "prior_confidence_included": False,
        "ground_truth_included": False,
        "items": [],
        "boundary": {
            "match_labels_distributed": False,
            "expected_confidence_distributed": False,
            "prior_human_confidence_distributed": False,
            "formal_human_evidence": False,
            "gate_qualification": False,
            "ci_blocking": False,
        },
    }
    output_items = []
    for sequence, item in enumerate(selected_items, start=1):
        case_id = item["review_case_id"]
        output_items.append(
            {
                "sequence": sequence,
                "review_case_id": case_id,
                "input_format": item["input_format"],
                "language": item["language"],
                "rule_id": RULE_ID,
                "reviewer_a_case_path": f"reviewer-a/cases/{case_id}/case.json",
                "reviewer_b_case_path": f"reviewer-b/cases/{case_id}/case.json",
            }
        )
    subset_selection["items"] = output_items
    unsigned_selection = dict(subset_selection)
    unsigned_selection["selection_id"] = None
    subset_selection["selection_id"] = (
        "confidence-selection-sha256:"
        + hashlib.sha256(_canonical(unsigned_selection)).hexdigest()
    )

    output.mkdir(exist_ok=True)
    for reviewer in ("reviewer-a", "reviewer-b"):
        reviewer_root = output / reviewer
        _write_text(reviewer_root / "WORKFLOW.md", _workflow(reviewer))
        rows = []
        for item in output_items:
            case_id = item["review_case_id"]
            source_case = source_root / reviewer / "cases" / case_id / "case.json"
            case_payload = _read(source_case)
            source_name = case_payload["source_location"]["path"]
            source_path = source_case.parent / source_name
            destination = reviewer_root / "cases" / case_id
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_case, destination / "case.json")
            shutil.copyfile(source_path, destination / source_name)
            rows.append(
                {
                    "review_case_id": case_id,
                    "review_case_fingerprint": case_payload["review_case_fingerprint"],
                    "source_sha256": case_payload["source_sha256"],
                    "confidence": None,
                    "confidence_rationale": None,
                    "status": None,
                }
            )
        labels = {
            "format": SUBMISSION_FORMAT,
            "schema_version": SCHEMA_VERSION,
            "task_id": TASK_ID,
            "gate_id": GATE_ID,
            "rule_id": RULE_ID,
            "package_id": None,
            "selection_id": subset_selection["selection_id"],
            "reviewer_id": reviewer,
            "reviews": rows,
        }
        _write(reviewer_root / "labels.template.json", labels)

    _write(output / "selection.json", subset_selection)
    _write_text(
        output / "reviewer-instructions.md",
        "# P2-15A-QUAL-02 Confidence-only Review\n\n"
        "Two independent reviewers each receive the same 20 opaque Cases. "
        "Only Confidence, Confidence rationale, and status may be edited. "
        "Expected labels and prior Confidence Evidence are not included.\n",
    )
    package_id = (
        "confidence-review-package-sha256:"
        + hashlib.sha256(
            _canonical(
                {
                    "selection_id": subset_selection["selection_id"],
                    "source_package_id": manifest["package_id"],
                    "review_count": 20,
                    "reviewer_count": 2,
                }
            )
        ).hexdigest()
    )
    for reviewer in ("reviewer-a", "reviewer-b"):
        labels_path = output / reviewer / "labels.template.json"
        labels = _read(labels_path)
        labels["package_id"] = package_id
        _write(labels_path, labels)
    package_files = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            package_files.append(_file_record(output, path))
    package_manifest = {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "package_id": package_id,
        "selection_id": subset_selection["selection_id"],
        "task_id": TASK_ID,
        "gate_id": GATE_ID,
        "rule_id": RULE_ID,
        "review_count": 20,
        "reviewer_count": 2,
        "expected_labels_included": False,
        "prior_confidence_included": False,
        "ground_truth_included": False,
        "human_evidence_included": False,
        "source_package_id": manifest["package_id"],
        "files": package_files,
    }
    _write(output / "package-manifest.json", package_manifest)
    return package_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=Path("calibration/confidence-review-20")
    )
    args = parser.parse_args()
    try:
        report = build(Path(__file__).resolve().parents[1], args.output)
    except Exception as error:  # noqa: BLE001 - bounded preparation CLI
        print(f"failed to build Confidence review subset: {type(error).__name__}")
        raise SystemExit(4) from error
    print(f"Package: {report['package_id']}")
    print(f"Selection: {report['selection_id']}")
    print("Task: P2-15A-QUAL-02")
    print("Review rows per Reviewer: 20")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
