"""Build the minimum independent-review package for HG-CAPCHAIN-001.

The generated package contains 20 Positive and 20 eligible Negative/Near-miss
opaque Reviewer cases for two independent experts. Expected labels, Ground
Truth, Joint Expert Evidence, and calibration answers are deliberately not
copied into the package. This is a reviewer-data preparation tool; formal
Human Evidence import remains a separate, explicitly approved operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any

GATE_ID = "HG-CAPCHAIN-001"
RULE_ID = "CAP-CHAIN-001"
SCHEMA_VERSION = "0.1.0"
PACK_SCHEMA_VERSION = "0.3.0"
BLINDING_SALT = "agentsec-p2-cal-04a-reviewer-pack-v2"
MATRIX_ID = "p2-cal-04a-gate-coverage"


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _review_case_id(corpus_id: str, case_id: str) -> str:
    material = f"{BLINDING_SALT}:{corpus_id}:{case_id}".encode()
    return "review-case-" + hashlib.sha256(material).hexdigest()[:20]


def _load_json(path: Path) -> dict[str, Any]:
    payload: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path}")
    return payload


def _select_stratified(rows: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    strata: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in sorted(rows, key=lambda item: str(item["case_id"])):
        strata[(str(row["language"]), str(row["format"]))].append(row)
    selected: list[dict[str, Any]] = []
    positions = {key: 0 for key in sorted(strata)}
    while len(selected) < count:
        progressed = False
        for key in sorted(strata):
            position = positions[key]
            values = strata[key]
            if position >= len(values):
                continue
            selected.append(values[position])
            positions[key] = position + 1
            progressed = True
            if len(selected) == count:
                break
        if not progressed:
            raise ValueError("not enough rows for deterministic stratified selection")
    return selected


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
        "sha256": _sha256(data),
        "bytes": len(data),
    }


def build(*, repository_root: Path, output: Path) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists; choose a new directory")
    calibration = repository_root / "calibration"
    matrix = _load_json(calibration / "gate-coverage-matrix.json")
    corpus = _load_json(calibration / "corpus.json")
    full_pack = calibration / "reviewer-pack"
    pack_manifest = _load_json(full_pack / "pack-manifest.json")
    full_labels = {
        reviewer: _load_json(full_pack / reviewer / "labels.template.json")
        for reviewer in ("reviewer-a", "reviewer-b")
    }

    matrix_rows = [
        row
        for row in matrix["rows"]
        if isinstance(row, dict) and row.get("gate_id") == GATE_ID
    ]
    positives = [row for row in matrix_rows if row.get("is_positive") is True]
    eligible_negatives = [
        row
        for row in matrix_rows
        if row.get("is_eligible_negative") is True
        and row.get("is_negative_or_near_miss") is True
    ]
    selected_positive = _select_stratified(positives, 20)
    selected_negative = _select_stratified(eligible_negatives, 20)
    selected_by_case = {
        str(row["case_id"]): row for row in (*selected_positive, *selected_negative)
    }

    source_pack_id = str(pack_manifest["pack_id"])
    corpus_binding_hash = str(pack_manifest["corpus_binding_hash"])
    corpus_id = str(corpus["corpus_id"])
    selected_review_cases = []
    for case_id in sorted(selected_by_case):
        review_case_id = _review_case_id(corpus_id, case_id)
        selected_review_cases.append(
            {
                "review_case_id": review_case_id,
                "question_id": f"question:{review_case_id}:{RULE_ID}",
                "rule_id": RULE_ID,
                "language": selected_by_case[case_id]["language"],
                "input_format": selected_by_case[case_id]["format"],
                "reviewer_a_case_path": (
                    f"reviewer-a/cases/{review_case_id}/case.json"
                ),
                "reviewer_b_case_path": (
                    f"reviewer-b/cases/{review_case_id}/case.json"
                ),
            }
        )

    # Interleave the two strata by stable case ID so the first rows do not
    # reveal whether a Case came from the Positive or Negative bucket.
    selected_review_cases.sort(key=lambda item: item["review_case_id"])
    selection: dict[str, Any] = {
        "format": "agentsec-gate-scoped-independent-review-selection",
        "schema_version": SCHEMA_VERSION,
        "selection_id": None,
        "title": "HG-CAPCHAIN-001 Minimum Independent Review Selection (40 Questions)",
        "purpose": (
            "Minimum independent human-review subset: 20 Positive and 20 eligible "
            "Negative/Near-miss Cases. Expected labels are intentionally omitted."
        ),
        "gate_id": GATE_ID,
        "component_rule_ids": [RULE_ID],
        "source_matrix_id": MATRIX_ID,
        "source_pack_id": source_pack_id,
        "source_corpus_binding_hash": corpus_binding_hash,
        "review_count": 40,
        "positive_count": 20,
        "eligible_negative_count": 20,
        "reviewer_scopes": ["reviewer-a", "reviewer-b"],
        "items": [
            {"sequence": index, **item}
            for index, item in enumerate(selected_review_cases, start=1)
        ],
        "boundary": {
            "expected_labels_distributed": False,
            "ground_truth_distributed": False,
            "joint_evidence_distributed": False,
            "seed_labels_distributed": False,
            "formal_human_evidence": False,
            "hard_gate_qualification": False,
            "ci_blocking": False,
        },
    }
    selection_unsigned = dict(selection)
    selection_unsigned["selection_id"] = None
    selection["selection_id"] = (
        "gate-subset-selection-sha256:"
        + hashlib.sha256(_canonical(selection_unsigned)).hexdigest()
    )

    output.mkdir(parents=True)
    for reviewer in ("reviewer-a", "reviewer-b"):
        source_rows = {
            row["review_id"]: row for row in full_labels[reviewer]["reviews"]
        }
        subset_rows = []
        for item in selected_review_cases:
            review_id = f"review:{reviewer}:{item['review_case_id']}:{RULE_ID}"
            row = source_rows.get(review_id)
            if row is None:
                raise ValueError(f"missing full-pack review row: {review_id}")
            if (
                any(
                    row.get(field) not in (None, "", [])
                    for field in (
                        "category",
                        "confidence",
                        "correlation",
                        "disposition",
                        "evidence_locations",
                        "finding_summary",
                        "human_condition_label",
                        "observed_finding",
                        "rationale_code",
                    )
                )
                or row.get("status") is not None
            ):
                raise ValueError(f"source reviewer row is not pending: {review_id}")
            subset_rows.append(row)
            source_case = (
                full_pack / reviewer / "cases" / item["review_case_id"] / "case.json"
            )
            destination = (
                output / reviewer / "cases" / item["review_case_id"] / "case.json"
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_case, destination)
            case_payload = _load_json(source_case)
            source_location = case_payload.get("source_location")
            if not isinstance(source_location, dict):
                raise ValueError(f"review Case source location is invalid: {review_id}")
            source_name = source_location.get("path")
            if (
                not isinstance(source_name, str)
                or not source_name
                or source_name.startswith("/")
                or "\\" in source_name
                or any(part in {"", ".", ".."} for part in source_name.split("/"))
            ):
                raise ValueError(f"review Case source path is unsafe: {review_id}")
            source_path = source_case.parent / source_name
            if not source_path.is_file() or source_path.is_symlink():
                raise ValueError(f"review Case source is missing: {review_id}")
            shutil.copyfile(source_path, destination.parent / source_name)
        labels = {
            "format": full_labels[reviewer]["format"],
            "schema_version": full_labels[reviewer]["schema_version"],
            "pack_id": source_pack_id,
            "corpus_binding_hash": corpus_binding_hash,
            "reviewer_id": reviewer,
            "reviews": subset_rows,
        }
        _write(output / reviewer / "labels.template.json", labels)
        role_label = "Reviewer A" if reviewer == "reviewer-a" else "Reviewer B"
        _write_text(
            output / reviewer / "WORK_PLAN.md",
            f"""# {role_label} 工作目录与评审计划

## 工作目录

```text
{reviewer}/
```

只使用本目录中的：

```text
labels.template.json
cases/<opaque-review-case-id>/case.json
cases/<opaque-review-case-id>/source.*
```

## 任务目标

独立完成 `HG-CAPCHAIN-001` 的 40 条评审：

```text
规则：CAP-CHAIN-001
条件：execute + secret-access + external network
数量：40 条
```

这 40 条整体包含 20 条 Positive 和 20 条 Eligible Negative/Near-miss，
但不会告诉你每一条的期望标签。

## 执行步骤

### 第 1 步：准备（约 5 分钟）

1. 阅读上级目录的 `reviewer-instructions.md`。
2. 确认只能访问本 Reviewer 目录。
3. 不要打开另一位 Reviewer 的目录、完整 Corpus、Coverage Matrix 或 Joint Evidence。

### 第 2 步：逐条评审（约 60～120 分钟）

对每个 `cases/<id>/case.json`：

1. 先阅读 `review_questions` 和 `condition`。
2. 再阅读同目录中的 `source.*` 原始展示内容。
3. 判断 `match`、`no_match` 或 `uncertain`。
4. 填写直接 Evidence Path 和行号。
5. 填写 `finding_summary`、`confidence`、`correlation`、`disposition`
   和 `rationale_code`。
6. 完成后将对应 `labels.template.json` 行的 `status` 改为 `reviewed`。

### 第 3 步：自检（约 10 分钟）

确认：

```text
40 条 status 都是 reviewed
没有必填字段为 null
每条 finding_summary 非空
每条 evidence_locations 至少一项
Evidence Path 来自对应的 source.*
没有填写 TP/FP/FN/TN classification
没有复制另一位 Reviewer 的答案
```

### 第 4 步：交付

只返回：

```text
labels.template.json
```

不要修改以下绑定字段：

```text
review_id
review_case_id
reviewer_id
rule_id
pack_id
corpus_binding_hash
question_set_sha256
review_case_fingerprint
source_sha256
```

## 独立性声明

完成后请在交付消息中确认：

```text
我独立完成了本目录中的 40 条评审，没有查看另一位 Reviewer 的结果，
没有使用 Ground Truth、Joint Expert Evidence 或 Seed Label 作为答案。
```

本目录是评审输入材料，不是正式 Human Evidence；正式导入、Comparison、
Confidence 校准和 Adjudication 将由 AgentSec 项目方后续执行。
""",
        )

    _write(output / "selection.json", selection)
    shutil.copyfile(
        full_pack / "reviewer-label-schema.json",
        output / "reviewer-label-schema.json",
    )
    _write_text(
        output / "reviewer-instructions.md",
        f"""# HG-CAPCHAIN-001 Independent Review — 40 Questions

This packet is for one independent Reviewer only. It contains 40 opaque Case
questions for `{GATE_ID}`. The selection is balanced at 20 Positive and 20
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
selection_id: {selection["selection_id"]}
source_pack_id: {source_pack_id}
source_corpus_binding_hash: {corpus_binding_hash}
review_count: 40
```

This packet is prepared for independent review. It is not yet formal Human
Evidence and does not enable a Hard Gate or CI blocking.
""",
    )

    package_files = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            package_files.append(_file_record(output, path))
    package_id = (
        "gate-review-package-sha256:"
        + hashlib.sha256(
            _canonical(
                {
                    "selection_id": selection["selection_id"],
                    "source_pack_id": source_pack_id,
                    "files": package_files,
                }
            )
        ).hexdigest()
    )
    package_manifest = {
        "format": "agentsec-gate-scoped-review-package",
        "schema_version": SCHEMA_VERSION,
        "package_id": package_id,
        "selection_id": selection["selection_id"],
        "gate_id": GATE_ID,
        "source_pack_id": source_pack_id,
        "source_corpus_binding_hash": corpus_binding_hash,
        "review_count": 40,
        "reviewer_count": 2,
        "expected_labels_included": False,
        "ground_truth_included": False,
        "joint_evidence_included": False,
        "files": package_files,
    }
    _write(output / "package-manifest.json", package_manifest)
    return package_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("calibration/p2-15a-capchain-40"),
    )
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[1]
    try:
        report = build(repository_root=repository_root, output=args.output)
    except Exception as error:  # noqa: BLE001 - safe preparation CLI
        print(f"failed to build review subset: {type(error).__name__}")
        raise SystemExit(4) from error
    print(f"Package: {report['package_id']}")
    print(f"Selection: {report['selection_id']}")
    print("Gate: HG-CAPCHAIN-001")
    print("Review rows per Reviewer: 40")
    print("Positive/Eligible Negative target: 20/20")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
