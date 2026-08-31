"""P2-CAL-04A independent Reviewer Pack security and import tests."""

from __future__ import annotations

import json
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from agentsec.calibration import (
    CalibrationAdjudicationRunner,
    ConfidenceCalibrationRunner,
    decode_adjudication_resolution_set_json,
    decode_adjudication_review_set_json,
    decode_confidence_review_set_json,
    load_adjudication_review_set,
    load_calibration_corpus,
)

REPOSITORY_ROOT = Path(__file__).parents[1]
CALIBRATION_ROOT = REPOSITORY_ROOT / "calibration"
CHECKED_IN_PACK = CALIBRATION_ROOT / "reviewer-pack"
BUILDER = REPOSITORY_ROOT / "scripts" / "build-reviewer-pack.py"
EXPECTED_CASES = 216
EXPECTED_QUESTIONS = 431


def _run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(BUILDER), *args],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )


def _run_builder(corpus: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return _run_tool("--corpus", str(corpus), "--output", str(output))


def _run_review_operation(
    operation: str,
    *,
    corpus: Path,
    pack: Path,
    reviewer_a: Path,
    reviewer_b: Path,
    adjudications: Path | None = None,
    output: Path | None = None,
    confidence_output: Path | None = None,
    resolution_output: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "--operation",
        operation,
        "--corpus",
        str(corpus),
        "--pack",
        str(pack),
        "--reviewer-a",
        str(reviewer_a),
        "--reviewer-b",
        str(reviewer_b),
    ]
    if adjudications is not None:
        args.extend(("--adjudications", str(adjudications)))
    if output is not None:
        args.extend(("--output", str(output)))
    if confidence_output is not None:
        args.extend(("--confidence-output", str(confidence_output)))
    if resolution_output is not None:
        args.extend(("--resolution-output", str(resolution_output)))
    return _run_tool(*args)


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _copy_corpus(tmp_path: Path) -> Path:
    target = tmp_path / "calibration"
    shutil.copytree(
        CALIBRATION_ROOT, target, ignore=shutil.ignore_patterns("reviewer-pack")
    )
    return target


def _fill_reviewer_labels(
    pack: Path,
    reviewer_id: str,
    output: Path,
) -> Path:
    template_path = pack / reviewer_id / "labels.template.json"
    payload = json.loads(template_path.read_text(encoding="utf-8"))
    reviews = cast(list[dict[str, Any]], payload["reviews"])
    for review in reviews:
        review_case_id = cast(str, review["review_case_id"])
        case_path = pack / reviewer_id / "cases" / review_case_id / "case.json"
        case = json.loads(case_path.read_text(encoding="utf-8"))
        source = cast(dict[str, object], case["source_location"])
        review.update(
            {
                "category": "standard",
                "confidence": "B",
                "correlation": "same_target",
                "disposition": "keep",
                "evidence_locations": [
                    {
                        "end_line": 1,
                        "path": f"cases/{review_case_id}/{source['path']}",
                        "start_line": 1,
                    }
                ],
                "finding_summary": "Independent human condition review completed.",
                "human_condition_label": "match",
                "observed_finding": "present",
                "rationale_code": "human-reviewed",
                "review_notes": "Independent review fixture.",
                "status": "reviewed",
            }
        )
        assert review["classification"] is None
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output


def _json_keys(value: object) -> set[str]:
    keys: set[str] = set()
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            keys.update(str(key) for key in current)
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return keys


def test_checked_in_reviewer_pack_is_reproducible_and_private(tmp_path: Path) -> None:
    generated = tmp_path / "reviewer-pack"
    result = _run_builder(CALIBRATION_ROOT, generated)

    assert result.returncode == 0, result.stderr
    assert f"Reviewer Cases per reviewer: {EXPECTED_CASES}" in result.stdout
    assert f"Rule questions per reviewer: {EXPECTED_QUESTIONS}" in result.stdout
    assert "reviewer-pack-sha256:" in result.stdout
    assert _files(generated) == _files(CHECKED_IN_PACK)
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in generated.rglob("*")
        if path.is_file()
    )


def test_reviewer_views_and_templates_exclude_ground_truth() -> None:
    original_case_ids = {
        path.parent.name for path in (CALIBRATION_ROOT / "cases").glob("*/case.json")
    }
    forbidden_keys = {
        "case_id",
        "case_kind",
        "coverage",
        "expected_confidence",
        "expected_correlation",
        "expected_gate_condition",
        "expected_outcome",
        "expected_rule_ids",
        "gate_candidates",
        "ground_truth",
        "outcome",
        "recommended_disposition",
        "semantic_fingerprint",
    }
    forbidden_text = (
        "cal-positive-",
        "cal-negative-",
        "cal-near-miss-",
        '"expected_',
        '"ground_truth"',
        '"gate_candidates"',
        '"recommended_disposition"',
    )

    for reviewer_id in ("reviewer-a", "reviewer-b"):
        reviewer_root = CHECKED_IN_PACK / reviewer_id
        case_files = sorted(reviewer_root.glob("cases/*/case.json"))
        assert len(case_files) == EXPECTED_CASES
        for case_file in case_files:
            payload: object = json.loads(case_file.read_text(encoding="utf-8"))
            assert isinstance(payload, dict)
            assert forbidden_keys.isdisjoint(_json_keys(payload))
            assert set(payload) == {
                "corpus_binding_hash",
                "format",
                "input_format",
                "language",
                "pack_id",
                "question_set_sha256",
                "review_case_fingerprint",
                "review_case_id",
                "review_questions",
                "schema_version",
                "source_location",
                "source_sha256",
                "synthetic_fixture",
            }
        all_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(reviewer_root.rglob("*"))
            if path.is_file()
        )
        assert not any(token in all_text for token in forbidden_text)
        assert not any(case_id in all_text for case_id in original_case_ids)
        assert '"case_id"' not in all_text
        assert "\ncase_id:" not in all_text
        assert "\ncase_id =" not in all_text

        template = json.loads(
            (reviewer_root / "labels.template.json").read_text(encoding="utf-8")
        )
        reviews = cast(list[dict[str, object]], template["reviews"])
        assert len(reviews) == EXPECTED_QUESTIONS
        for review in reviews:
            assert review["human_condition_label"] is None
            assert review["observed_finding"] is None
            assert review["finding_summary"] is None
            assert review["classification"] is None
            assert review["category"] is None
            assert review["confidence"] is None
            assert review["correlation"] is None
            assert review["disposition"] is None
            assert review["rationale_code"] is None
            assert review["status"] is None


def test_pack_bindings_and_conditional_schemas_are_present() -> None:
    manifest = json.loads((CHECKED_IN_PACK / "pack-manifest.json").read_text())
    matrix = json.loads((CHECKED_IN_PACK / "case-matrix.json").read_text())
    assert manifest["case_count"] == EXPECTED_CASES
    assert manifest["question_count"] == EXPECTED_QUESTIONS
    assert matrix["case_count"] == EXPECTED_CASES
    assert len(matrix["cases"]) == EXPECTED_CASES
    assert manifest["pack_id"] == matrix["pack_id"]
    assert manifest["corpus_binding_hash"] == matrix["corpus_binding_hash"]

    for row in cast(list[dict[str, object]], matrix["cases"]):
        assert str(row["source_sha256"]).startswith("sha256:")
        assert str(row["question_set_sha256"]).startswith("sha256:")
        assert str(row["review_case_fingerprint"]).startswith("sha256:")
        assert row["pack_id"] == matrix["pack_id"]
        assert row["corpus_binding_hash"] == matrix["corpus_binding_hash"]

    reviewer_schema = json.loads(
        (CHECKED_IN_PACK / "reviewer-label-schema.json").read_text()
    )
    review_item = reviewer_schema["properties"]["reviews"]["items"]
    assert reviewer_schema["additionalProperties"] is False
    assert review_item["properties"]["classification"] == {"const": None}
    assert review_item["allOf"][0]["if"]["properties"]["status"] == {
        "const": "reviewed"
    }
    assert (
        review_item["allOf"][0]["then"]["properties"]["evidence_locations"]["minItems"]
        == 1
    )
    assert reviewer_schema["properties"]["reviews"]["maxItems"] == 20_000

    adjudication_schema = json.loads(
        (CHECKED_IN_PACK / "adjudication-label-schema.json").read_text()
    )
    adjudication_item = adjudication_schema["properties"]["adjudications"]["items"]
    assert adjudication_schema["additionalProperties"] is False
    assert adjudication_item["properties"]["classification"] == {"const": None}
    assert adjudication_item["properties"]["review_ids"]["minItems"] == 2
    assert adjudication_item["properties"]["review_ids"]["maxItems"] == 2
    assert adjudication_item["allOf"][0]["if"]["properties"]["status"] == {
        "const": "adjudicated"
    }


def test_builder_does_not_overwrite_an_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "reviewer-pack"
    output.mkdir()
    marker = output / "marker.txt"
    marker.write_text("keep", encoding="utf-8")

    result = _run_builder(CALIBRATION_ROOT, output)

    assert result.returncode != 0
    assert "already exists" in result.stderr
    assert marker.read_text(encoding="utf-8") == "keep"


def test_builder_rejects_case_path_traversal(tmp_path: Path) -> None:
    corpus = _copy_corpus(tmp_path)
    index_path = corpus / "corpus.json"
    payload = json.loads(index_path.read_text(encoding="utf-8"))
    payload["case_paths"][0] = "../outside/case.json"
    index_path.write_text(json.dumps(payload), encoding="utf-8")

    result = _run_builder(corpus, tmp_path / "reviewer-pack")

    assert result.returncode != 0
    assert "safe relative path" in result.stderr
    assert not (tmp_path / "reviewer-pack").exists()


def test_builder_rejects_symlinked_source_view(tmp_path: Path) -> None:
    corpus = _copy_corpus(tmp_path)
    source = next(corpus.glob("fixtures/*/source.*"))
    source.unlink()
    source.symlink_to(source.parent / "facts.json")

    result = _run_builder(corpus, tmp_path / "reviewer-pack")

    assert result.returncode != 0
    assert "symlink" in result.stderr
    assert not (tmp_path / "reviewer-pack").exists()


@pytest.mark.parametrize(
    "filename",
    ("source.json", "source.manifest.json", "source.yaml", "source.toml", "source.md"),
)
def test_builder_rejects_ground_truth_injected_into_any_source_format(
    tmp_path: Path,
    filename: str,
) -> None:
    corpus = _copy_corpus(tmp_path)
    source = next(corpus.glob(f"fixtures/*/{filename}"))
    text = source.read_text(encoding="utf-8")
    if filename.endswith(".json"):
        payload = json.loads(text)
        payload["ground_truth"] = {
            "expected_outcome": "match",
            "expected_confidence": "B",
            "expected_correlation": "same_target",
            "expected_gate_condition": "match",
            "recommended_disposition": "keep",
            "gate_candidates": ["HG-CAPCHAIN-001"],
        }
        text = json.dumps(payload)
    elif filename.endswith(".yaml"):
        text += "\nground_truth:\n  expected_outcome: match\n"
    elif filename.endswith(".toml"):
        text += '\n[ground_truth]\nexpected_outcome = "match"\n'
    else:
        text += "\n## Ground Truth\n- expected_outcome: match\n"
    source.write_text(text, encoding="utf-8")

    output = tmp_path / "reviewer-pack"
    result = _run_builder(corpus, output)

    assert result.returncode != 0
    assert "source" in result.stderr.lower()
    assert not output.exists()


def test_builder_rejects_secret_like_source_material(tmp_path: Path) -> None:
    corpus = _copy_corpus(tmp_path)
    source = next(corpus.glob("fixtures/*/source.md"))
    source.write_text(
        source.read_text(encoding="utf-8")
        + "\n- Authorization: Bearer synthetic-but-forbidden\n",
        encoding="utf-8",
    )

    result = _run_builder(corpus, tmp_path / "reviewer-pack")

    assert result.returncode != 0
    assert "secret-like" in result.stderr


def test_source_change_updates_bindings_and_old_labels_are_rejected(
    tmp_path: Path,
) -> None:
    corpus = _copy_corpus(tmp_path)
    first_pack = tmp_path / "pack-first"
    second_pack = tmp_path / "pack-second"
    assert _run_builder(corpus, first_pack).returncode == 0
    old_a = _fill_reviewer_labels(first_pack, "reviewer-a", tmp_path / "old-a.json")
    old_b = _fill_reviewer_labels(first_pack, "reviewer-b", tmp_path / "old-b.json")

    source_path = next(corpus.glob("fixtures/*/source.json"))
    case_id = source_path.parent.name
    changed_target = "target:changed-binding"

    source = json.loads(source_path.read_text(encoding="utf-8"))
    source["facts"][0]["target_id"] = changed_target
    source_path.write_text(json.dumps(source), encoding="utf-8")

    facts_path = source_path.parent / "facts.json"
    facts = json.loads(facts_path.read_text(encoding="utf-8"))
    facts["facts"][0]["target_id"] = changed_target
    facts_path.write_text(json.dumps(facts), encoding="utf-8")

    case_path = corpus / "cases" / case_id / "case.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    case["ground_truth"]["facts"][0]["target_id"] = changed_target
    case_path.write_text(json.dumps(case), encoding="utf-8")

    result = _run_builder(corpus, second_pack)
    assert result.returncode == 0, result.stderr

    first_matrix = json.loads((first_pack / "case-matrix.json").read_text())
    second_matrix = json.loads((second_pack / "case-matrix.json").read_text())
    first_rows = {
        row["review_case_id"]: row
        for row in cast(list[dict[str, Any]], first_matrix["cases"])
    }
    second_rows = {
        row["review_case_id"]: row
        for row in cast(list[dict[str, Any]], second_matrix["cases"])
    }
    assert set(first_rows) == set(second_rows)
    changed = [
        review_case_id
        for review_case_id in first_rows
        if first_rows[review_case_id]["source_sha256"]
        != second_rows[review_case_id]["source_sha256"]
    ]
    assert len(changed) == 1
    review_case_id = changed[0]
    assert (
        first_rows[review_case_id]["question_set_sha256"]
        == second_rows[review_case_id]["question_set_sha256"]
    )
    assert (
        first_rows[review_case_id]["review_case_fingerprint"]
        != second_rows[review_case_id]["review_case_fingerprint"]
    )
    assert first_matrix["pack_id"] != second_matrix["pack_id"]
    assert first_matrix["corpus_binding_hash"] != second_matrix["corpus_binding_hash"]

    validation = _run_review_operation(
        "validate",
        corpus=corpus,
        pack=second_pack,
        reviewer_a=old_a,
        reviewer_b=old_b,
    )
    assert validation.returncode != 0
    assert "binding" in validation.stderr


def test_reviewed_status_requires_complete_human_fields(tmp_path: Path) -> None:
    reviewer_a = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-a", tmp_path / "reviewer-a.json"
    )
    reviewer_b = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-b", tmp_path / "reviewer-b.json"
    )
    payload = json.loads(reviewer_a.read_text(encoding="utf-8"))
    payload["reviews"][0]["confidence"] = None
    reviewer_a.write_text(json.dumps(payload), encoding="utf-8")

    result = _run_review_operation(
        "validate",
        corpus=CALIBRATION_ROOT,
        pack=CHECKED_IN_PACK,
        reviewer_a=reviewer_a,
        reviewer_b=reviewer_b,
    )

    assert result.returncode != 0
    assert "confidence" in result.stderr


def test_adjudicated_status_requires_complete_final_fields(tmp_path: Path) -> None:
    reviewer_a = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-a", tmp_path / "reviewer-a.json"
    )
    reviewer_b = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-b", tmp_path / "reviewer-b.json"
    )
    adjudications = tmp_path / "adjudications.json"
    payload = json.loads(
        (CHECKED_IN_PACK / "adjudicator" / "adjudication.template.json").read_text(
            encoding="utf-8"
        )
    )
    payload["adjudications"][0]["status"] = "adjudicated"
    adjudications.write_text(json.dumps(payload), encoding="utf-8")

    result = _run_review_operation(
        "validate",
        corpus=CALIBRATION_ROOT,
        pack=CHECKED_IN_PACK,
        reviewer_a=reviewer_a,
        reviewer_b=reviewer_b,
        adjudications=adjudications,
    )

    assert result.returncode != 0
    assert "human_condition_label" in result.stderr


def test_validator_rejects_tampered_bound_source(tmp_path: Path) -> None:
    pack = tmp_path / "reviewer-pack"
    shutil.copytree(CHECKED_IN_PACK, pack)
    source = next(pack.glob("reviewer-a/cases/*/source.*"))
    source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    reviewer_a = _fill_reviewer_labels(pack, "reviewer-a", tmp_path / "a.json")
    reviewer_b = _fill_reviewer_labels(pack, "reviewer-b", tmp_path / "b.json")

    result = _run_review_operation(
        "validate",
        corpus=CALIBRATION_ROOT,
        pack=pack,
        reviewer_a=reviewer_a,
        reviewer_b=reviewer_b,
    )

    assert result.returncode != 0
    assert "manifest" in result.stderr


def test_import_derives_formal_classification_and_loads_in_p2_cal_04(
    tmp_path: Path,
) -> None:
    reviewer_a = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-a", tmp_path / "reviewer-a.json"
    )
    reviewer_b = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-b", tmp_path / "reviewer-b.json"
    )
    output = tmp_path / "adjudication-reviews.json"
    confidence_output = tmp_path / "confidence-reviews.json"

    result = _run_review_operation(
        "import",
        corpus=CALIBRATION_ROOT,
        pack=CHECKED_IN_PACK,
        reviewer_a=reviewer_a,
        reviewer_b=reviewer_b,
        output=output,
        confidence_output=confidence_output,
    )

    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE(confidence_output.stat().st_mode) == 0o600
    formal = decode_adjudication_review_set_json(output.read_text(encoding="utf-8"))
    confidence = decode_confidence_review_set_json(
        confidence_output.read_text(encoding="utf-8")
    )
    assert formal.reviewer_ids == ("reviewer-a", "reviewer-b")
    assert len(formal.reviews) == EXPECTED_QUESTIONS * 2
    assert all(item.status.value == "reviewed" for item in formal.reviews)
    assert confidence.reviewer_ids == ("reviewer-a", "reviewer-b")
    assert confidence.reviews
    assert all(item.status.value == "reviewed" for item in confidence.reviews)
    assert {item.classification.value for item in formal.reviews} <= {
        "true_positive",
        "false_negative",
    }

    corpus_copy = _copy_corpus(tmp_path / "loader")
    shutil.copy2(output, corpus_copy / "human-adjudication-reviews.json")
    loaded_corpus = load_calibration_corpus(corpus_copy)
    loaded_reviews = load_adjudication_review_set(
        loaded_corpus, path="human-adjudication-reviews.json"
    )
    report = CalibrationAdjudicationRunner().run(loaded_corpus, loaded_reviews)
    assert len(loaded_reviews.reviews) == EXPECTED_QUESTIONS * 2
    assert report.summary.total_reviews == EXPECTED_QUESTIONS * 2


def test_validator_rejects_undeclared_or_missing_pack_files(tmp_path: Path) -> None:
    reviewer_a = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-a", tmp_path / "reviewer-a.json"
    )
    reviewer_b = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-b", tmp_path / "reviewer-b.json"
    )

    with_extra = tmp_path / "pack-extra"
    shutil.copytree(CHECKED_IN_PACK, with_extra)
    (with_extra / "reviewer-a" / "GROUND_TRUTH.txt").write_text(
        "expected_outcome=match\n", encoding="utf-8"
    )
    extra = _run_review_operation(
        "validate",
        corpus=CALIBRATION_ROOT,
        pack=with_extra,
        reviewer_a=reviewer_a,
        reviewer_b=reviewer_b,
    )
    assert extra.returncode != 0
    assert "file set" in extra.stderr

    with_missing = tmp_path / "pack-missing"
    shutil.copytree(CHECKED_IN_PACK, with_missing)
    next(with_missing.glob("reviewer-b/cases/*/source.*")).unlink()
    missing = _run_review_operation(
        "validate",
        corpus=CALIBRATION_ROOT,
        pack=with_missing,
        reviewer_a=reviewer_a,
        reviewer_b=reviewer_b,
    )
    assert missing.returncode != 0
    assert "file set" in missing.stderr


def test_adjudication_import_preserves_independent_disagreement(
    tmp_path: Path,
) -> None:
    reviewer_a = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-a", tmp_path / "reviewer-a.json"
    )
    reviewer_b = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-b", tmp_path / "reviewer-b.json"
    )
    reviewer_b_payload = json.loads(reviewer_b.read_text(encoding="utf-8"))
    reviewer_b_payload["reviews"][0].update(
        {
            "human_condition_label": "no_match",
            "observed_finding": "absent",
            "finding_summary": "Independent reviewer did not confirm the condition.",
        }
    )
    reviewer_b.write_text(
        json.dumps(reviewer_b_payload, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    adjudications = tmp_path / "adjudications.json"
    adjudication_payload = json.loads(
        (CHECKED_IN_PACK / "adjudicator" / "adjudication.template.json").read_text(
            encoding="utf-8"
        )
    )
    row = adjudication_payload["adjudications"][0]
    review_case_id = cast(str, row["review_case_id"])
    case_payload = json.loads(
        (
            CHECKED_IN_PACK / "reviewer-a" / "cases" / review_case_id / "case.json"
        ).read_text(encoding="utf-8")
    )
    source_path = cast(dict[str, object], case_payload["source_location"])["path"]
    row.update(
        {
            "adjudication_notes": "Independent adjudicator resolved the condition.",
            "category": "standard",
            "confidence": "B",
            "correlation": "same_target",
            "disposition": "keep",
            "evidence_locations": [
                {
                    "end_line": 1,
                    "path": f"reviewer-a/cases/{review_case_id}/{source_path}",
                    "start_line": 1,
                }
            ],
            "finding_summary": "Final human resolution confirms the condition.",
            "human_condition_label": "match",
            "observed_finding": "present",
            "rationale_code": "human-adjudicated",
            "status": "adjudicated",
        }
    )
    adjudications.write_text(
        json.dumps(adjudication_payload, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    review_output = tmp_path / "reviews.json"
    confidence_output = tmp_path / "confidence.json"
    resolution_output = tmp_path / "resolutions.json"
    result = _run_review_operation(
        "import",
        corpus=CALIBRATION_ROOT,
        pack=CHECKED_IN_PACK,
        reviewer_a=reviewer_a,
        reviewer_b=reviewer_b,
        adjudications=adjudications,
        output=review_output,
        confidence_output=confidence_output,
        resolution_output=resolution_output,
    )
    assert result.returncode == 0, result.stderr

    reviews = decode_adjudication_review_set_json(
        review_output.read_text(encoding="utf-8")
    )
    resolutions = decode_adjudication_resolution_set_json(
        resolution_output.read_text(encoding="utf-8")
    )
    assert all(item.status.value == "reviewed" for item in reviews.reviews)
    assert len(resolutions.resolutions) == 1
    resolution = resolutions.resolutions[0]
    independent = [
        item
        for item in reviews.reviews
        if item.case_id == resolution.case_id and item.rule_id == resolution.rule_id
    ]
    assert len(independent) == 2
    assert len({item.classification for item in independent}) == 2
    assert resolution.status == "adjudicated"

    confidence_set = decode_confidence_review_set_json(
        confidence_output.read_text(encoding="utf-8")
    )
    confidence_report = ConfidenceCalibrationRunner().run(
        load_calibration_corpus(CALIBRATION_ROOT), confidence_set
    )
    report = CalibrationAdjudicationRunner().run(
        load_calibration_corpus(CALIBRATION_ROOT),
        reviews,
        confidence_report,
        resolutions,
        evidence_mode="human",
    )
    resolved = next(
        item
        for item in report.by_case
        if item.case_id == resolution.case_id and item.rule_id == resolution.rule_id
    )
    assert resolved.classification_agreement is False
    assert resolved.adjudication_required is True
    assert resolved.adjudication_completed is True
    assert resolved.final_classification == resolution.final_classification
    assert report.summary.adjudication_required_count == 1
    assert report.summary.adjudication_completed_count == 1
    assert all(
        "seed-labels-not-independent" not in item.reason_codes
        for item in report.gate_candidates
    )

    human_corpus = _copy_corpus(tmp_path / "human-cli")
    shutil.copy2(review_output, human_corpus / "human-reviews.json")
    shutil.copy2(confidence_output, human_corpus / "human-confidence.json")
    shutil.copy2(resolution_output, human_corpus / "human-resolutions.json")
    cli = subprocess.run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "scripts" / "run-calibration-adjudication.py"),
            "--corpus",
            str(human_corpus),
            "--adjudications",
            str(human_corpus / "human-reviews.json"),
            "--confidence-reviews",
            str(human_corpus / "human-confidence.json"),
            "--resolutions",
            str(human_corpus / "human-resolutions.json"),
            "--evidence-mode",
            "human",
            "--format",
            "json",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    assert cli.returncode == 0, cli.stderr
    cli_payload = json.loads(cli.stdout)
    assert cli_payload["policy"]["evidence_mode"] == "human"
    assert cli_payload["summary"]["adjudication_required_count"] == 1
    assert cli_payload["summary"]["adjudication_completed_count"] == 1


@pytest.mark.parametrize(
    "relative",
    ("reviewer-a/labels.template.json", "reviewer-instructions.md"),
)
def test_validator_rejects_tampered_pack_material(
    tmp_path: Path, relative: str
) -> None:
    reviewer_a = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-a", tmp_path / "reviewer-a.json"
    )
    reviewer_b = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-b", tmp_path / "reviewer-b.json"
    )
    pack = tmp_path / "pack"
    shutil.copytree(CHECKED_IN_PACK, pack)
    target = pack / relative
    target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    result = _run_review_operation(
        "validate",
        corpus=CALIBRATION_ROOT,
        pack=pack,
        reviewer_a=reviewer_a,
        reviewer_b=reviewer_b,
    )
    assert result.returncode != 0
    assert "manifest" in result.stderr


def test_validator_rejects_incorrect_pack_permissions(tmp_path: Path) -> None:
    reviewer_a = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-a", tmp_path / "reviewer-a.json"
    )
    reviewer_b = _fill_reviewer_labels(
        CHECKED_IN_PACK, "reviewer-b", tmp_path / "reviewer-b.json"
    )
    pack = tmp_path / "pack"
    shutil.copytree(CHECKED_IN_PACK, pack)
    (pack / "README.md").chmod(0o644)

    result = _run_review_operation(
        "validate",
        corpus=CALIBRATION_ROOT,
        pack=pack,
        reviewer_a=reviewer_a,
        reviewer_b=reviewer_b,
    )
    assert result.returncode != 0
    assert "permissions" in result.stderr
