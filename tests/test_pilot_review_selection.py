"""Regression tests for the 100-question Demo-first review selection."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, cast

REPOSITORY_ROOT = Path(__file__).parents[1]
CALIBRATION_ROOT = REPOSITORY_ROOT / "calibration"
PILOT_ROOT = CALIBRATION_ROOT / "pilot-review-100"
PACK_ROOT = CALIBRATION_ROOT / "reviewer-pack"
BLINDING_SALT = "agentsec-p2-cal-04a-reviewer-pack-v2"


def _read_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _review_case_id(corpus_id: str, case_id: str) -> str:
    material = f"{BLINDING_SALT}:{corpus_id}:{case_id}".encode()
    return "review-case-" + hashlib.sha256(material).hexdigest()[:20]


def _load_expectation_index() -> dict[tuple[str, str], dict[str, Any]]:
    corpus = _read_json(CALIBRATION_ROOT / "corpus.json")
    result = {}
    for relative_path in corpus["case_paths"]:
        case = _read_json(CALIBRATION_ROOT / relative_path)
        for expectation in case["ground_truth"]["rule_expectations"]:
            result[(case["case_id"], expectation["rule_id"])] = {
                "case": case,
                "expectation": expectation,
            }
    return result


def test_pilot_selection_has_100_opaque_questions_and_all_rules() -> None:
    selection = _read_json(PILOT_ROOT / "selection.json")
    items = selection["items"]

    assert selection["format"] == "agentsec-pilot-review-selection"
    assert selection["review_count"] == 100
    assert len(items) == 100
    assert len({item["question_id"] for item in items}) == 100
    assert len({item["rule_id"] for item in items}) == 29
    forbidden = {
        "case_id",
        "case_kind",
        "coverage",
        "expected_outcome",
        "ground_truth",
        "has_unknown",
        "is_eligible_negative",
        "is_positive",
        "selection_reason",
        "track",
        "unknown_dimensions",
    }
    for item in items:
        assert not forbidden.intersection(item), item
        assert item["review_case_id"].startswith("review-case-")
        assert (PACK_ROOT / item["reviewer_a_case_path"]).is_file()
        assert (PACK_ROOT / item["reviewer_b_case_path"]).is_file()


def test_pilot_selection_preserves_demo_rule_strata() -> None:
    selection = _read_json(PILOT_ROOT / "selection.json")
    expectation_index = _load_expectation_index()
    corpus = _read_json(CALIBRATION_ROOT / "corpus.json")
    by_review_case = {
        _review_case_id(corpus["corpus_id"], case_id): case_id
        for case_id, _rule_id in expectation_index
    }

    selected = []
    for item in selection["items"]:
        case_id = by_review_case[item["review_case_id"]]
        pair = expectation_index[(case_id, item["rule_id"])]
        selected.append((item, pair["case"], pair["expectation"]))

    chain = [row for row in selected if row[0]["rule_id"] == "CAP-CHAIN-001"]
    assert len(chain) == 44
    assert sum(expectation["outcome"] == "match" for _, _, expectation in chain) == 20
    assert (
        sum(
            expectation["outcome"] == "no_match"
            and case["ground_truth"]["coverage"] == "complete"
            and not case["ground_truth"]["unknown_dimensions"]
            for _, case, expectation in chain
        )
        == 20
    )
    assert (
        sum(bool(case["ground_truth"]["unknown_dimensions"]) for _, case, _ in chain)
        == 4
    )

    rule_counts = Counter(item["rule_id"] for item, _case, _expectation in selected)
    assert rule_counts["CAP-CHAIN-001"] == 44
    assert all(
        count == 2 for rule, count in rule_counts.items() if rule != "CAP-CHAIN-001"
    )


def test_pilot_templates_are_100_row_draft_only_templates() -> None:
    selection = _read_json(PILOT_ROOT / "selection.json")
    selected_review_ids = {
        f"review:{reviewer_id}:{item['review_case_id']}:{item['rule_id']}"
        for reviewer_id in ("reviewer-a", "reviewer-b")
        for item in selection["items"]
    }

    for reviewer_id in ("reviewer-a", "reviewer-b"):
        template = _read_json(PILOT_ROOT / f"{reviewer_id}-labels.template.json")
        reviews = template["reviews"]
        assert template["format"] == "agentsec-pilot-review-label-template"
        assert template["pilot_selection_id"] == selection["selection_id"]
        assert len(reviews) == 100
        assert {row["review_id"] for row in reviews} == {
            review_id
            for review_id in selected_review_ids
            if review_id.startswith(f"review:{reviewer_id}:")
        }
        assert all(row["status"] in {None, "reviewed"} for row in reviews)

        full_template = _read_json(PACK_ROOT / reviewer_id / "labels.template.json")
        assert len(full_template["reviews"]) == 431


def test_pilot_selection_is_not_a_hard_gate_or_ci_decision() -> None:
    selection = _read_json(PILOT_ROOT / "selection.json")
    assert selection["boundary"] == {
        "full_pack_remains_authoritative": True,
        "pilot_labels_are_not_formal_human_evidence_until_import_support_exists": True,
        "hard_gate_qualification": False,
        "ci_blocking": False,
        "fail_on": False,
    }
