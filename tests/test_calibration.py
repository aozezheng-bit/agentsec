"""P2-CAL-01 Calibration Case Schema and labeled corpus tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.calibration import (
    CALIBRATION_CASE_FORMAT,
    CALIBRATION_CASE_SCHEMA_VERSION,
    CalibrationCase,
    CalibrationCorpusError,
    CalibrationValidationCode,
    CalibrationValidationError,
    decode_calibration_case_json,
    encode_calibration_case_json,
    export_calibration_case_json_schema,
    export_calibration_corpus_json_schema,
    load_calibration_corpus,
    validate_calibration_case_payload,
)
from agentsec.capability_rules import BUILTIN_CAPABILITY_RULE_IDS

REPOSITORY_ROOT = Path(__file__).parents[1]
CALIBRATION_ROOT = REPOSITORY_ROOT / "calibration"
SECRET_MARKER = "p2-cal-01-secret-must-not-leak"


def test_seed_corpus_is_complete_and_stratified() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    summary = corpus.summary

    assert summary.total_cases == len(corpus.index.case_paths)
    assert set(summary.cases_by_kind) == {
        "positive",
        "negative",
        "near_miss",
        "incomplete",
        "unknown",
        "conflict",
    }
    assert set(summary.cases_by_rule) == set(BUILTIN_CAPABILITY_RULE_IDS)
    assert set(summary.matching_cases_by_rule) == set(BUILTIN_CAPABILITY_RULE_IDS)
    assert set(summary.no_match_cases_by_rule) == set(BUILTIN_CAPABILITY_RULE_IDS)
    assert all(
        summary.matching_cases_by_rule[rule_id] >= 1
        and summary.no_match_cases_by_rule[rule_id] >= 1
        for rule_id in BUILTIN_CAPABILITY_RULE_IDS
    )
    assert {case.language.value for case in corpus.cases} >= {"en", "zh", "bilingual"}
    assert all(case.ground_truth.runtime_verified is False for case in corpus.cases)


def test_every_case_is_deterministic_and_value_minimizing() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)

    first = [encode_calibration_case_json(case) for case in corpus.cases]
    second = [encode_calibration_case_json(case) for case in corpus.cases]

    assert first == second
    joined = "\n".join(first)
    assert SECRET_MARKER not in joined
    assert "Authorization:" not in joined
    assert "Bearer " not in joined
    assert "https://" not in joined
    assert all(
        expectation.rule_id in BUILTIN_CAPABILITY_RULE_IDS
        for case in corpus.cases
        for expectation in case.ground_truth.rule_expectations
    )


def test_calibration_case_json_round_trip_and_schema_exports(tmp_path: Path) -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    case = corpus.cases[0]

    encoded = encode_calibration_case_json(case)
    decoded = decode_calibration_case_json(encoded)

    assert decoded == case
    assert json.loads(encoded)["format"] == CALIBRATION_CASE_FORMAT
    assert json.loads(encoded)["schema_version"] == CALIBRATION_CASE_SCHEMA_VERSION

    first_case_schema = export_calibration_case_json_schema(tmp_path / "first")
    second_case_schema = export_calibration_case_json_schema(tmp_path / "second")
    first_corpus_schema = export_calibration_corpus_json_schema(tmp_path / "first")
    second_corpus_schema = export_calibration_corpus_json_schema(tmp_path / "second")

    assert first_case_schema.read_bytes() == second_case_schema.read_bytes()
    assert first_corpus_schema.read_bytes() == second_corpus_schema.read_bytes()
    assert json.loads(first_case_schema.read_text())["$schema"] == (
        "https://json-schema.org/draft/2020-12/schema"
    )
    assert json.loads(first_corpus_schema.read_text())["additionalProperties"] is False


def test_calibration_validation_does_not_leak_rejected_values() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    payload = json.loads(encode_calibration_case_json(corpus.cases[0]))
    payload[SECRET_MARKER] = True

    with pytest.raises(CalibrationValidationError) as captured:
        validate_calibration_case_payload(payload)

    assert captured.value.code is CalibrationValidationCode.INVALID_PAYLOAD
    assert SECRET_MARKER not in str(captured.value)
    assert "<field>" in captured.value.field_paths


def test_calibration_case_rejects_unsafe_fixture_path() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    payload = json.loads(encode_calibration_case_json(corpus.cases[0]))
    payload["fixture"]["path"] = "../outside/facts.json"

    with pytest.raises(CalibrationValidationError) as captured:
        validate_calibration_case_payload(payload)

    assert captured.value.code is CalibrationValidationCode.INVALID_PAYLOAD
    assert "fixture.path" in captured.value.field_paths


def test_corpus_loader_rejects_index_case_path_escape(tmp_path: Path) -> None:
    index = json.loads((CALIBRATION_ROOT / "corpus.json").read_text())
    index["case_paths"] = ["../outside/case.json"]
    (tmp_path / "corpus.json").write_text(
        json.dumps(index, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )

    with pytest.raises(CalibrationCorpusError):
        load_calibration_corpus(tmp_path)


def test_corpus_loader_rejects_rule_pack_version_mismatch(tmp_path: Path) -> None:
    index = json.loads((CALIBRATION_ROOT / "corpus.json").read_text())
    index["capability_rule_pack_version"] = "0.1.0"
    (tmp_path / "corpus.json").write_text(
        json.dumps(index, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )

    with pytest.raises(CalibrationCorpusError):
        load_calibration_corpus(tmp_path)


def test_calibration_case_model_is_strict_and_frozen() -> None:
    case = load_calibration_corpus(CALIBRATION_ROOT).cases[0]

    with pytest.raises(ValidationError):
        case.case_id = "cal-mutated"

    payload = case.model_dump(mode="python")
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        CalibrationCase.model_validate(payload)
