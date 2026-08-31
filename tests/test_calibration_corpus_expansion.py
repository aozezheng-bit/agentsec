"""P2-CAL-04A Gate candidate corpus expansion and coverage matrix tests."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import cast

from agentsec.calibration import (
    CalibrationCase,
    CalibrationRuleOutcome,
    DeterministicCalibrationRunner,
    encode_calibration_case_json,
    load_calibration_corpus,
)
from agentsec.capability_rules import BUILTIN_CAPABILITY_RULE_IDS

REPOSITORY_ROOT = Path(__file__).parents[1]
CALIBRATION_ROOT = REPOSITORY_ROOT / "calibration"
MATRIX_PATH = CALIBRATION_ROOT / "gate-coverage-matrix.json"
EXPANSION_TAG = "p2-cal-04a"
MIN_GATE_SAMPLES = 20
EXPANSION_CASE_COUNT = 155

GATE_COMPONENT_RULES: dict[str, tuple[str, ...]] = {
    "HG-CAPCHAIN-001": ("CAP-CHAIN-001",),
    "HG-PRODAUTO-001": ("CAP-APPROVAL-001", "CAP-AUTOPROD-001"),
    "HG-EXTERNALPROD-001": (
        "CAP-EXTERNALPRIVILEGED-001",
        "CAP-PRODADMIN-001",
        "CAP-PRODIDENTITY-001",
        "CAP-PRODWRITE-001",
    ),
}

EXPECTED_LANGUAGES = {"en", "zh", "bilingual"}
EXPECTED_FORMATS = {"json", "manifest", "markdown", "toml", "yaml"}


def _matrix_rows() -> list[dict[str, object]]:
    payload: object = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    rows = payload["rows"]
    assert isinstance(rows, list)
    return [cast(dict[str, object], row) for row in rows]


def _semantic_fingerprint(case: CalibrationCase) -> str:
    payload = case.model_dump(mode="json")["ground_truth"]
    facts = [
        {
            key: value
            for key, value in item.items()
            if key not in {"fact_id", "evidence"}
        }
        for item in payload["facts"]
    ]
    expectations = [
        {
            key: value
            for key, value in item.items()
            if key not in {"fact_ids", "rationale_code"}
        }
        for item in payload["rule_expectations"]
    ]
    semantic = {
        "facts": facts,
        "expectations": expectations,
        "coverage": payload["coverage"],
        "unknown_dimensions": payload["unknown_dimensions"],
    }
    encoded = json.dumps(
        semantic,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _eligible_negative(row: dict[str, object]) -> bool:
    return (
        row["is_negative_or_near_miss"] is True
        and row["has_unknown"] is False
        and row["coverage"] == "complete"
        and row["is_eligible_negative"] is True
    )


def _expansion_cases() -> tuple[CalibrationCase, ...]:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    return tuple(case for case in corpus.cases if EXPANSION_TAG in case.tags)


def test_expansion_registers_every_case_in_the_corpus_index() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    expansion = _expansion_cases()

    assert len(expansion) == EXPANSION_CASE_COUNT
    assert corpus.summary.total_cases == len(corpus.index.case_paths)
    indexed = set(corpus.index.case_paths)
    assert all(f"cases/{case.case_id}/case.json" in indexed for case in expansion)
    assert set(corpus.summary.cases_by_rule) == set(BUILTIN_CAPABILITY_RULE_IDS)
    assert all(
        corpus.summary.matching_cases_by_rule[rule_id] >= 1
        and corpus.summary.no_match_cases_by_rule[rule_id] >= 1
        for rule_id in BUILTIN_CAPABILITY_RULE_IDS
    )


def test_gate_component_rules_meet_sample_thresholds() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    matching: Counter[str] = Counter()
    no_match: Counter[str] = Counter()
    for case in corpus.cases:
        for expectation in case.ground_truth.rule_expectations:
            if expectation.outcome is CalibrationRuleOutcome.MATCH:
                matching[expectation.rule_id] += 1
            else:
                no_match[expectation.rule_id] += 1

    for gate_id, rule_ids in GATE_COMPONENT_RULES.items():
        positives = min(matching[rule_id] for rule_id in rule_ids)
        negatives = min(no_match[rule_id] for rule_id in rule_ids)
        assert positives >= MIN_GATE_SAMPLES, gate_id
        assert negatives >= MIN_GATE_SAMPLES, gate_id


def test_gate_matrix_volume_and_unique_rows() -> None:
    rows = _matrix_rows()

    assert len(rows) == EXPANSION_CASE_COUNT
    keys = [(row["gate_id"], row["case_id"]) for row in rows]
    assert len(set(keys)) == len(keys)
    assert keys == sorted(keys)
    assert {row["gate_id"] for row in rows} == set(GATE_COMPONENT_RULES)

    for gate_id in GATE_COMPONENT_RULES:
        gate_rows = [row for row in rows if row["gate_id"] == gate_id]
        positives = sum(1 for row in gate_rows if row["is_positive"] is True)
        negatives = sum(1 for row in gate_rows if _eligible_negative(row))
        unknowns = sum(1 for row in gate_rows if row["has_unknown"] is True)
        assert positives >= MIN_GATE_SAMPLES, gate_id
        assert negatives >= MIN_GATE_SAMPLES, gate_id
        assert unknowns >= 1, gate_id


def test_matrix_rows_match_corpus_ground_truth() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    cases = {case.case_id: case for case in corpus.cases}

    for row in _matrix_rows():
        gate_id = row["gate_id"]
        case_id = row["case_id"]
        assert isinstance(gate_id, str)
        assert isinstance(case_id, str)
        case = cases[case_id]
        assert row["case_kind"] == case.case_kind.value
        assert row["language"] == case.language.value
        assert row["coverage"] == case.ground_truth.coverage
        assert row["has_unknown"] == bool(case.ground_truth.unknown_dimensions)
        assert row["format"] in {item.value for item in case.source_formats}
        assert row["semantic_fingerprint"] == _semantic_fingerprint(case)
        assert row["review_status"] == "seeded"
        assert row["is_eligible_negative"] is (
            row["is_negative_or_near_miss"] is True
            and row["has_unknown"] is False
            and row["coverage"] == "complete"
        )
        assert row["expected_rule_ids"] == [
            expectation.rule_id for expectation in case.ground_truth.rule_expectations
        ]
        assert row["expected_rule_ids"] == list(GATE_COMPONENT_RULES[gate_id])
        assert row["is_positive"] is not row["is_negative_or_near_miss"]
        expected_condition = (
            "match" if case.case_kind.value == "positive" else "no_match"
        )
        assert row["expected_gate_condition"] == expected_condition


def test_gate_samples_are_semantically_unique_and_eligible() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    cases = {case.case_id: case for case in corpus.cases}
    rows = _matrix_rows()

    for gate_id in GATE_COMPONENT_RULES:
        gate_rows = [row for row in rows if row["gate_id"] == gate_id]
        positives = [row for row in gate_rows if row["is_positive"] is True]
        negatives = [row for row in gate_rows if _eligible_negative(row)]
        for population in (positives, negatives):
            fingerprints = [
                _semantic_fingerprint(cases[cast(str, row["case_id"])])
                for row in population
            ]
            assert len(fingerprints) >= MIN_GATE_SAMPLES, gate_id
            assert len(fingerprints) == len(set(fingerprints)), gate_id


def test_language_and_format_coverage_per_gate() -> None:
    rows = _matrix_rows()
    for gate_id in GATE_COMPONENT_RULES:
        gate_rows = [row for row in rows if row["gate_id"] == gate_id]
        languages = {row["language"] for row in gate_rows}
        formats = {row["format"] for row in gate_rows}
        assert languages >= EXPECTED_LANGUAGES, gate_id
        assert formats >= EXPECTED_FORMATS, gate_id
        positive_languages = {
            row["language"] for row in gate_rows if row["is_positive"] is True
        }
        negative_languages = {
            row["language"]
            for row in gate_rows
            if row["is_negative_or_near_miss"] is True
        }
        assert positive_languages >= {"en", "zh"}, gate_id
        assert negative_languages >= {"en", "zh"}, gate_id
        for row in gate_rows:
            source_path = (
                CALIBRATION_ROOT / cast(str, row["source_asset_path"])
            ).resolve()
            source_path.relative_to(CALIBRATION_ROOT.resolve())
            assert source_path.is_file()
            assert not source_path.is_symlink()
            content = source_path.read_text(encoding="utf-8")
            assert content.strip()
            assert "https://" not in content
            assert "Authorization:" not in content
            assert "Bearer " not in content
            expected_suffix = {
                "markdown": ".md",
                "json": ".json",
                "yaml": ".yaml",
                "toml": ".toml",
                "manifest": ".json",
            }[cast(str, row["format"])]
            assert source_path.name.endswith(expected_suffix)


def test_expanded_corpus_replays_without_fp_fn_or_failure() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    report = DeterministicCalibrationRunner().run(corpus)
    confusion = report.summary.micro.confusion

    assert report.status == "complete"
    assert confusion.false_positive == 0
    assert confusion.false_negative == 0
    assert report.summary.failures == 0
    assert report.summary.duplicate_findings == 0
    assert report.summary.micro.precision == 1.0
    assert report.summary.micro.recall == 1.0
    assert report.summary.micro.f1 == 1.0
    assert report.summary.coverage_visibility == 1.0
    assert report.summary.evidence_completeness == 1.0
    assert report.summary.correlation_agreement == 1.0
    assert report.summary.confidence_agreement == 1.0

    component_rules = {
        rule_id for rule_ids in GATE_COMPONENT_RULES.values() for rule_id in rule_ids
    }
    sufficient = {item.rule_id for item in report.rules if item.sufficient_sample_size}
    assert sufficient == component_rules


def test_expansion_labels_remain_seeded_and_value_free() -> None:
    for case in _expansion_cases():
        assert case.review.status.value == "seeded"
        assert case.review.rationale_code == (
            "machine-generated-draft-requires-human-review"
        )
        assert "machine-generated-draft" in case.tags
        assert case.ground_truth.runtime_verified is False
        encoded = encode_calibration_case_json(case)
        assert "https://" not in encoded
        assert "Bearer " not in encoded
        assert "Authorization:" not in encoded


COVERAGE_CLI_PATH = REPOSITORY_ROOT / "scripts" / "check-gate-calibration-coverage.py"
EXIT_READY = 0
EXIT_INCOMPLETE = 2
EXIT_INVALID = 4

REQUIRED_GATE_REPORT_FIELDS = {
    "gate_id",
    "positive_count",
    "negative_count",
    "near_miss_count",
    "unknown_count",
    "incomplete_count",
    "language_distribution",
    "format_distribution",
    "coverage_status",
    "missing_sample_count",
}


def _run_coverage_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(COVERAGE_CLI_PATH), *args],
        capture_output=True,
        text=True,
        cwd=REPOSITORY_ROOT,
        check=False,
    )


def _copy_corpus(tmp_path: Path) -> Path:
    target = tmp_path / "calibration"
    shutil.copytree(CALIBRATION_ROOT, target)
    return target


def _rewrite_matrix(
    corpus_root: Path,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    matrix_path = corpus_root / "gate-coverage-matrix.json"
    payload = json.loads(matrix_path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    mutate(payload)
    matrix_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _rewrite_matrix_rows(
    corpus_root: Path,
    mutate: Callable[[list[dict[str, object]]], None],
) -> None:
    def apply(payload: dict[str, object]) -> None:
        rows = payload["rows"]
        assert isinstance(rows, list)
        mutate(cast(list[dict[str, object]], rows))

    _rewrite_matrix(corpus_root, apply)


def _coverage_report(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    payload: object = json.loads(result.stdout)
    assert isinstance(payload, dict)
    return payload


def _gate_entries(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    gates = payload["gates"]
    assert isinstance(gates, list)
    entries = [cast(dict[str, object], gate) for gate in gates]
    return {str(gate["gate_id"]): gate for gate in entries}


def test_coverage_cli_ready_corpus_exits_zero_with_valid_report() -> None:
    result = _run_coverage_cli(
        "--corpus",
        str(CALIBRATION_ROOT),
        "--matrix",
        str(MATRIX_PATH),
        "--format",
        "json",
    )

    assert result.returncode == EXIT_READY, result.stderr
    payload = _coverage_report(result)
    assert payload["overall_status"] == "ready"
    assert payload["ci_blocking_enabled"] is False
    assert payload["enforcement_mode"] == "report_only"
    gates = _gate_entries(payload)
    assert set(gates) == set(GATE_COMPONENT_RULES)
    for gate in gates.values():
        assert set(gate) >= REQUIRED_GATE_REPORT_FIELDS
        assert gate["coverage_status"] == "ready"
        assert gate["missing_sample_count"] == 0


def test_coverage_cli_language_and_format_distributions_are_correct() -> None:
    result = _run_coverage_cli(
        "--corpus",
        str(CALIBRATION_ROOT),
        "--matrix",
        str(MATRIX_PATH),
        "--format",
        "json",
    )

    assert result.returncode == EXIT_READY, result.stderr
    gates = _gate_entries(_coverage_report(result))
    rows = _matrix_rows()
    for gate_id in GATE_COMPONENT_RULES:
        gate_rows = [row for row in rows if row["gate_id"] == gate_id]
        languages = Counter(str(row["language"]) for row in gate_rows)
        formats = Counter(str(row["format"]) for row in gate_rows)
        gate = gates[gate_id]
        assert gate["language_distribution"] == dict(sorted(languages.items()))
        assert gate["format_distribution"] == dict(sorted(formats.items()))
        assert set(languages) == EXPECTED_LANGUAGES
        assert set(formats) == EXPECTED_FORMATS
        assert gate["positive_count"] == sum(
            1 for row in gate_rows if row["is_positive"] is True
        )
        assert gate["near_miss_count"] == sum(
            1 for row in gate_rows if row["case_kind"] == "near_miss"
        )
        assert gate["negative_count"] == sum(
            1 for row in gate_rows if row["case_kind"] == "negative"
        )
        assert gate["unknown_count"] == sum(
            1 for row in gate_rows if row["has_unknown"] is True
        )


def test_coverage_cli_exact_threshold_still_exits_zero(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def trim(rows: list[dict[str, object]]) -> None:
        gate = "HG-CAPCHAIN-001"
        positives = [
            row for row in rows if row["gate_id"] == gate and row["is_positive"] is True
        ]
        eligible_negatives = [
            row for row in rows if row["gate_id"] == gate and _eligible_negative(row)
        ]
        for row in positives[MIN_GATE_SAMPLES:] + eligible_negatives[MIN_GATE_SAMPLES:]:
            rows.remove(row)

    _rewrite_matrix_rows(corpus_root, trim)
    result = _run_coverage_cli("--corpus", str(corpus_root), "--format", "json")

    assert result.returncode == EXIT_READY, result.stderr
    gate = _gate_entries(_coverage_report(result))["HG-CAPCHAIN-001"]
    assert gate["eligible_positive_count"] == MIN_GATE_SAMPLES
    assert gate["eligible_negative_or_near_miss_count"] == MIN_GATE_SAMPLES
    assert gate["coverage_status"] == "ready"


def test_coverage_cli_below_threshold_exits_nonzero(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def trim(rows: list[dict[str, object]]) -> None:
        positives = [
            row
            for row in rows
            if row["gate_id"] == "HG-CAPCHAIN-001" and row["is_positive"] is True
        ]
        for row in positives[MIN_GATE_SAMPLES - 1 :]:
            rows.remove(row)

    _rewrite_matrix_rows(corpus_root, trim)
    result = _run_coverage_cli("--corpus", str(corpus_root), "--format", "json")

    assert result.returncode == EXIT_INCOMPLETE
    payload = _coverage_report(result)
    assert payload["overall_status"] == "more_data_required"
    gate = _gate_entries(payload)["HG-CAPCHAIN-001"]
    assert gate["eligible_positive_count"] == MIN_GATE_SAMPLES - 1
    assert gate["coverage_status"] == "more_data_required"
    assert gate["missing_sample_count"] == 1
    assert payload["ci_blocking_enabled"] is False


def test_coverage_cli_rejects_unknown_gate_id(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        rows[0]["gate_id"] = "HG-UNKNOWN-001"

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "unknown gate_id" in result.stderr


def test_coverage_cli_rejects_duplicate_gate_case_row(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        rows.append(dict(rows[0]))

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "duplicate (gate_id, case_id)" in result.stderr


def test_coverage_cli_rejects_conflicting_labels(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        positive = next(row for row in rows if row["is_positive"] is True)
        positive["is_negative_or_near_miss"] = True

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "conflict" in result.stderr


def test_coverage_cli_rejects_conflicting_case_kind(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        positive = next(row for row in rows if row["is_positive"] is True)
        positive["case_kind"] = "negative"

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "conflict" in result.stderr


def test_coverage_cli_rejects_missing_case_reference(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        rows[0]["case_id"] = "cal-missing-from-corpus-001"

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INCOMPLETE
    assert "missing from the corpus" in result.stderr


def test_coverage_cli_rejects_matrix_path_escape(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)
    outside = tmp_path / "outside-matrix.json"
    shutil.copy(corpus_root / "gate-coverage-matrix.json", outside)

    result = _run_coverage_cli(
        "--corpus",
        str(corpus_root),
        "--matrix",
        str(outside),
    )

    assert result.returncode == EXIT_INVALID
    assert "escapes the corpus root" in result.stderr


def test_coverage_cli_rejects_symlink_matrix(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)
    link = corpus_root / "linked-matrix.json"
    link.symlink_to(corpus_root / "gate-coverage-matrix.json")

    result = _run_coverage_cli(
        "--corpus",
        str(corpus_root),
        "--matrix",
        str(link),
    )

    assert result.returncode == EXIT_INVALID
    assert "symlink" in result.stderr


def test_coverage_cli_rejects_unapproved_gate_definition(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(payload: dict[str, object]) -> None:
        gates = cast(list[dict[str, object]], payload["gates"])
        gates.append(
            {
                "gate_id": "HG-FAKE-001",
                "floor": "high",
                "component_rule_ids": ["CAP-CHAIN-001"],
                "min_positive_samples": 1,
                "min_negative_or_near_miss_samples": 1,
            }
        )
        rows = cast(list[dict[str, object]], payload["rows"])
        rows[0]["gate_id"] = "HG-FAKE-001"
        rows[-1]["gate_id"] = "HG-FAKE-001"

    _rewrite_matrix(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "unapproved gate_id" in result.stderr


def test_coverage_cli_rejects_tampered_gate_threshold(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(payload: dict[str, object]) -> None:
        gates = cast(list[dict[str, object]], payload["gates"])
        gates[0]["min_positive_samples"] = 1

    _rewrite_matrix(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "differs from the approved value" in result.stderr


def test_coverage_cli_rejects_tampered_gate_components(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(payload: dict[str, object]) -> None:
        gates = cast(list[dict[str, object]], payload["gates"])
        gates[0]["component_rule_ids"] = ["CAP-APPROVAL-001"]

    _rewrite_matrix(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "differ from the approved definition" in result.stderr


def test_coverage_cli_rejects_foreign_corpus_binding(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(payload: dict[str, object]) -> None:
        payload["corpus_id"] = "unrelated-corpus"

    _rewrite_matrix(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "does not match the corpus" in result.stderr


def test_coverage_cli_rejects_unsupported_matrix_schema_version(
    tmp_path: Path,
) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(payload: dict[str, object]) -> None:
        payload["schema_version"] = "9.9.9"

    _rewrite_matrix(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "schema_version is unsupported" in result.stderr


def test_coverage_cli_rejects_forged_semantic_fingerprint(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        rows[0]["semantic_fingerprint"] = "sha256:" + "0" * 64

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "disagrees with the corpus ground truth" in result.stderr


def test_coverage_cli_rejects_collapsed_semantic_fingerprints(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        for row in rows:
            row["semantic_fingerprint"] = "sha256:" + "0" * 64

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "semantic_fingerprint" in result.stderr


def test_coverage_cli_rejects_mismatched_eligibility_flag(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        eligible = next(row for row in rows if _eligible_negative(row))
        eligible["is_eligible_negative"] = False

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "trusted computation" in result.stderr


def test_coverage_cli_rejects_internal_symlink_source_asset(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)
    rows = _matrix_rows()
    first = corpus_root / cast(str, rows[0]["source_asset_path"])
    second = corpus_root / cast(str, rows[1]["source_asset_path"])
    first.unlink()
    first.symlink_to(second)

    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "symlink" in result.stderr


def test_coverage_cli_rejects_source_asset_from_another_case(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        markdown = next(row for row in rows if row["format"] == "markdown")
        json_row = next(row for row in rows if row["format"] == "json")
        markdown["source_asset_path"] = json_row["source_asset_path"]

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "does not match the Case fixture and format" in result.stderr


def test_coverage_cli_rejects_review_status_mismatch(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        rows[0]["review_status"] = "adjudicated"

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "review_status disagrees" in result.stderr


def test_coverage_cli_rejects_duplicate_scenario_in_same_gate(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)

    def poison(rows: list[dict[str, object]]) -> None:
        same_gate = [row for row in rows if row["gate_id"] == "HG-CAPCHAIN-001"]
        same_gate[1]["scenario_id"] = same_gate[0]["scenario_id"]

    _rewrite_matrix_rows(corpus_root, poison)
    result = _run_coverage_cli("--corpus", str(corpus_root))

    assert result.returncode == EXIT_INVALID
    assert "duplicate scenario_id" in result.stderr


def test_coverage_cli_allows_one_case_to_cover_multiple_gates(tmp_path: Path) -> None:
    corpus_root = _copy_corpus(tmp_path)
    case_id = "cal-positive-prodauto-001-en"
    case_path = corpus_root / "cases" / case_id / "case.json"
    case_payload = json.loads(case_path.read_text(encoding="utf-8"))
    assert isinstance(case_payload, dict)
    ground_truth = cast(dict[str, object], case_payload["ground_truth"])
    facts = cast(list[dict[str, object]], ground_truth["facts"])
    start = len(facts)
    added_fact_ids: list[str] = []
    for offset, key in enumerate(
        ("execute", "secret-access", "external-network"), start=1
    ):
        fact_id = f"fact-{start + offset:02d}"
        added_fact_ids.append(fact_id)
        facts.append(
            {
                "dimension": "permission",
                "evidence": [
                    {
                        "asset_path": "facts.json",
                        "field_path": f"facts.{start + offset - 1}",
                    }
                ],
                "fact_id": fact_id,
                "key": key,
                "state": "present",
                "target_id": "target:prodauto-1",
            }
        )
    expectations = cast(list[dict[str, object]], ground_truth["rule_expectations"])
    expectations.append(
        {
            "confidences": ["B"],
            "correlations": ["same_target"],
            "fact_ids": added_fact_ids,
            "max_findings": 4,
            "min_findings": 1,
            "outcome": "match",
            "rationale_code": "cross_gate_capchain_match",
            "rule_id": "CAP-CHAIN-001",
        }
    )
    expectations.sort(key=lambda item: cast(str, item["rule_id"]))
    case_path.write_text(
        json.dumps(case_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    fixture_path = corpus_root / "fixtures" / case_id / "facts.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    fixture["facts"] = facts
    fixture_path.write_text(
        json.dumps(fixture, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    loaded = load_calibration_corpus(corpus_root)
    case = next(item for item in loaded.cases if item.case_id == case_id)
    semantic_fingerprint = _semantic_fingerprint(case)

    def add_cross_gate_row(payload: dict[str, object]) -> None:
        rows = cast(list[dict[str, object]], payload["rows"])
        existing = next(row for row in rows if row["case_id"] == case_id)
        existing["semantic_fingerprint"] = semantic_fingerprint
        cross_gate = dict(existing)
        cross_gate.update(
            {
                "gate_id": "HG-CAPCHAIN-001",
                "expected_rule_ids": ["CAP-CHAIN-001"],
                "expected_gate_condition": "match",
                "is_positive": True,
                "is_negative_or_near_miss": False,
                "is_eligible_negative": False,
            }
        )
        rows.append(cross_gate)
        rows.sort(
            key=lambda row: (cast(str, row["gate_id"]), cast(str, row["case_id"]))
        )

    _rewrite_matrix(corpus_root, add_cross_gate_row)
    result = _run_coverage_cli("--corpus", str(corpus_root), "--format", "json")

    assert result.returncode == EXIT_READY, result.stderr
    report = _coverage_report(result)
    assert report["overall_status"] == "ready"


def test_coverage_cli_accepts_macos_tmp_alias_path() -> None:
    temporary = Path(tempfile.mkdtemp(prefix="agentsec-coverage-", dir="/tmp"))
    try:
        corpus_root = temporary / "calibration"
        shutil.copytree(CALIBRATION_ROOT, corpus_root)
        result = _run_coverage_cli(
            "--corpus",
            str(corpus_root),
            "--format",
            "json",
        )
        assert result.returncode == EXIT_READY, result.stderr
    finally:
        shutil.rmtree(temporary)
