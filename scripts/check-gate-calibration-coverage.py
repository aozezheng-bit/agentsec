"""Check P2-CAL-04A Gate candidate sample coverage from the coverage matrix.

This tool is report-only. It never edits Rules, the Risk Model, Reviewer
Labels, or Gate enforcement, and it never enables CI blocking. It reads only
bounded JSON metadata; Case Fixture contents are never opened or executed.

The Gate candidate definitions are pinned in this tool. The untrusted Matrix
must reproduce them exactly; it cannot introduce new Gates, different
component Rules, different floors, or different sample thresholds. Sample
counts are computed over unique semantic fingerprints recomputed from the
Corpus ground truth, never over raw Matrix rows.

Exit codes:
  0 = every approved candidate Gate meets its minimum sample requirements
  2 = the Corpus or Matrix is incomplete (for example samples are missing)
  4 = input format, path, or Schema is invalid
  5 = the tool failed to execute
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsec.calibration import (
    CalibrationCase,
    CalibrationCorpusError,
    load_calibration_corpus,
)

EXIT_READY = 0
EXIT_INCOMPLETE = 2
EXIT_INVALID = 4
EXIT_FAILED = 5

_MATRIX_FORMAT = "agentsec-gate-coverage-matrix"
_REPORT_FORMAT = "agentsec-gate-coverage-check"
_REPORT_SCHEMA_VERSION = "0.1.0"
_SUPPORTED_MATRIX_SCHEMA_VERSIONS = frozenset({"0.2.0"})
_MAX_MATRIX_BYTES = 4 * 1024 * 1024
_MAX_ROWS = 100_000

_SCENARIO_ID_PATTERN = re.compile(r"^scenario-[a-z0-9]+(?:-[a-z0-9]+)*$")
_FINGERPRINT_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

_CASE_KINDS = frozenset({"positive", "negative", "near_miss"})
_COVERAGE_VALUES = frozenset({"complete", "incomplete"})
_GATE_CONDITIONS = frozenset({"match", "no_match"})
_LANGUAGES = frozenset({"en", "zh", "bilingual"})
_FORMATS = frozenset({"json", "manifest", "markdown", "toml", "yaml"})
_REVIEW_STATUSES = frozenset({"seeded", "reviewed", "adjudicated"})
_SOURCE_FILENAMES = {
    "markdown": "source.md",
    "json": "source.json",
    "yaml": "source.yaml",
    "toml": "source.toml",
    "manifest": "source.manifest.json",
}


@dataclass(frozen=True, slots=True)
class _GateRequirement:
    """Trusted, tool-pinned Gate candidate definition."""

    gate_id: str
    floor: str
    component_rule_ids: tuple[str, ...]
    min_positive_samples: int
    min_negative_or_near_miss_samples: int


_APPROVED_GATE_REQUIREMENTS: tuple[_GateRequirement, ...] = (
    _GateRequirement(
        gate_id="HG-CAPCHAIN-001",
        floor="high",
        component_rule_ids=("CAP-CHAIN-001",),
        min_positive_samples=20,
        min_negative_or_near_miss_samples=20,
    ),
    _GateRequirement(
        gate_id="HG-EXTERNALPROD-001",
        floor="critical",
        component_rule_ids=(
            "CAP-EXTERNALPRIVILEGED-001",
            "CAP-PRODADMIN-001",
            "CAP-PRODIDENTITY-001",
            "CAP-PRODWRITE-001",
        ),
        min_positive_samples=20,
        min_negative_or_near_miss_samples=20,
    ),
    _GateRequirement(
        gate_id="HG-PRODAUTO-001",
        floor="high",
        component_rule_ids=("CAP-APPROVAL-001", "CAP-AUTOPROD-001"),
        min_positive_samples=20,
        min_negative_or_near_miss_samples=20,
    ),
)
_APPROVED_BY_ID = {item.gate_id: item for item in _APPROVED_GATE_REQUIREMENTS}


class _InputError(Exception):
    """Invalid input format, path, or Schema (exit code 4)."""


class _IncompleteError(Exception):
    """Incomplete Corpus or Matrix cross-references (exit code 2)."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        raise SystemExit(EXIT_INVALID) from None


@dataclass(slots=True)
class _GateStats:
    requirement: _GateRequirement
    positive_count: int = 0
    negative_count: int = 0
    near_miss_count: int = 0
    unknown_count: int = 0
    incomplete_count: int = 0
    eligible_positive_fingerprints: set[str] = field(default_factory=set)
    eligible_negative_fingerprints: set[str] = field(default_factory=set)
    language_distribution: Counter[str] = field(default_factory=Counter)
    format_distribution: Counter[str] = field(default_factory=Counter)

    @property
    def eligible_positive_count(self) -> int:
        return len(self.eligible_positive_fingerprints)

    @property
    def eligible_negative_count(self) -> int:
        return len(self.eligible_negative_fingerprints)

    @property
    def missing_sample_count(self) -> int:
        missing_positive = max(
            0, self.requirement.min_positive_samples - self.eligible_positive_count
        )
        missing_negative = max(
            0,
            self.requirement.min_negative_or_near_miss_samples
            - self.eligible_negative_count,
        )
        return missing_positive + missing_negative

    @property
    def coverage_status(self) -> str:
        return "ready" if self.missing_sample_count == 0 else "more_data_required"


def _fail_invalid(message: str) -> None:
    raise _InputError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise _InputError(message)


def _bounded_boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        _fail_invalid(f"{label} must be a boolean")
    return value


def _bounded_choice(value: object, label: str, choices: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        _fail_invalid(f"{label} must be one of {sorted(choices)}")
    return value


def _bounded_pattern(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _fail_invalid(f"{label} must match {pattern.pattern}")
    return value


def _resolve_corpus_root(raw_root: Path) -> tuple[Path, Path]:
    lexical = Path(os.path.abspath(raw_root))
    if lexical.is_symlink() or not lexical.is_dir():
        _fail_invalid("corpus root is not a directory or is a symlink")
    resolved = lexical.resolve()
    if not resolved.is_dir():
        _fail_invalid("corpus root cannot be resolved")
    return lexical, resolved


def _reject_symlink_components(
    corpus_root: Path, relative_parts: tuple[str, ...]
) -> None:
    current = corpus_root
    for part in relative_parts:
        current = current / part
        if current.is_symlink():
            _fail_invalid("path contains a symlink")


def _resolve_matrix_path(
    lexical_root: Path,
    resolved_root: Path,
    raw_matrix: Path | None,
) -> Path:
    candidate = (
        lexical_root / "gate-coverage-matrix.json" if raw_matrix is None else raw_matrix
    )
    # Lexical normalization only: symlinks must stay visible at this stage.
    lexical = Path(os.path.abspath(candidate))
    try:
        relative = lexical.relative_to(lexical_root)
    except ValueError:
        _fail_invalid("matrix path escapes the corpus root")
    if not relative.parts:
        _fail_invalid("matrix path cannot be the corpus root")
    _reject_symlink_components(resolved_root, relative.parts)
    resolved = lexical.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        _fail_invalid("matrix path escapes the corpus root")
    if not resolved.is_file():
        _fail_invalid("matrix file is missing")
    return resolved


def _read_matrix_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise _InputError("matrix file cannot be read") from error
    if len(data) > _MAX_MATRIX_BYTES:
        _fail_invalid("matrix file exceeds the bounded size")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _InputError("matrix file must be UTF-8") from error


def _load_matrix_payload(path: Path) -> dict[str, Any]:
    text = _read_matrix_text(path)
    try:
        payload: object = json.loads(text)
    except json.JSONDecodeError as error:
        raise _InputError("matrix file is not valid JSON") from error
    if not isinstance(payload, dict):
        _fail_invalid("matrix payload must be a JSON object")
    _require(
        payload.get("format") == _MATRIX_FORMAT,
        "matrix format identifier is unsupported",
    )
    schema_version = payload.get("schema_version")
    if (
        not isinstance(schema_version, str)
        or schema_version not in _SUPPORTED_MATRIX_SCHEMA_VERSIONS
    ):
        _fail_invalid("matrix schema_version is unsupported")
    gates = payload.get("gates")
    rows = payload.get("rows")
    if not isinstance(gates, list) or not gates:
        _fail_invalid("matrix gates must be a non-empty list")
    if not isinstance(rows, list):
        _fail_invalid("matrix rows must be a list")
    if len(rows) > _MAX_ROWS:
        _fail_invalid("matrix rows exceed the bounded count")
    return payload


def _bind_matrix_to_corpus(
    payload: dict[str, Any], corpus_id: str, rule_pack: str
) -> None:
    if payload.get("corpus_id") != corpus_id:
        _fail_invalid("matrix corpus_id does not match the corpus")
    if payload.get("capability_rule_pack_version") != rule_pack:
        _fail_invalid("matrix Rule Pack version does not match the corpus")


def _parse_gates(payload: dict[str, Any]) -> dict[str, _GateRequirement]:
    declared: set[str] = set()
    for entry in payload["gates"]:
        if not isinstance(entry, dict):
            _fail_invalid("gate entries must be JSON objects")
        gate_id = entry.get("gate_id")
        if not isinstance(gate_id, str):
            _fail_invalid("gate_id must be a string")
        approved = _APPROVED_BY_ID.get(gate_id)
        if approved is None:
            _fail_invalid("matrix declares an unapproved gate_id")
        if gate_id in declared:
            _fail_invalid("duplicate gate_id in matrix gates")
        declared.add(gate_id)
        component_rule_ids = entry.get("component_rule_ids")
        if not isinstance(component_rule_ids, list):
            _fail_invalid("component_rule_ids must be a list")
        if tuple(component_rule_ids) != approved.component_rule_ids:
            _fail_invalid("gate component_rule_ids differ from the approved definition")
        if entry.get("floor") != approved.floor:
            _fail_invalid("gate floor differs from the approved definition")
        if entry.get("min_positive_samples") != approved.min_positive_samples:
            _fail_invalid("gate min_positive_samples differs from the approved value")
        if (
            entry.get("min_negative_or_near_miss_samples")
            != approved.min_negative_or_near_miss_samples
        ):
            _fail_invalid(
                "gate min_negative_or_near_miss_samples differs from the approved value"
            )
    missing = set(_APPROVED_BY_ID) - declared
    if missing:
        raise _IncompleteError("matrix omits an approved gate")
    return dict(_APPROVED_BY_ID)


def _validate_row(
    row: object,
    seen_rows: set[tuple[str, str]],
    seen_scenarios: set[tuple[str, str]],
) -> None:
    if not isinstance(row, dict):
        _fail_invalid("matrix rows must be JSON objects")
    case_id = row.get("case_id")
    if not isinstance(case_id, str) or not case_id.startswith("cal-"):
        _fail_invalid("case_id must use the cal- prefixed form")
    gate_id = row.get("gate_id")
    if not isinstance(gate_id, str) or gate_id not in _APPROVED_BY_ID:
        _fail_invalid("matrix row references an unknown gate_id")
    key = (gate_id, case_id)
    if key in seen_rows:
        _fail_invalid("duplicate (gate_id, case_id) row in matrix")
    seen_rows.add(key)
    approved = _APPROVED_BY_ID[gate_id]

    expected_rule_ids = row.get("expected_rule_ids")
    if not isinstance(expected_rule_ids, list):
        _fail_invalid("expected_rule_ids must be a list")
    if tuple(expected_rule_ids) != approved.component_rule_ids:
        _fail_invalid("row expected_rule_ids differ from the approved gate definition")

    case_kind = _bounded_choice(row.get("case_kind"), "case_kind", _CASE_KINDS)
    coverage = _bounded_choice(row.get("coverage"), "coverage", _COVERAGE_VALUES)
    condition = _bounded_choice(
        row.get("expected_gate_condition"), "expected_gate_condition", _GATE_CONDITIONS
    )
    _bounded_choice(row.get("language"), "language", _LANGUAGES)
    _bounded_choice(row.get("format"), "format", _FORMATS)
    _bounded_choice(row.get("review_status"), "review_status", _REVIEW_STATUSES)
    scenario_id = _bounded_pattern(
        row.get("scenario_id"), "scenario_id", _SCENARIO_ID_PATTERN
    )
    scenario_key = (gate_id, scenario_id)
    if scenario_key in seen_scenarios:
        _fail_invalid("duplicate scenario_id inside an approved gate")
    seen_scenarios.add(scenario_key)
    _bounded_pattern(
        row.get("semantic_fingerprint"), "semantic_fingerprint", _FINGERPRINT_PATTERN
    )
    is_positive = _bounded_boolean(row.get("is_positive"), "is_positive")
    is_negative = _bounded_boolean(
        row.get("is_negative_or_near_miss"), "is_negative_or_near_miss"
    )
    is_eligible = _bounded_boolean(
        row.get("is_eligible_negative"), "is_eligible_negative"
    )
    has_unknown = _bounded_boolean(row.get("has_unknown"), "has_unknown")

    if is_positive and is_negative:
        _fail_invalid("positive and negative labels conflict")
    if not is_positive and not is_negative:
        _fail_invalid("row must be labeled positive or negative/near-miss")
    if case_kind == "positive" and not is_positive:
        _fail_invalid("positive case_kind conflicts with is_positive")
    if case_kind != "positive" and is_positive:
        _fail_invalid("non-positive case_kind conflicts with is_positive")
    if condition == "match" and not is_positive:
        _fail_invalid("match condition conflicts with negative label")
    if condition == "no_match" and is_positive:
        _fail_invalid("no_match condition conflicts with positive label")
    trusted_eligible = is_negative and coverage == "complete" and not has_unknown
    if is_eligible != trusted_eligible:
        _fail_invalid("is_eligible_negative disagrees with the trusted computation")

    source_asset_path = row.get("source_asset_path")
    if not isinstance(source_asset_path, str) or not source_asset_path:
        _fail_invalid("source_asset_path must be a non-empty string")
    if (
        source_asset_path.startswith("/")
        or "\\" in source_asset_path
        or any(part in ("", ".", "..") for part in source_asset_path.split("/"))
    ):
        _fail_invalid("source_asset_path must be a safe relative path")


def _semantic_fingerprint(case: CalibrationCase) -> str:
    """Recompute the value-free semantic fingerprint from Corpus ground truth."""

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


def _cross_check_corpus(
    corpus_cases: dict[str, CalibrationCase],
    rows: list[dict[str, Any]],
) -> None:
    for row in rows:
        case_id = row["case_id"]
        case = corpus_cases.get(case_id)
        if case is None:
            raise _IncompleteError("matrix references a case missing from the corpus")
        if case.case_kind.value != row["case_kind"]:
            _fail_invalid("matrix case_kind disagrees with the corpus")
        if case.language.value != row["language"]:
            _fail_invalid("matrix language disagrees with the corpus")
        if row["format"] not in {item.value for item in case.source_formats}:
            _fail_invalid("matrix format is not a declared source format")
        if case.ground_truth.coverage != row["coverage"]:
            _fail_invalid("matrix coverage disagrees with the corpus")
        if bool(case.ground_truth.unknown_dimensions) != row["has_unknown"]:
            _fail_invalid("matrix unknown flag disagrees with the corpus")
        expectations_by_rule = {
            expectation.rule_id: expectation
            for expectation in case.ground_truth.rule_expectations
        }
        selected_rule_ids = tuple(row["expected_rule_ids"])
        if any(rule_id not in expectations_by_rule for rule_id in selected_rule_ids):
            _fail_invalid("row expected_rule_ids are missing from case expectations")
        computed_condition = (
            "match"
            if all(
                expectations_by_rule[rule_id].outcome.value == "match"
                for rule_id in selected_rule_ids
            )
            else "no_match"
        )
        if computed_condition != row["expected_gate_condition"]:
            _fail_invalid(
                "expected_gate_condition disagrees with the case expectations"
            )
        if _semantic_fingerprint(case) != row["semantic_fingerprint"]:
            _fail_invalid("semantic_fingerprint disagrees with the corpus ground truth")
        if row["review_status"] != case.review.status.value:
            _fail_invalid("review_status disagrees with the case review status")
        expected_scenario_id = f"scenario-{case.case_id.removeprefix('cal-')}"
        if row["scenario_id"] != expected_scenario_id:
            _fail_invalid("scenario_id disagrees with the case identity")


def _check_source_assets(
    corpus_root: Path,
    corpus_cases: dict[str, CalibrationCase],
    rows: list[dict[str, Any]],
) -> None:
    for row in rows:
        relative = row["source_asset_path"]
        case = corpus_cases[row["case_id"]]
        expected = (
            Path(case.fixture.path).parent / _SOURCE_FILENAMES[row["format"]]
        ).as_posix()
        if relative != expected:
            _fail_invalid(
                "source_asset_path does not match the Case fixture and format"
            )
        parts = tuple(relative.split("/"))
        _reject_symlink_components(corpus_root, parts)
        resolved = (corpus_root / relative).resolve()
        try:
            resolved.relative_to(corpus_root)
        except ValueError:
            _fail_invalid("source_asset_path escapes the corpus root")
        if not resolved.is_file():
            raise _IncompleteError("matrix source asset is missing from the corpus")


def _build_stats(
    requirements: dict[str, _GateRequirement],
    rows: list[dict[str, Any]],
) -> dict[str, _GateStats]:
    stats = {
        gate_id: _GateStats(requirement)
        for gate_id, requirement in requirements.items()
    }
    for row in rows:
        gate = stats[row["gate_id"]]
        if row["is_positive"]:
            gate.positive_count += 1
        elif row["case_kind"] == "negative":
            gate.negative_count += 1
        else:
            gate.near_miss_count += 1
        if row["has_unknown"]:
            gate.unknown_count += 1
        if row["coverage"] != "complete":
            gate.incomplete_count += 1
        eligible = row["coverage"] == "complete" and not row["has_unknown"]
        if eligible:
            fingerprint = row["semantic_fingerprint"]
            if (
                fingerprint in gate.eligible_positive_fingerprints
                or fingerprint in gate.eligible_negative_fingerprints
            ):
                _fail_invalid("duplicate semantic fingerprint inside an approved gate")
            if row["is_positive"]:
                gate.eligible_positive_fingerprints.add(fingerprint)
            else:
                gate.eligible_negative_fingerprints.add(fingerprint)
        gate.language_distribution[row["language"]] += 1
        gate.format_distribution[row["format"]] += 1
    return stats


def _render_text(stats: dict[str, _GateStats]) -> str:
    lines: list[str] = []
    for gate_id in sorted(stats):
        gate = stats[gate_id]
        languages = ", ".join(
            f"{name}={count}"
            for name, count in sorted(gate.language_distribution.items())
        )
        formats = ", ".join(
            f"{name}={count}"
            for name, count in sorted(gate.format_distribution.items())
        )
        lines.append(gate_id)
        lines.append(f"  positive: {gate.positive_count}")
        lines.append(f"  negative: {gate.negative_count}")
        lines.append(f"  near_miss: {gate.near_miss_count}")
        lines.append(f"  unknown: {gate.unknown_count}")
        lines.append(f"  incomplete: {gate.incomplete_count}")
        lines.append(f"  eligible_positive: {gate.eligible_positive_count}")
        lines.append(
            f"  eligible_negative_or_near_miss: {gate.eligible_negative_count}"
        )
        lines.append(f"  min_positive: {gate.requirement.min_positive_samples}")
        lines.append(
            "  min_negative_or_near_miss: "
            f"{gate.requirement.min_negative_or_near_miss_samples}"
        )
        lines.append(f"  languages: {languages or 'none'}")
        lines.append(f"  formats: {formats or 'none'}")
        lines.append(f"  status: {gate.coverage_status}")
        lines.append(f"  missing_samples: {gate.missing_sample_count}")
    ready = all(gate.coverage_status == "ready" for gate in stats.values())
    lines.append(f"overall: {'ready' if ready else 'more_data_required'}")
    return "\n".join(lines) + "\n"


def _render_json(stats: dict[str, _GateStats]) -> str:
    gates = []
    for gate_id in sorted(stats):
        gate = stats[gate_id]
        gates.append(
            {
                "gate_id": gate_id,
                "positive_count": gate.positive_count,
                "negative_count": gate.negative_count,
                "near_miss_count": gate.near_miss_count,
                "unknown_count": gate.unknown_count,
                "incomplete_count": gate.incomplete_count,
                "eligible_positive_count": gate.eligible_positive_count,
                "eligible_negative_or_near_miss_count": gate.eligible_negative_count,
                "min_positive_samples": gate.requirement.min_positive_samples,
                "min_negative_or_near_miss_samples": (
                    gate.requirement.min_negative_or_near_miss_samples
                ),
                "language_distribution": dict(
                    sorted(gate.language_distribution.items())
                ),
                "format_distribution": dict(sorted(gate.format_distribution.items())),
                "coverage_status": gate.coverage_status,
                "missing_sample_count": gate.missing_sample_count,
            }
        )
    ready = all(gate["coverage_status"] == "ready" for gate in gates)
    payload = {
        "format": _REPORT_FORMAT,
        "schema_version": _REPORT_SCHEMA_VERSION,
        "ci_blocking_enabled": False,
        "enforcement_mode": "report_only",
        "overall_status": "ready" if ready else "more_data_required",
        "gates": gates,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _run(corpus: Path, matrix: Path | None, output_format: str) -> int:
    lexical_root, corpus_root = _resolve_corpus_root(corpus)
    matrix_path = _resolve_matrix_path(lexical_root, corpus_root, matrix)
    try:
        loaded = load_calibration_corpus(corpus_root)
    except CalibrationCorpusError as error:
        raise _InputError("calibration corpus failed validation") from error
    payload = _load_matrix_payload(matrix_path)
    _bind_matrix_to_corpus(
        payload,
        loaded.index.corpus_id,
        loaded.index.capability_rule_pack_version,
    )
    requirements = _parse_gates(payload)
    seen_rows: set[tuple[str, str]] = set()
    seen_scenarios: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for raw_row in payload["rows"]:
        _validate_row(raw_row, seen_rows, seen_scenarios)
        rows.append(raw_row)
    corpus_cases = {case.case_id: case for case in loaded.cases}
    _cross_check_corpus(corpus_cases, rows)
    _check_source_assets(corpus_root, corpus_cases, rows)
    stats = _build_stats(requirements, rows)
    rendered = _render_json(stats) if output_format == "json" else _render_text(stats)
    print(rendered, end="")
    if any(gate.missing_sample_count > 0 for gate in stats.values()):
        return EXIT_INCOMPLETE
    return EXIT_READY


def main() -> None:
    parser = _ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("calibration"))
    parser.add_argument("--matrix", type=Path, default=None)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    try:
        code = _run(args.corpus, args.matrix, args.format)
    except _IncompleteError as error:
        print(f"incomplete corpus or matrix: {error}", file=sys.stderr)
        code = EXIT_INCOMPLETE
    except _InputError as error:
        print(f"invalid input: {error}", file=sys.stderr)
        code = EXIT_INVALID
    except Exception as error:  # noqa: BLE001 - fail closed with exit code 5
        print(f"coverage check failed: {type(error).__name__}", file=sys.stderr)
        code = EXIT_FAILED
    raise SystemExit(code)


if __name__ == "__main__":
    main()
