"""Safe deterministic loading and structural validation of calibration corpora."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from agentsec.capability_rules import BUILTIN_CAPABILITY_RULE_IDS
from agentsec.versioning import CAPABILITY_RULE_PACK_VERSION

from .models import (
    CalibrationCase,
    CalibrationCorpusIndex,
)
from .validation import (
    CalibrationValidationError,
    decode_calibration_case_json,
    decode_calibration_corpus_json,
)

_MAX_INDEX_BYTES = 256 * 1024
_MAX_CASE_BYTES = 512 * 1024


class CalibrationCorpusError(RuntimeError):
    """Safe corpus loading failure without source content or host paths."""


@dataclass(frozen=True, slots=True)
class CalibrationCorpusSummary:
    """Deterministic corpus counts used before evaluation begins."""

    total_cases: int
    cases_by_kind: Mapping[str, int]
    cases_by_rule: Mapping[str, int]
    matching_cases_by_rule: Mapping[str, int]
    no_match_cases_by_rule: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class LoadedCalibrationCorpus:
    """Validated index plus immutable, sorted Calibration Cases."""

    root: Path
    index: CalibrationCorpusIndex
    cases: tuple[CalibrationCase, ...]

    @property
    def summary(self) -> CalibrationCorpusSummary:
        by_kind = Counter(case.case_kind.value for case in self.cases)
        by_rule: Counter[str] = Counter()
        matching: Counter[str] = Counter()
        no_match: Counter[str] = Counter()
        for case in self.cases:
            for expectation in case.ground_truth.rule_expectations:
                by_rule[expectation.rule_id] += 1
                if expectation.outcome.value == "match":
                    matching[expectation.rule_id] += 1
                else:
                    no_match[expectation.rule_id] += 1
        return CalibrationCorpusSummary(
            total_cases=len(self.cases),
            cases_by_kind=MappingProxyType(dict(sorted(by_kind.items()))),
            cases_by_rule=MappingProxyType(dict(sorted(by_rule.items()))),
            matching_cases_by_rule=MappingProxyType(dict(sorted(matching.items()))),
            no_match_cases_by_rule=MappingProxyType(dict(sorted(no_match.items()))),
        )


def load_calibration_corpus(
    root: Path,
    *,
    index_path: str = "corpus.json",
) -> LoadedCalibrationCorpus:
    """Load only bounded JSON metadata and verify fixture containment."""

    if not isinstance(root, Path):
        raise TypeError("calibration corpus root must be Path")
    if root.is_symlink() or not root.is_dir():
        raise CalibrationCorpusError("calibration corpus root is not a directory")
    root = root.resolve()
    index_file = _safe_child(root, index_path, label="corpus index")
    index = _read_index(index_file)
    if index.capability_rule_pack_version != CAPABILITY_RULE_PACK_VERSION:
        raise CalibrationCorpusError(
            "calibration corpus Rule Pack version is unsupported"
        )
    cases: list[CalibrationCase] = []
    case_ids: set[str] = set()
    for case_path in index.case_paths:
        path = _safe_child(root, case_path, label="case")
        case = _read_case(path)
        if case.case_id in case_ids:
            raise CalibrationCorpusError("calibration case IDs must be unique")
        case_ids.add(case.case_id)
        _validate_fixture(root, case)
        cases.append(case)
    ordered = tuple(sorted(cases, key=lambda item: item.case_id))
    _validate_rule_coverage(ordered)
    return LoadedCalibrationCorpus(root=root, index=index, cases=ordered)


def _read_index(path: Path) -> CalibrationCorpusIndex:
    text = _read_bounded_text(path, _MAX_INDEX_BYTES, "corpus index")
    try:
        return decode_calibration_corpus_json(text)
    except CalibrationValidationError as error:
        raise CalibrationCorpusError("corpus index is invalid") from error


def _read_case(path: Path) -> CalibrationCase:
    text = _read_bounded_text(path, _MAX_CASE_BYTES, "calibration case")
    try:
        return decode_calibration_case_json(text)
    except CalibrationValidationError as error:
        raise CalibrationCorpusError("calibration case is invalid") from error


def _read_bounded_text(path: Path, limit: int, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise CalibrationCorpusError(f"{label} is missing or unsafe")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CalibrationCorpusError(f"{label} cannot be read") from error
    if len(data) > limit:
        raise CalibrationCorpusError(f"{label} exceeds the bounded size")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CalibrationCorpusError(f"{label} must be UTF-8") from error


def _safe_child(root: Path, relative: str, *, label: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise CalibrationCorpusError(f"{label} escapes the corpus root") from error
    if candidate == root:
        raise CalibrationCorpusError(f"{label} cannot be the corpus root")
    return candidate


def _validate_fixture(root: Path, case: CalibrationCase) -> None:
    fixture_path = _safe_child(root, case.fixture.path, label="fixture")
    if fixture_path.is_symlink():
        raise CalibrationCorpusError("calibration fixture symlinks are not allowed")
    if case.fixture.kind.value == "project":
        if not fixture_path.is_dir():
            raise CalibrationCorpusError("project fixture must be a directory")
        fixture_base = fixture_path
        for asset in case.fixture.assets:
            asset_path = _safe_child(fixture_path, asset, label="fixture asset")
            if asset_path.is_symlink() or not asset_path.is_file():
                raise CalibrationCorpusError("fixture asset is missing or unsafe")
    else:
        if not fixture_path.is_file():
            raise CalibrationCorpusError("file fixture is missing")
        if fixture_path.stat().st_size > _MAX_CASE_BYTES:
            raise CalibrationCorpusError("file fixture exceeds the bounded size")
        fixture_base = fixture_path.parent
    for fact in case.ground_truth.facts:
        for evidence in fact.evidence:
            evidence_path = _safe_child(
                fixture_base, evidence.asset_path, label="evidence asset"
            )
            if evidence_path.is_symlink() or not evidence_path.is_file():
                raise CalibrationCorpusError("evidence asset is missing or unsafe")


def corpus_case_paths(root: Path) -> tuple[str, ...]:
    """Return sorted case JSON paths without opening fixture contents."""

    return tuple(
        str(path.relative_to(root).as_posix())
        for path in sorted(root.rglob("case.json"))
        if not path.is_symlink()
    )


def _validate_rule_coverage(cases: tuple[CalibrationCase, ...]) -> None:
    observed = {
        expectation.rule_id
        for case in cases
        for expectation in case.ground_truth.rule_expectations
    }
    required = set(BUILTIN_CAPABILITY_RULE_IDS)
    if observed != required:
        raise CalibrationCorpusError(
            "calibration corpus Rule coverage does not match the current Rule Pack"
        )
    for rule_id in sorted(required):
        outcomes = {
            expectation.outcome.value
            for case in cases
            for expectation in case.ground_truth.rule_expectations
            if expectation.rule_id == rule_id
        }
        if outcomes != {"match", "no_match"}:
            raise CalibrationCorpusError(
                "each Capability Rule requires match and no-match labels"
            )
