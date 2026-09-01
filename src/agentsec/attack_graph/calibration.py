"""P3-AG-08 human Evidence calibration for Attack Path associations."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.attack_graph.association import (
    AttackPathAssociationRelation,
    AttackPathEvidenceAssociation,
    AttackPathEvidenceAssociationReport,
    canonical_attack_path_evidence_association_sha256,
)

ATTACK_PATH_CALIBRATION_VERSION = "0.1.0"
ATTACK_PATH_CALIBRATION_FORMAT = "agentsec-attack-path-calibration-report"

_DIGEST = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_CASE_ID = Annotated[str, Field(pattern=r"^attack-cal-[a-z0-9]+(?:-[a-z0-9]+)*$")]
_PATH_ID = Annotated[str, Field(pattern=r"^attack-path-sha256:[0-9a-f]{64}$")]
_CANDIDATE_ID = Annotated[
    str, Field(pattern=r"^semantic-candidate-sha256:[0-9a-f]{64}$")
]
_REVIEWER_ID = Annotated[str, Field(min_length=1, max_length=128)]
_RATIONALE = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class AttackPathCalibrationCaseFamily(StrEnum):
    """Calibration strata used to expose different association failure modes."""

    EXACT_MATCH = "exact_match"
    PARTIAL_MATCH = "partial_match"
    HASH_MISMATCH = "hash_mismatch"
    PATH_MISMATCH = "path_mismatch"
    LINE_MISMATCH = "line_mismatch"
    RUNTIME_ONLY = "runtime_only"
    NO_SOURCE = "no_source"
    OTHER = "other"


class AttackPathCalibrationClassification(StrEnum):
    """Multi-class calibration outcome; not a CI decision."""

    CORRECT = "correct"
    INCORRECT = "incorrect"


class AttackPathCalibrationCase(_Strict):
    """One independent human label for one report association key."""

    case_id: _CASE_ID
    association_report_sha256: _DIGEST
    path_id: _PATH_ID
    target_kind: Literal["finding", "semantic_candidate"]
    target_id: str | None = Field(default=None, min_length=1, max_length=256)
    expected_relation: AttackPathAssociationRelation
    family: AttackPathCalibrationCaseFamily
    reviewer_id: _REVIEWER_ID
    rationale_code: _RATIONALE

    @model_validator(mode="after")
    def case_target_must_be_coherent(self) -> AttackPathCalibrationCase:
        if self.target_kind == "semantic_candidate" and (
            self.target_id is None
            or re.fullmatch(r"semantic-candidate-sha256:[0-9a-f]{64}", self.target_id)
            is None
        ):
            raise ValueError(
                "semantic calibration cases require a Semantic Candidate ID"
            )
        if self.expected_relation is not AttackPathAssociationRelation.UNMATCHED:
            if self.target_id is None:
                raise ValueError("matched calibration cases require a target ID")
        elif self.target_kind == "finding" and self.target_id is not None:
            raise ValueError(
                "unmatched Finding calibration cases must not name a Finding"
            )
        return self

    def sort_key(self) -> tuple[str, str, str]:
        return (self.path_id, self.target_kind, self.target_id or "")


class AttackPathCalibrationCaseResult(_Strict):
    """One comparison between an independent label and observed association."""

    case_id: _CASE_ID
    path_id: _PATH_ID
    target_kind: Literal["finding", "semantic_candidate"]
    target_id: str | None = None
    expected_relation: AttackPathAssociationRelation
    observed_relation: AttackPathAssociationRelation | Literal["missing"]
    classification: AttackPathCalibrationClassification

    @model_validator(mode="after")
    def result_classification_must_match(self) -> AttackPathCalibrationCaseResult:
        expected = self.expected_relation.value
        observed = (
            "missing"
            if self.observed_relation == "missing"
            else (
                self.observed_relation.value
                if isinstance(self.observed_relation, AttackPathAssociationRelation)
                else "missing"
            )
        )
        expected_classification = (
            AttackPathCalibrationClassification.CORRECT
            if expected == observed
            else AttackPathCalibrationClassification.INCORRECT
        )
        if self.classification is not expected_classification:
            raise ValueError("calibration classification is inconsistent")
        return self

    def sort_key(self) -> tuple[str, str, str]:
        return (self.path_id, self.target_kind, self.target_id or "")


class AttackPathCalibrationLabelMetrics(_Strict):
    """One-vs-rest metrics for one expected relation label."""

    relation: AttackPathAssociationRelation
    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    f1: float | None = Field(default=None, ge=0, le=1)


class AttackPathCalibrationMetrics(_Strict):
    """Deterministic multi-class calibration metrics."""

    case_count: int = Field(ge=1)
    correct_count: int = Field(ge=0)
    incorrect_count: int = Field(ge=0)
    accuracy: float = Field(ge=0, le=1)
    macro_precision: float | None = Field(default=None, ge=0, le=1)
    macro_recall: float | None = Field(default=None, ge=0, le=1)
    macro_f1: float | None = Field(default=None, ge=0, le=1)
    labels: tuple[AttackPathCalibrationLabelMetrics, ...]

    @model_validator(mode="after")
    def metrics_must_be_coherent(self) -> AttackPathCalibrationMetrics:
        if self.correct_count + self.incorrect_count != self.case_count:
            raise ValueError("calibration metric counts are inconsistent")
        if self.accuracy != _ratio(self.correct_count, self.case_count):
            raise ValueError("calibration accuracy is inconsistent")
        relations = tuple(item.relation for item in self.labels)
        expected = tuple(AttackPathAssociationRelation)
        if relations != expected:
            raise ValueError("calibration labels must cover every relation in order")
        return self


class AttackPathEvidenceCalibrationReport(_Strict):
    """Report-only human calibration of a frozen association report."""

    format: Literal["agentsec-attack-path-calibration-report"] = (
        "agentsec-attack-path-calibration-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    association_report_sha256: _DIGEST
    reviewed_case_count: int = Field(ge=1)
    unreviewed_association_count: int = Field(ge=0)
    reviewer_count: int = Field(ge=1)
    cases: tuple[AttackPathCalibrationCaseResult, ...]
    metrics: AttackPathCalibrationMetrics
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    finding_authority: Literal[False] = False
    semantic_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    hard_gate_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False
    limitations: tuple[str, ...] = (
        (
            "calibration measures agreement with independent labels for a "
            "frozen association report"
        ),
        (
            "seed or single-reviewer labels are not production quality "
            "qualification evidence"
        ),
        (
            "calibration does not modify associations, Findings, Severity, "
            "Confidence, Policy, or CI"
        ),
        (
            "static path correlation does not prove runtime reachability or "
            "exploitability"
        ),
    )

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> AttackPathEvidenceCalibrationReport:
        if self.reviewed_case_count != len(self.cases):
            raise ValueError("reviewed case count is inconsistent")
        if self.metrics.case_count != len(self.cases):
            raise ValueError("calibration metric case count is inconsistent")
        keys = tuple(item.sort_key() for item in self.cases)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("calibration results must be sorted and unique")
        if not self.limitations:
            raise ValueError("calibration report must disclose limitations")
        return self


class AttackPathEvidenceCalibrationRunner:
    """Compare independent labels with deterministic association output."""

    def run(
        self,
        report: AttackPathEvidenceAssociationReport,
        cases: tuple[AttackPathCalibrationCase, ...],
    ) -> AttackPathEvidenceCalibrationReport:
        if not isinstance(report, AttackPathEvidenceAssociationReport):
            raise TypeError("calibration requires AttackPathEvidenceAssociationReport")
        if not isinstance(cases, tuple) or not cases:
            raise TypeError("calibration cases must be a non-empty tuple")
        if any(not isinstance(item, AttackPathCalibrationCase) for item in cases):
            raise TypeError("calibration cases contain an invalid case")
        report_digest = canonical_attack_path_evidence_association_sha256(report)
        if any(item.association_report_sha256 != report_digest for item in cases):
            raise ValueError(
                "calibration case is bound to a different association report"
            )
        case_keys = tuple(item.sort_key() for item in cases)
        if case_keys != tuple(sorted(set(case_keys))):
            raise ValueError("calibration cases must be sorted and unique")

        association_keys = tuple(_association_key(item) for item in report.associations)
        if len(set(association_keys)) != len(association_keys):
            raise ValueError("association target keys must be unique")
        associations = {_association_key(item): item for item in report.associations}
        rows: list[AttackPathCalibrationCaseResult] = []
        for case in cases:
            observed = associations.get(case.sort_key())
            observed_relation: AttackPathAssociationRelation | Literal["missing"] = (
                "missing" if observed is None else observed.relation
            )
            rows.append(
                AttackPathCalibrationCaseResult(
                    case_id=case.case_id,
                    path_id=case.path_id,
                    target_kind=case.target_kind,
                    target_id=case.target_id,
                    expected_relation=case.expected_relation,
                    observed_relation=observed_relation,
                    classification=(
                        AttackPathCalibrationClassification.CORRECT
                        if observed_relation == case.expected_relation
                        else AttackPathCalibrationClassification.INCORRECT
                    ),
                )
            )
        ordered = tuple(sorted(rows, key=lambda item: item.sort_key()))
        metrics = _metrics(ordered)
        reviewed_keys = {item.sort_key() for item in cases}
        return AttackPathEvidenceCalibrationReport(
            association_report_sha256=report_digest,
            reviewed_case_count=len(ordered),
            unreviewed_association_count=len(
                set(associations).difference(reviewed_keys)
            ),
            reviewer_count=len({item.reviewer_id for item in cases}),
            cases=ordered,
            metrics=metrics,
        )


def _association_key(
    association: object,
) -> tuple[str, str, str]:
    """Return the stable lookup key shared by a report row and a case."""

    if not isinstance(association, AttackPathEvidenceAssociation):
        raise TypeError("association row is invalid")
    return (
        association.path_id,
        association.target_kind,
        association.finding_id or association.semantic_candidate_id or "",
    )


def _metrics(
    cases: tuple[AttackPathCalibrationCaseResult, ...],
) -> AttackPathCalibrationMetrics:
    correct = sum(
        item.classification is AttackPathCalibrationClassification.CORRECT
        for item in cases
    )
    labels: list[AttackPathCalibrationLabelMetrics] = []
    for relation in AttackPathAssociationRelation:
        true_positive = sum(
            item.expected_relation is relation and item.observed_relation is relation
            for item in cases
        )
        false_positive = sum(
            item.expected_relation is not relation
            and item.observed_relation is relation
            for item in cases
        )
        false_negative = sum(
            item.expected_relation is relation
            and item.observed_relation is not relation
            for item in cases
        )
        precision = _ratio(true_positive, true_positive + false_positive)
        recall = _ratio(true_positive, true_positive + false_negative)
        f1 = (
            None
            if precision is None or recall is None or precision + recall == 0
            else round(2 * precision * recall / (precision + recall), 6)
        )
        labels.append(
            AttackPathCalibrationLabelMetrics(
                relation=relation,
                true_positive=true_positive,
                false_positive=false_positive,
                false_negative=false_negative,
                precision=precision,
                recall=recall,
                f1=f1,
            )
        )
    available = [item for item in labels if item.precision is not None]
    recall_available = [item for item in labels if item.recall is not None]
    f1_available = [item for item in labels if item.f1 is not None]
    return AttackPathCalibrationMetrics(
        case_count=len(cases),
        correct_count=correct,
        incorrect_count=len(cases) - correct,
        accuracy=_ratio(correct, len(cases)) or 0.0,
        macro_precision=(
            _average(item.precision for item in available) if available else None
        ),
        macro_recall=(
            _average(item.recall for item in recall_available)
            if recall_available
            else None
        ),
        macro_f1=_average(item.f1 for item in f1_available) if f1_available else None,
        labels=tuple(labels),
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _average(values: Iterable[float | None]) -> float | None:
    numbers = [float(value) for value in values if value is not None]
    return round(sum(numbers) / len(numbers), 6) if numbers else None


def encode_attack_path_calibration_json(
    report: AttackPathEvidenceCalibrationReport,
) -> str:
    """Encode a validated calibration report as canonical JSON."""

    if not isinstance(report, AttackPathEvidenceCalibrationReport):
        raise TypeError(
            "calibration encoder requires AttackPathEvidenceCalibrationReport"
        )
    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_attack_path_calibration_text(
    report: AttackPathEvidenceCalibrationReport,
) -> str:
    """Render a bounded human-review calibration summary."""

    if not isinstance(report, AttackPathEvidenceCalibrationReport):
        raise TypeError(
            "calibration renderer requires AttackPathEvidenceCalibrationReport"
        )
    lines = [
        "AgentSec Attack Path Evidence Calibration Report",
        f"Format: {report.format} {report.schema_version}",
        f"Reviewed Cases: {report.reviewed_case_count}",
        f"Unreviewed Associations: {report.unreviewed_association_count}",
        f"Reviewers: {report.reviewer_count}",
        f"Accuracy: {report.metrics.accuracy}",
    ]
    for label in report.metrics.labels:
        lines.append(
            f"- {label.relation.value}: precision={label.precision} "
            f"recall={label.recall} f1={label.f1}"
        )
    lines.extend(
        (
            "Mode: report_only=true; blocks=false; no authority granted",
            (
                "Calibration is reviewer evidence for a frozen report; it does not "
                "tune or publish rules."
            ),
        )
    )
    return "\n".join(lines) + "\n"


def export_attack_path_calibration_json_schema(output_path: Path) -> Path:
    """Export the frozen Attack Path calibration report Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("calibration Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            AttackPathEvidenceCalibrationReport.model_json_schema(mode="serialization"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


__all__ = [
    "ATTACK_PATH_CALIBRATION_FORMAT",
    "ATTACK_PATH_CALIBRATION_VERSION",
    "AttackPathCalibrationCase",
    "AttackPathCalibrationCaseFamily",
    "AttackPathCalibrationCaseResult",
    "AttackPathCalibrationClassification",
    "AttackPathCalibrationLabelMetrics",
    "AttackPathCalibrationMetrics",
    "AttackPathEvidenceCalibrationReport",
    "AttackPathEvidenceCalibrationRunner",
    "encode_attack_path_calibration_json",
    "export_attack_path_calibration_json_schema",
    "render_attack_path_calibration_text",
]
