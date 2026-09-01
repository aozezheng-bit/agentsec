"""Report-only Attack Path context for the Integrated Agentic Score.

Attack Paths are useful explanatory evidence, but an uncalibrated static path is
not itself a risk score.  This module deliberately projects the frozen Attack
Path association/calibration reports into a score context without changing any
Technical, Drift, Governance, Overall, Severity, or Hard Gate result.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.attack_graph import (
    AttackPathAssociationRelation,
    AttackPathEvidenceAssociationReport,
    AttackPathEvidenceCalibrationReport,
    canonical_attack_path_evidence_association_sha256,
)
from agentsec.versioning import ATTACK_PATH_SCORE_CONTEXT_VERSION

ATTACK_PATH_SCORE_CONTEXT_FORMAT = "agentsec-attack-path-score-context"
_DIGEST = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class AttackPathScoreIntegrationError(ValueError):
    """Safe failure while binding Attack Path evidence to a score report."""


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class AttackPathRelationCounts(_Strict):
    """Stable counts for every association relation."""

    supports: int = Field(ge=0)
    partially_supports: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    unmatched: int = Field(ge=0)

    @property
    def total(self) -> int:
        return (
            self.supports + self.partially_supports + self.duplicates + self.unmatched
        )


class AttackPathScoreContext(_Strict):
    """Bounded report context attached to an Agentic Score result.

    ``scoring_mode=context_only`` and ``numeric_score_effect=0.0`` are literal
    contract values.  They prevent path volume or fixture calibration accuracy
    from silently becoming risk points before a separately approved scoring
    model and real calibration evidence exist.
    """

    format: Literal["agentsec-attack-path-score-context"] = (
        "agentsec-attack-path-score-context"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    association_report_sha256: _DIGEST
    path_report_sha256: _DIGEST
    path_count: int = Field(ge=0)
    association_count: int = Field(ge=0)
    finding_association_count: int = Field(ge=0)
    semantic_association_count: int = Field(ge=0)
    relation_counts: AttackPathRelationCounts
    calibration_report_sha256: _DIGEST | None = None
    calibration_accuracy: float | None = Field(default=None, ge=0, le=1)
    calibration_reviewed_case_count: int | None = Field(default=None, ge=1)
    calibration_qualified: Literal[False] = False
    scoring_mode: Literal["context_only"] = "context_only"
    numeric_score_effect: float = Field(default=0.0, ge=0, le=0)
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    finding_authority: Literal[False] = False
    semantic_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    hard_gate_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def context_must_be_coherent(self) -> AttackPathScoreContext:
        if self.association_count != self.relation_counts.total:
            raise ValueError("Attack Path relation counts are inconsistent")
        if self.finding_association_count + self.semantic_association_count != (
            self.association_count
        ):
            raise ValueError("Attack Path target counts are inconsistent")
        if self.calibration_report_sha256 is None:
            if (
                self.calibration_accuracy is not None
                or self.calibration_reviewed_case_count is not None
            ):
                raise ValueError("calibration metrics require a calibration digest")
        elif (
            self.calibration_accuracy is None
            or self.calibration_reviewed_case_count is None
        ):
            raise ValueError(
                "calibration digest requires accuracy and reviewed case count"
            )
        return self

    def to_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


def build_attack_path_score_context(
    association_report: AttackPathEvidenceAssociationReport,
    calibration_report: AttackPathEvidenceCalibrationReport | None = None,
) -> AttackPathScoreContext:
    """Build a report-only context from validated, content-addressed reports."""

    if not isinstance(association_report, AttackPathEvidenceAssociationReport):
        raise TypeError(
            "Attack Path Score context requires an evidence association report"
        )
    if calibration_report is not None and not isinstance(
        calibration_report, AttackPathEvidenceCalibrationReport
    ):
        raise TypeError("Attack Path calibration report has an invalid type")

    relation_counts = {relation.value: 0 for relation in AttackPathAssociationRelation}
    finding_count = 0
    semantic_count = 0
    for association in association_report.associations:
        relation_counts[association.relation.value] += 1
        if association.target_kind == "finding":
            finding_count += 1
        else:
            semantic_count += 1

    calibration_digest: str | None = None
    calibration_accuracy: float | None = None
    reviewed_case_count: int | None = None
    if calibration_report is not None:
        expected_digest = canonical_attack_path_evidence_association_sha256(
            association_report
        )
        if calibration_report.association_report_sha256 != expected_digest:
            raise AttackPathScoreIntegrationError(
                "Attack Path calibration report is bound to a different "
                "association report"
            )
        calibration_digest = _canonical_report_hash(calibration_report)
        calibration_accuracy = calibration_report.metrics.accuracy
        reviewed_case_count = calibration_report.reviewed_case_count

    return AttackPathScoreContext(
        association_report_sha256=canonical_attack_path_evidence_association_sha256(
            association_report
        ),
        path_report_sha256=association_report.path_report_sha256,
        path_count=association_report.path_count,
        association_count=association_report.association_count,
        finding_association_count=finding_count,
        semantic_association_count=semantic_count,
        relation_counts=AttackPathRelationCounts.model_validate(relation_counts),
        calibration_report_sha256=calibration_digest,
        calibration_accuracy=calibration_accuracy,
        calibration_reviewed_case_count=reviewed_case_count,
    )


def encode_attack_path_score_context_json(context: AttackPathScoreContext) -> str:
    """Encode the context as deterministic, secret-free JSON."""

    if not isinstance(context, AttackPathScoreContext):
        raise TypeError("Attack Path Score context encoder requires its model")
    return (
        json.dumps(
            context.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def export_attack_path_score_context_json_schema(output_path: Path) -> Path:
    """Export the standalone Attack Path Score Context schema."""

    if not isinstance(output_path, Path):
        raise TypeError("Attack Path Score Context schema path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            AttackPathScoreContext.model_json_schema(mode="serialization"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


def _canonical_report_hash(report: BaseModel) -> str:
    payload = report.model_dump(mode="json")
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "ATTACK_PATH_SCORE_CONTEXT_FORMAT",
    "ATTACK_PATH_SCORE_CONTEXT_VERSION",
    "AttackPathRelationCounts",
    "AttackPathScoreIntegrationError",
    "AttackPathScoreContext",
    "build_attack_path_score_context",
    "encode_attack_path_score_context_json",
    "export_attack_path_score_context_json_schema",
]
