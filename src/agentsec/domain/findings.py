"""Evidence and security finding domain models."""

from __future__ import annotations

import math
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from agentsec.domain.base import (
    DomainModel,
    NonEmptyString,
    Sha256Digest,
    validate_relative_path,
)
from agentsec.domain.enums import (
    EvidenceConfidence,
    EvidenceSource,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)
from agentsec.versioning import CVSS_HARD_GATE_VERSION

_CVSS_V31_METRIC_VALUES = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}
_CVSS_V40_METRIC_VALUES = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "AT": {"N", "P"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "P", "A"},
    "VC": {"N", "L", "H"},
    "VI": {"N", "L", "H"},
    "VA": {"N", "L", "H"},
    "SC": {"N", "L", "H"},
    "SI": {"N", "L", "H", "S"},
    "SA": {"N", "L", "H", "S"},
}
_CVSS_V31_EXTENDED_METRIC_VALUES = {
    "E": {"X", "U", "P", "F", "H"},
    "RL": {"X", "O", "T", "W", "U"},
    "RC": {"X", "U", "R", "C"},
    "CR": {"X", "L", "M", "H"},
    "IR": {"X", "L", "M", "H"},
    "AR": {"X", "L", "M", "H"},
    "MAV": {"X", "N", "A", "L", "P"},
    "MAC": {"X", "L", "H"},
    "MPR": {"X", "N", "L", "H"},
    "MUI": {"X", "N", "R"},
    "MS": {"X", "U", "C"},
    "MC": {"X", "N", "L", "H"},
    "MI": {"X", "N", "L", "H"},
    "MA": {"X", "N", "L", "H"},
}
_CVSS_V40_EXTENDED_METRIC_VALUES = {
    "E": {"X", "A", "P", "U"},
    "CR": {"X", "L", "M", "H"},
    "IR": {"X", "L", "M", "H"},
    "AR": {"X", "L", "M", "H"},
    "MAV": {"X", "N", "A", "L", "P"},
    "MAC": {"X", "L", "H"},
    "MAT": {"X", "N", "P"},
    "MPR": {"X", "N", "L", "H"},
    "MUI": {"X", "N", "P", "A"},
    "MVC": {"X", "N", "L", "H"},
    "MVI": {"X", "N", "L", "H"},
    "MVA": {"X", "N", "L", "H"},
    "MSC": {"X", "N", "L", "H"},
    "MSI": {"X", "N", "L", "H", "S"},
    "MSA": {"X", "N", "L", "H", "S"},
    "S": {"X", "N", "P"},
    "AU": {"X", "N", "Y"},
    "R": {"X", "A", "U", "I"},
    "V": {"X", "D", "C"},
    "RE": {"X", "L", "M", "H"},
    "U": {"X", "Clear", "Green", "Amber", "Red"},
}

StableIdentifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
CveIdentifier = Annotated[str, Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")]
CweIdentifier = Annotated[str, Field(pattern=r"^CWE-(?:[0-9]+|Other|noinfo)$")]


class Evidence(DomainModel):
    """Source material supporting a security finding."""

    source_type: EvidenceSource
    asset_path: NonEmptyString | None = None
    start_line: Annotated[int, Field(ge=1)] | None = None
    end_line: Annotated[int, Field(ge=1)] | None = None
    field: NonEmptyString | None = None
    excerpt: NonEmptyString | None = None
    content_sha256: Sha256Digest | None = None

    @field_validator("asset_path")
    @classmethod
    def path_must_be_project_relative(cls, value: str | None) -> str | None:
        """Validate file-backed evidence paths when present."""

        if value is None:
            return None
        return validate_relative_path(value)

    @model_validator(mode="after")
    def location_must_be_coherent(self) -> Evidence:
        """Validate line ranges and require a useful evidence locator."""

        if self.end_line is not None and self.start_line is None:
            raise ValueError("end_line requires start_line")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("end_line must be greater than or equal to start_line")
        if self.asset_path is None and self.field is None:
            raise ValueError("evidence requires asset_path or field")
        if self.start_line is not None and self.asset_path is None:
            raise ValueError("line evidence requires asset_path")

        return self


class VulnerabilityReference(DomainModel):
    """Explicit, source-backed vulnerability identity attached to a Finding."""

    vulnerability_id: StableIdentifier
    cve_id: CveIdentifier | None = None
    cwe_ids: tuple[CweIdentifier, ...] = ()
    source: StableIdentifier
    association_method: Literal["explicit", "deterministic_match"] = "explicit"
    association_basis: Annotated[tuple[NonEmptyString, ...], Field(min_length=1)]

    @field_validator("cwe_ids")
    @classmethod
    def cwe_ids_must_be_unique_and_ordered(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        """Normalize CWE references into a deterministic unique order."""

        if len(set(value)) != len(value):
            raise ValueError("CWE identifiers must be unique")
        return tuple(sorted(value))

    @field_validator("association_basis")
    @classmethod
    def association_basis_must_be_unique(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        """Prevent contradictory duplicated association explanations."""

        if len(set(value)) != len(value):
            raise ValueError("association basis values must be unique")
        return value

    @model_validator(mode="after")
    def cve_identity_must_be_coherent(self) -> VulnerabilityReference:
        """Keep CVE aliases and generic vulnerability IDs consistent."""

        if (
            self.vulnerability_id.startswith("CVE-")
            and self.cve_id != self.vulnerability_id
        ):
            raise ValueError("a CVE vulnerability_id must match the cve_id field")
        return self


_CVSS_GATE_ID_PATTERN = r"^HG-CVSS-[0-9]{3}$"
_CVSS_GATE_SCORE_TYPES = (
    "base",
    "temporal",
    "environmental",
    "threat",
    "environmental_threat",
)


class CvssHardGateMatch(DomainModel):
    """One deterministic CVSS threshold match in report-only mode."""

    gate_id: Annotated[str, Field(pattern=_CVSS_GATE_ID_PATTERN)]
    floor: Literal["high", "critical"]
    threshold: Annotated[float, Field(ge=0, le=10)]
    score: Annotated[float, Field(ge=0, le=10)]
    score_type: Literal[
        "base", "temporal", "environmental", "threat", "environmental_threat"
    ]
    rationale: Annotated[tuple[NonEmptyString, ...], Field(min_length=1)]

    @field_validator("threshold", "score", mode="before")
    @classmethod
    def scores_must_be_finite(cls, value: object) -> object:
        """Reject booleans, NaN, infinity, and scores with excess precision."""

        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError("CVSS Hard Gate scores must be finite numbers")
        if round(float(value), 1) != float(value):
            raise ValueError("CVSS Hard Gate scores must have at most one decimal")
        return value

    @field_validator("rationale")
    @classmethod
    def rationale_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Keep deterministic policy rationale free of duplicate rows."""

        if len(set(value)) != len(value):
            raise ValueError("CVSS Hard Gate rationale values must be unique")
        return value

    @model_validator(mode="after")
    def threshold_and_floor_must_be_coherent(self) -> CvssHardGateMatch:
        """Ensure the match encodes the trusted High/Critical thresholds."""

        expected_threshold = 9.0 if self.floor == "critical" else 7.0
        expected_gate_id = "HG-CVSS-002" if self.floor == "critical" else "HG-CVSS-001"
        if self.threshold != expected_threshold:
            raise ValueError("CVSS Hard Gate threshold does not match its floor")
        if self.gate_id != expected_gate_id:
            raise ValueError("CVSS Hard Gate ID does not match its floor")
        if self.score < self.threshold:
            raise ValueError("CVSS Hard Gate match score is below its threshold")
        return self


class CvssHardGateAssessment(DomainModel):
    """Report-only CVSS gate evaluation kept separate from AgentSec risk."""

    gate_version: NonEmptyString
    finding_id: NonEmptyString
    mode: Literal["report_only"]
    score: Annotated[float, Field(ge=0, le=10)]
    severity: Severity
    score_type: Literal[
        "base", "temporal", "environmental", "threat", "environmental_threat"
    ]
    match: CvssHardGateMatch | None = None
    mapping_basis: Annotated[tuple[NonEmptyString, ...], Field(min_length=1)]

    @field_validator("score", mode="before")
    @classmethod
    def score_must_be_finite(cls, value: object) -> object:
        """Reject non-finite or over-precise effective CVSS scores."""

        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError("CVSS Hard Gate score must be a finite number")
        if round(float(value), 1) != float(value):
            raise ValueError("CVSS Hard Gate score must have at most one decimal")
        return value

    @field_validator("mapping_basis")
    @classmethod
    def mapping_basis_must_be_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Prevent duplicate provenance statements in serialized reports."""

        if len(set(value)) != len(value):
            raise ValueError("CVSS Hard Gate mapping basis must be unique")
        return value

    @model_validator(mode="after")
    def score_and_match_must_be_coherent(self) -> CvssHardGateAssessment:
        """Keep CVSS gate output internally consistent and non-enforcing."""

        if self.gate_version != CVSS_HARD_GATE_VERSION:
            raise ValueError("CVSS Hard Gate version is not supported")
        if _cvss_severity_for_score(self.score) is not self.severity:
            raise ValueError("CVSS Hard Gate score and Severity are inconsistent")
        if self.match is not None:
            if self.match.score != self.score:
                raise ValueError("CVSS Hard Gate match score is inconsistent")
            if self.match.score_type != self.score_type:
                raise ValueError("CVSS Hard Gate match score type is inconsistent")
        return self

    @property
    def triggered(self) -> bool:
        """Return whether the High or Critical CVSS threshold matched."""

        return self.match is not None

    @property
    def blocks(self) -> bool:
        """CVSS P2-24 is report-only and never blocks CI."""

        return False


class CvssBase(DomainModel):
    """Schema-backed CVSS Base data attached to a vulnerability Finding.

    This is deliberately a separate nested object. Its Severity is the CVSS
    qualitative result, not the AgentSec Finding Severity, and its score is not
    used to overwrite or average the Finding's AgentSec score.
    """

    adapter_version: NonEmptyString
    version: Literal["3.1", "4.0"]
    vector: NonEmptyString
    base_score: Annotated[float, Field(ge=0, le=10)]
    base_severity: Severity
    metrics: dict[NonEmptyString, NonEmptyString]
    score_verification: Literal["calculated", "provided"]
    mapping_basis: Annotated[tuple[NonEmptyString, ...], Field(min_length=1)]
    effective_score: Annotated[float, Field(ge=0, le=10)] | None = None
    effective_severity: Severity | None = None
    score_type: Literal[
        "base", "temporal", "environmental", "threat", "environmental_threat"
    ] = "base"

    @field_validator("vector")
    @classmethod
    def vector_must_be_bounded_ascii(cls, value: str) -> str:
        """Keep report vectors bounded and portable."""

        if len(value) > 512:
            raise ValueError("CVSS vector exceeds the supported length limit")
        if any(ord(character) > 127 for character in value):
            raise ValueError("CVSS vector must contain ASCII characters only")
        return value

    @field_validator("base_score", mode="before")
    @classmethod
    def score_must_be_finite_number(cls, value: object) -> object:
        """Reject booleans, non-numeric values, and non-finite scores."""

        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError("CVSS Base Score must be finite numeric data")
        if round(float(value), 1) != float(value):
            raise ValueError("CVSS Base Score must have at most one decimal place")
        return value

    @field_validator("effective_score", mode="before")
    @classmethod
    def effective_score_must_be_finite_number(cls, value: object) -> object:
        """Reject invalid extended CVSS scores when present."""

        if value is None:
            return value
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError("CVSS effective Score must be finite numeric data")
        if round(float(value), 1) != float(value):
            raise ValueError("CVSS effective Score must have at most one decimal place")
        return value

    @field_validator("metrics")
    @classmethod
    def metrics_must_be_canonical(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject unknown metric names and values before report serialization."""

        expected: dict[str, set[str]] = {}
        for metric_map in (
            _CVSS_V31_METRIC_VALUES,
            _CVSS_V40_METRIC_VALUES,
            _CVSS_V31_EXTENDED_METRIC_VALUES,
            _CVSS_V40_EXTENDED_METRIC_VALUES,
        ):
            for name, allowed_values in metric_map.items():
                expected.setdefault(name, set()).update(allowed_values)
        if not value:
            raise ValueError("CVSS Base metrics must not be empty")
        for name, metric_value in value.items():
            if name not in expected:
                raise ValueError("CVSS Base contains an unknown metric")
            if metric_value not in expected[name]:
                raise ValueError("CVSS Base contains an invalid metric value")
        return value

    @model_validator(mode="after")
    def vector_and_metrics_must_match(self) -> CvssBase:
        """Require version, vector, metrics, score, and extension state to agree."""

        base = (
            _CVSS_V31_METRIC_VALUES
            if self.version == "3.1"
            else _CVSS_V40_METRIC_VALUES
        )
        extended = (
            _CVSS_V31_EXTENDED_METRIC_VALUES
            if self.version == "3.1"
            else _CVSS_V40_EXTENDED_METRIC_VALUES
        )
        if not set(base) <= set(self.metrics):
            raise ValueError("CVSS Base metrics are incomplete")
        allowed = base | extended
        if not set(self.metrics) <= set(allowed):
            raise ValueError("CVSS metrics do not match the version")
        for name, metric_value in self.metrics.items():
            if metric_value not in allowed[name]:
                raise ValueError("CVSS metric value does not match the version")
        prefix = f"CVSS:{self.version}/"
        if not self.vector.startswith(prefix):
            raise ValueError("CVSS vector prefix does not match the version")
        if self.version == "3.1" and self.score_verification != "calculated":
            raise ValueError("CVSS v3.1 score verification must be calculated")
        if _cvss_severity_for_score(self.base_score) is not self.base_severity:
            raise ValueError("CVSS Base Score and Severity are inconsistent")
        effective_score = (
            self.base_score if self.effective_score is None else self.effective_score
        )
        effective_severity = (
            _cvss_severity_for_score(effective_score)
            if self.effective_severity is None
            else self.effective_severity
        )
        if _cvss_severity_for_score(effective_score) is not effective_severity:
            raise ValueError("CVSS effective Score and Severity are inconsistent")
        object.__setattr__(self, "effective_score", effective_score)
        object.__setattr__(self, "effective_severity", effective_severity)
        return self


class Finding(DomainModel):
    """An independently actionable, evidence-backed security result."""

    finding_id: NonEmptyString
    rule_id: NonEmptyString
    category: FindingCategory
    title: NonEmptyString
    description: NonEmptyString
    likelihood: LikelihoodLevel
    impact: ImpactLevel
    severity: Severity
    score: Annotated[float, Field(ge=0, le=10)]
    confidence: EvidenceConfidence
    hard_gate: bool = False
    vulnerability: VulnerabilityReference | None = None
    cvss: CvssBase | None = None
    cvss_hard_gate: CvssHardGateAssessment | None = None
    evidence: Annotated[tuple[Evidence, ...], Field(min_length=1)]
    recommendations: Annotated[tuple[NonEmptyString, ...], Field(min_length=1)]

    def attach_vulnerability(self, reference: VulnerabilityReference) -> Finding:
        """Return an immutable copy linked to an explicit vulnerability record."""

        if not isinstance(reference, VulnerabilityReference):
            raise TypeError("Finding vulnerability association requires a reference")
        return self.model_copy(update={"vulnerability": reference})

    def attach_cvss_hard_gate(self, assessment: CvssHardGateAssessment) -> Finding:
        """Return an immutable copy carrying a CVSS gate evaluation."""

        if not isinstance(assessment, CvssHardGateAssessment):
            raise TypeError("Finding CVSS Hard Gate requires an assessment")
        if assessment.finding_id != self.finding_id:
            raise ValueError("Finding CVSS Hard Gate ID does not match Finding")
        return self.model_copy(update={"cvss_hard_gate": assessment})


def _cvss_severity_for_score(score: float) -> Severity:
    """Map the CVSS Base score to the standard qualitative range."""

    if score == 0.0:
        return Severity.NONE
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL
