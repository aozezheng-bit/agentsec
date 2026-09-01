"""Strict, source-independent CVSS v3.1/v4.0 input adaptation.

The adapter keeps conventional CVSS results separate from AgentSec's
NIST-style risk model. It performs no filesystem, network, runtime, LLM, or
MCP operation.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from agentsec.domain import CvssBase, Finding, Severity
from agentsec.risk.cvss_v40 import (
    CVSS_V40_CALCULATION_BASIS,
    calculate_cvss_v40_base_score,
)

CVSS_ADAPTER_VERSION = "0.3.0"
CVSS_V31_MAPPING_BASIS = (
    "FIRST CVSS v3.1 Base, Temporal, and Environmental formulas",
    "FIRST CVSS v3.1 qualitative severity rating scale",
    "AgentSec CVSS extended input adapter contract 0.3.0",
)
CVSS_V40_MAPPING_BASIS = (
    *CVSS_V40_CALCULATION_BASIS,
    "AgentSec CVSS extended input adapter contract 0.3.0",
)
CVSS_MAPPING_BASIS = CVSS_V31_MAPPING_BASIS

_MAX_VECTOR_LENGTH = 512
_V31_PREFIX = "CVSS:3.1"
_V40_PREFIX = "CVSS:4.0"

_V31_BASE_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_V31_BASE_ALLOWED = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}
_V31_OPTIONAL_ORDER = (
    "E",
    "RL",
    "RC",
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MPR",
    "MUI",
    "MS",
    "MC",
    "MI",
    "MA",
)
_V31_OPTIONAL_ALLOWED = {
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

_V40_BASE_ORDER = (
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
)
_V40_BASE_ALLOWED = {
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
_V40_OPTIONAL_ORDER = (
    "E",
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MAT",
    "MPR",
    "MUI",
    "MVC",
    "MVI",
    "MVA",
    "MSC",
    "MSI",
    "MSA",
    "S",
    "AU",
    "R",
    "V",
    "RE",
    "U",
)
_V40_OPTIONAL_ALLOWED = {
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

_V31_TEMPORAL_METRICS = {"E", "RL", "RC"}
_V31_ENVIRONMENTAL_METRICS = {
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MPR",
    "MUI",
    "MS",
    "MC",
    "MI",
    "MA",
}
_V40_THREAT_METRICS = {"E"}
_V40_ENVIRONMENTAL_METRICS = {
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MAT",
    "MPR",
    "MUI",
    "MVC",
    "MVI",
    "MVA",
    "MSC",
    "MSI",
    "MSA",
}


class CvssVersion(StrEnum):
    """CVSS versions accepted by the extended input adapter."""

    V3_1 = "3.1"
    V4_0 = "4.0"


class CvssScoreVerification(StrEnum):
    """How the adapter established the score."""

    CALCULATED = "calculated"
    PROVIDED = "provided"


class CvssScoreType(StrEnum):
    """The highest CVSS score dimension calculated from the supplied vector."""

    BASE = "base"
    TEMPORAL = "temporal"
    ENVIRONMENTAL = "environmental"
    THREAT = "threat"
    ENVIRONMENTAL_THREAT = "environmental_threat"


class CvssAdapterCode(StrEnum):
    """Stable, non-sensitive CVSS adapter failure reasons."""

    INVALID_INPUT = "invalid_input"
    INVALID_JSON = "invalid_json"
    UNKNOWN_INPUT_FIELD = "unknown_input_field"
    UNSUPPORTED_VERSION = "unsupported_version"
    INVALID_VECTOR = "invalid_vector"
    INVALID_METRIC = "invalid_metric"
    DUPLICATE_METRIC = "duplicate_metric"
    MISSING_METRIC = "missing_metric"
    INVALID_SCORE = "invalid_score"
    SCORE_MISMATCH = "score_mismatch"
    SEVERITY_MISMATCH = "severity_mismatch"
    SCORE_REQUIRED = "score_required"


class CvssAdapterError(ValueError):
    """Safe CVSS input error that never copies the complete input payload."""

    def __init__(self, code: CvssAdapterCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class CvssBaseInput:
    """Untrusted CVSS input with optional extended-score expectations."""

    vector: str
    version: CvssVersion | str | None = None
    base_score: float | int | None = None
    base_severity: Severity | str | None = None
    score: float | int | None = None
    severity: Severity | str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.vector, str) or not self.vector.strip():
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_INPUT,
                "CVSS input vector must be non-empty text.",
            )
        if len(self.vector) > _MAX_VECTOR_LENGTH:
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_INPUT,
                "CVSS input vector exceeds the supported length limit.",
            )
        if self.version is not None and not isinstance(
            self.version, (CvssVersion, str)
        ):
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_INPUT,
                "CVSS input version must be text.",
            )
        for value in (self.base_score, self.score):
            if value is not None:
                _validate_score(value)
        for severity_value in (self.base_severity, self.severity):
            if severity_value is not None and not isinstance(
                severity_value, (Severity, str)
            ):
                raise CvssAdapterError(
                    CvssAdapterCode.INVALID_INPUT,
                    "CVSS input Severity must be text.",
                )

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> CvssBaseInput:
        """Create input from a strict mapping without accepting extra fields."""

        if not isinstance(payload, Mapping):
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_INPUT,
                "CVSS input must be a JSON object or mapping.",
            )
        allowed = {
            "vector",
            "version",
            "base_score",
            "base_severity",
            "score",
            "severity",
        }
        if set(payload) - allowed:
            raise CvssAdapterError(
                CvssAdapterCode.UNKNOWN_INPUT_FIELD,
                "CVSS input contains an unsupported field.",
            )
        if "vector" not in payload:
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_INPUT,
                "CVSS input requires a vector field.",
            )
        return cls(
            vector=payload["vector"],  # type: ignore[arg-type]
            version=payload.get("version"),  # type: ignore[arg-type]
            base_score=payload.get("base_score"),  # type: ignore[arg-type]
            base_severity=payload.get("base_severity"),  # type: ignore[arg-type]
            score=payload.get("score"),  # type: ignore[arg-type]
            severity=payload.get("severity"),  # type: ignore[arg-type]
        )

    @classmethod
    def from_json(cls, payload: str) -> CvssBaseInput:
        """Create input from one JSON object without exposing parser details."""

        if not isinstance(payload, str):
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_JSON,
                "CVSS JSON input must be text.",
            )
        try:
            decoded: Any = json.loads(payload)
        except (TypeError, ValueError) as error:
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_JSON,
                "CVSS JSON input is not valid JSON.",
            ) from error
        if not isinstance(decoded, Mapping):
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_JSON,
                "CVSS JSON input must contain one object.",
            )
        return cls.from_mapping(decoded)


@dataclass(frozen=True, slots=True)
class CvssMetric:
    """One normalized CVSS metric."""

    name: str
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("CVSS metric name must be non-empty text")
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("CVSS metric value must be non-empty text")


@dataclass(frozen=True, slots=True)
class CvssBaseAssessment:
    """Validated CVSS result with Base and optional extended score views."""

    adapter_version: str
    version: CvssVersion
    vector: str
    base_score: float
    severity: Severity
    metrics: tuple[CvssMetric, ...]
    score_verification: CvssScoreVerification
    mapping_basis: tuple[str, ...]
    effective_score: float | None = None
    effective_severity: Severity | None = None
    score_type: CvssScoreType = CvssScoreType.BASE

    def __post_init__(self) -> None:
        if self.adapter_version != CVSS_ADAPTER_VERSION:
            raise ValueError("CVSS adapter version is not supported")
        if not isinstance(self.version, CvssVersion):
            raise TypeError("CVSS assessment version must be CvssVersion")
        if not isinstance(self.vector, str) or not self.vector:
            raise ValueError("CVSS assessment vector must be non-empty text")
        _validate_score(self.base_score)
        if not isinstance(self.severity, Severity):
            raise TypeError("CVSS assessment Severity must be Severity")
        if severity_for_cvss_score(self.base_score) is not self.severity:
            raise ValueError("CVSS Base Score and Severity are inconsistent")
        if not isinstance(self.metrics, tuple) or not self.metrics:
            raise ValueError("CVSS assessment requires metrics")
        if any(not isinstance(item, CvssMetric) for item in self.metrics):
            raise TypeError("CVSS assessment contains an invalid metric")
        if self.mapping_basis != _mapping_basis_for(self.version):
            raise ValueError("CVSS assessment mapping basis is inconsistent")
        if not isinstance(self.score_verification, CvssScoreVerification):
            raise TypeError("CVSS score verification must be CvssScoreVerification")
        if not isinstance(self.score_type, CvssScoreType):
            raise TypeError("CVSS score type must be CvssScoreType")
        effective_score = (
            self.base_score if self.effective_score is None else self.effective_score
        )
        effective_severity = (
            self.severity
            if self.effective_severity is None
            else self.effective_severity
        )
        _validate_score(effective_score)
        if severity_for_cvss_score(effective_score) is not effective_severity:
            raise ValueError("CVSS effective Score and Severity are inconsistent")
        object.__setattr__(self, "effective_score", effective_score)
        object.__setattr__(self, "effective_severity", effective_severity)

    @property
    def metric_values(self) -> dict[str, str]:
        """Return a defensive mapping of normalized metrics."""

        return {item.name: item.value for item in self.metrics}

    def to_domain_cvss(self) -> CvssBase:
        """Convert the adapter result into the serialized Finding value object."""

        return CvssBase(
            adapter_version=self.adapter_version,
            version=self.version.value,
            vector=self.vector,
            base_score=self.base_score,
            base_severity=self.severity,
            metrics=self.metric_values,
            score_verification=self.score_verification.value,
            mapping_basis=self.mapping_basis,
            effective_score=self.effective_score,
            effective_severity=self.effective_severity,
            score_type=self.score_type.value,
        )

    def attach_to_finding(self, finding: Finding) -> Finding:
        """Return a copy of one Finding carrying this independent CVSS result."""

        if not isinstance(finding, Finding):
            raise TypeError("CVSS attachment requires a Domain Finding")
        return finding.model_copy(update={"cvss": self.to_domain_cvss()})

    def to_dict(self) -> dict[str, object]:
        """Return deterministic, report-ready data without AgentSec fields."""

        effective_severity = self.effective_severity
        assert effective_severity is not None
        return {
            "adapter_version": self.adapter_version,
            "cvss_version": self.version.value,
            "vector": self.vector,
            "base_score": self.base_score,
            "base_severity": self.severity.value,
            "score": self.effective_score,
            "severity": effective_severity.value,
            "score_type": self.score_type.value,
            "metrics": self.metric_values,
            "score_verification": self.score_verification.value,
            "mapping_basis": list(self.mapping_basis),
        }


class CvssBaseAdapter:
    """Parse, calculate, and adapt CVSS v3.1/v4.0 deterministically."""

    def adapt(
        self,
        value: CvssBaseInput | Mapping[str, object],
    ) -> CvssBaseAssessment:
        """Adapt one input object into a validated CVSS assessment."""

        input_value = (
            value
            if isinstance(value, CvssBaseInput)
            else CvssBaseInput.from_mapping(value)
        )
        version, metrics = _parse_vector(input_value.vector)
        metric_values = dict(metrics)
        if (
            input_value.version is not None
            and _parse_version(input_value.version) is not version
        ):
            raise CvssAdapterError(
                CvssAdapterCode.UNSUPPORTED_VERSION,
                "CVSS input version does not match the vector prefix.",
            )

        base_metrics = dict(
            (name, metric_values[name])
            for name in (
                _V31_BASE_ORDER if version is CvssVersion.V3_1 else _V40_BASE_ORDER
            )
        )
        if version is CvssVersion.V3_1:
            base_score = _calculate_v31_score(base_metrics)
            extended_score = _calculate_v31_extended_score(metric_values, base_score)
        else:
            base_score = calculate_cvss_v40_base_score(base_metrics)
            extended_score = calculate_cvss_v40_base_score(metric_values)

        _check_expected_score(input_value.base_score, base_score, version, "Base")
        _check_expected_score(input_value.score, extended_score, version, "effective")
        base_severity = severity_for_cvss_score(base_score)
        effective_severity = severity_for_cvss_score(extended_score)
        _check_expected_severity(input_value.base_severity, base_severity, "Base")
        _check_expected_severity(input_value.severity, effective_severity, "effective")

        score_type = _score_type(version, metric_values)
        return CvssBaseAssessment(
            adapter_version=CVSS_ADAPTER_VERSION,
            version=version,
            vector=_canonical_vector(version, metrics),
            base_score=base_score,
            severity=base_severity,
            metrics=tuple(
                CvssMetric(name=name, value=value) for name, value in metrics
            ),
            score_verification=CvssScoreVerification.CALCULATED,
            mapping_basis=_mapping_basis_for(version),
            effective_score=extended_score,
            effective_severity=effective_severity,
            score_type=score_type,
        )

    def adapt_json(self, payload: str) -> CvssBaseAssessment:
        """Adapt one JSON object."""

        return self.adapt(CvssBaseInput.from_json(payload))


def _mapping_basis_for(version: CvssVersion) -> tuple[str, ...]:
    return (
        CVSS_V31_MAPPING_BASIS
        if version is CvssVersion.V3_1
        else CVSS_V40_MAPPING_BASIS
    )


def severity_for_cvss_score(score: float | int) -> Severity:
    """Map a CVSS 0.0–10.0 score to qualitative Severity."""

    numeric = _validate_score(score)
    if numeric == 0.0:
        return Severity.NONE
    if numeric < 4.0:
        return Severity.LOW
    if numeric < 7.0:
        return Severity.MEDIUM
    if numeric < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def _parse_version(value: CvssVersion | str) -> CvssVersion:
    if isinstance(value, CvssVersion):
        return value
    if isinstance(value, str):
        try:
            return CvssVersion(value)
        except ValueError as error:
            raise CvssAdapterError(
                CvssAdapterCode.UNSUPPORTED_VERSION,
                "CVSS version is not supported.",
            ) from error
    raise CvssAdapterError(
        CvssAdapterCode.UNSUPPORTED_VERSION,
        "CVSS version is not supported.",
    )


def _parse_severity(value: Severity | str) -> Severity:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value.strip().lower())
        except ValueError as error:
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_INPUT,
                "CVSS Severity is invalid.",
            ) from error
    raise CvssAdapterError(
        CvssAdapterCode.INVALID_INPUT,
        "CVSS Severity is invalid.",
    )


def _parse_vector(vector: str) -> tuple[CvssVersion, tuple[tuple[str, str], ...]]:
    if not isinstance(vector, str) or not vector or len(vector) > _MAX_VECTOR_LENGTH:
        raise CvssAdapterError(
            CvssAdapterCode.INVALID_VECTOR, "CVSS vector is invalid."
        )
    if any(ord(character) > 127 for character in vector):
        raise CvssAdapterError(
            CvssAdapterCode.INVALID_VECTOR,
            "CVSS vector must contain ASCII characters only.",
        )
    parts = vector.split("/")
    prefix = parts[0]
    base_order: tuple[str, ...]
    optional_order: tuple[str, ...]
    if prefix == _V31_PREFIX:
        version = CvssVersion.V3_1
        base_order = _V31_BASE_ORDER
        base_allowed = _V31_BASE_ALLOWED
        optional_order = _V31_OPTIONAL_ORDER
        optional_allowed = _V31_OPTIONAL_ALLOWED
    elif prefix == _V40_PREFIX:
        version = CvssVersion.V4_0
        base_order = _V40_BASE_ORDER
        base_allowed = _V40_BASE_ALLOWED
        optional_order = _V40_OPTIONAL_ORDER
        optional_allowed = _V40_OPTIONAL_ALLOWED
    else:
        raise CvssAdapterError(
            CvssAdapterCode.UNSUPPORTED_VERSION,
            "CVSS vector version is not supported.",
        )

    parsed: dict[str, str] = {}
    for part in parts[1:]:
        if part.count(":") != 1:
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_METRIC,
                "CVSS vector metric syntax is invalid.",
            )
        name, value = part.split(":", 1)
        if name in parsed:
            raise CvssAdapterError(
                CvssAdapterCode.DUPLICATE_METRIC,
                "CVSS vector contains a duplicate metric.",
            )
        allowed = base_allowed.get(name) or optional_allowed.get(name)
        if allowed is None:
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_METRIC,
                "CVSS vector contains an unsupported metric.",
            )
        if value not in allowed:
            raise CvssAdapterError(
                CvssAdapterCode.INVALID_METRIC,
                "CVSS vector contains an invalid metric value.",
            )
        parsed[name] = value

    missing = set(base_order) - set(parsed)
    if missing:
        raise CvssAdapterError(
            CvssAdapterCode.MISSING_METRIC,
            "CVSS vector is missing a required Base Metric.",
        )
    order = (*base_order, *optional_order)
    return version, tuple((name, parsed[name]) for name in order if name in parsed)


def _canonical_vector(
    version: CvssVersion, metrics: tuple[tuple[str, str], ...]
) -> str:
    prefix = _V31_PREFIX if version is CvssVersion.V3_1 else _V40_PREFIX
    return "/".join((prefix, *(f"{name}:{value}" for name, value in metrics)))


def _score_type(version: CvssVersion, metrics: Mapping[str, str]) -> CvssScoreType:
    if version is CvssVersion.V3_1:
        if any(
            metrics.get(name) not in (None, "X") for name in _V31_ENVIRONMENTAL_METRICS
        ):
            return CvssScoreType.ENVIRONMENTAL
        if any(metrics.get(name) not in (None, "X") for name in _V31_TEMPORAL_METRICS):
            return CvssScoreType.TEMPORAL
        return CvssScoreType.BASE
    environmental = any(
        metrics.get(name) not in (None, "X") for name in _V40_ENVIRONMENTAL_METRICS
    )
    threat = metrics.get("E") not in (None, "X")
    if environmental and threat:
        return CvssScoreType.ENVIRONMENTAL_THREAT
    if environmental:
        return CvssScoreType.ENVIRONMENTAL
    if threat:
        return CvssScoreType.THREAT
    return CvssScoreType.BASE


def _calculate_v31_extended_score(
    metrics: Mapping[str, str], base_score: float
) -> float:
    if any(metrics.get(name) not in (None, "X") for name in _V31_ENVIRONMENTAL_METRICS):
        return _calculate_v31_environmental_score(metrics)
    if any(metrics.get(name) not in (None, "X") for name in _V31_TEMPORAL_METRICS):
        return _calculate_v31_temporal_score(base_score, metrics)
    return base_score


def _calculate_v31_temporal_score(
    base_score: float, metrics: Mapping[str, str]
) -> float:
    e = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}[metrics.get("E", "X")]
    rl = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}[metrics.get("RL", "X")]
    rc = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}[metrics.get("RC", "X")]
    return _round_up_one_decimal(base_score * e * rl * rc)


def _calculate_v31_environmental_score(metrics: Mapping[str, str]) -> float:
    scope = metrics.get("MS", "X")
    scope = metrics.get("S", "U") if scope == "X" else scope
    c = _v31_impact(metrics.get("MC", "X"), metrics["C"])
    i = _v31_impact(metrics.get("MI", "X"), metrics["I"])
    a = _v31_impact(metrics.get("MA", "X"), metrics["A"])
    cr = _v31_requirement(metrics.get("CR", "X"))
    ir = _v31_requirement(metrics.get("IR", "X"))
    ar = _v31_requirement(metrics.get("AR", "X"))
    miss = min(1.0 - (1.0 - c * cr) * (1.0 - i * ir) * (1.0 - a * ar), 0.915)
    if miss <= 0.0:
        return 0.0
    if scope == "U":
        impact = 6.42 * miss
        exploitability = _v31_modified_exploitability(metrics, scope)
        raw = min(impact + exploitability, 10.0)
    else:
        impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
        exploitability = _v31_modified_exploitability(metrics, scope)
        raw = min(1.08 * (impact + exploitability), 10.0)
    e = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}[metrics.get("E", "X")]
    rl = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}[metrics.get("RL", "X")]
    rc = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}[metrics.get("RC", "X")]
    return _round_up_one_decimal(raw * e * rl * rc)


def _v31_impact(modified: str | None, base: str) -> float:
    value = base if modified in (None, "X") else modified
    assert value is not None
    return {"N": 0.0, "L": 0.22, "H": 0.56}[value]


def _v31_requirement(value: str) -> float:
    return {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}[value]


def _v31_modified_exploitability(metrics: Mapping[str, str], scope: str) -> float:
    av = metrics.get("MAV", "X")
    ac = metrics.get("MAC", "X")
    pr = metrics.get("MPR", "X")
    ui = metrics.get("MUI", "X")
    av = metrics["AV"] if av == "X" else av
    ac = metrics["AC"] if ac == "X" else ac
    pr = metrics["PR"] if pr == "X" else pr
    ui = metrics["UI"] if ui == "X" else ui
    return (
        8.22
        * {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[av]
        * {"L": 0.77, "H": 0.44}[ac]
        * _v31_privileges_required(pr, scope)
        * {"N": 0.85, "R": 0.62}[ui]
    )


def _v31_privileges_required(value: str, scope: str) -> float:
    if scope == "U":
        return {"N": 0.85, "L": 0.62, "H": 0.27}[value]
    return {"N": 0.85, "L": 0.68, "H": 0.5}[value]


def _calculate_v31_score(metrics: Mapping[str, str]) -> float:
    impact = 1.0 - (1.0 - _v31_impact(None, metrics["C"])) * (
        1.0 - _v31_impact(None, metrics["I"])
    ) * (1.0 - _v31_impact(None, metrics["A"]))
    if impact <= 0.0:
        return 0.0
    scope = metrics["S"]
    impact_subscore = (
        6.42 * impact
        if scope == "U"
        else 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15
    )
    exploitability = (
        8.22
        * {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        * {"L": 0.77, "H": 0.44}[metrics["AC"]]
        * _v31_privileges_required(metrics["PR"], scope)
        * {"N": 0.85, "R": 0.62}[metrics["UI"]]
    )
    raw = min(impact_subscore + exploitability, 10.0)
    if scope == "C":
        raw = min(1.08 * (impact_subscore + exploitability), 10.0)
    return _round_up_one_decimal(raw)


def _round_up_one_decimal(value: float) -> float:
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def _validate_score(value: float | int) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 10.0
    ):
        raise CvssAdapterError(
            CvssAdapterCode.INVALID_SCORE,
            "CVSS Score must be finite and within 0.0 to 10.0.",
        )
    numeric = float(value)
    if round(numeric, 1) != numeric:
        raise CvssAdapterError(
            CvssAdapterCode.INVALID_SCORE,
            "CVSS Score must have at most one decimal place.",
        )
    return numeric


def _check_expected_score(
    provided: float | int | None,
    expected: float,
    version: CvssVersion,
    label: str,
) -> None:
    if provided is None:
        return
    if _validate_score(provided) != expected:
        raise CvssAdapterError(
            CvssAdapterCode.SCORE_MISMATCH,
            f"CVSS v{version.value} {label} Score does not match the vector.",
        )


def _check_expected_severity(
    provided: Severity | str | None,
    expected: Severity,
    label: str,
) -> None:
    if provided is None:
        return
    if _parse_severity(provided) is not expected:
        raise CvssAdapterError(
            CvssAdapterCode.SEVERITY_MISMATCH,
            f"CVSS {label} Score and Severity are inconsistent.",
        )
