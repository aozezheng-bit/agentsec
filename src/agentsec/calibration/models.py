"""Strict, value-minimizing models for P2-CAL-01 calibration cases."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from agentsec.capability_rules import CapabilityCorrelation
from agentsec.domain import EvidenceConfidence
from agentsec.manifests import ManifestUnknownDimension
from agentsec.manifests.models import InterfaceVersionString
from agentsec.versioning import (
    CALIBRATION_CASE_SCHEMA_VERSION,
    CAPABILITY_RULE_PACK_VERSION,
)

CALIBRATION_CASE_FORMAT = "agentsec-capability-calibration-case"
CALIBRATION_CORPUS_FORMAT = "agentsec-capability-calibration-corpus"

CALIBRATION_CASE_SCHEMA_FILENAME = "calibration-case.schema.json"
CALIBRATION_CORPUS_SCHEMA_FILENAME = "calibration-corpus.schema.json"

_STABLE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_CASE_ID_PATTERN = re.compile(r"^cal-[a-z0-9]+(?:-[a-z0-9]+)*$")
_FIELD_PATH_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")

NonEmptyText = Annotated[str, Field(min_length=1, max_length=512)]
StableId = Annotated[str, Field(min_length=1, max_length=128)]
PositiveLine = Annotated[int, Field(ge=1)]


def _exact_text(value: str) -> str:
    if not value.strip() or value != value.strip():
        raise ValueError("text must be non-empty and have no outer whitespace")
    return value


def _stable_id(value: str) -> str:
    if _STABLE_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("identifier must use the stable lowercase form")
    return value


def _case_id(value: str) -> str:
    if _CASE_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("case_id must use cal-<slug> form")
    return value


def _safe_field_path(value: str) -> str:
    if _FIELD_PATH_PATTERN.fullmatch(value) is None:
        raise ValueError("field_path contains unsupported characters")
    return value


def _sorted_unique[T](values: tuple[T, ...], key: object, label: str) -> None:
    del key
    if not values or values != tuple(sorted(set(values), key=lambda item: str(item))):
        raise ValueError(f"{label} must be non-empty, sorted, and unique")


class CalibrationModel(BaseModel):
    """Immutable strict base for calibration JSON contracts."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        use_enum_values=False,
    )


class CalibrationCaseKind(StrEnum):
    """Ground-truth scenario class used for calibration stratification."""

    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEAR_MISS = "near_miss"
    INCOMPLETE = "incomplete"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class CalibrationLanguage(StrEnum):
    """Language of the inert input fixture or reviewed declaration."""

    EN = "en"
    ZH = "zh"
    BILINGUAL = "bilingual"


class CalibrationInputKind(StrEnum):
    """Safe fixture representation consumed by a later calibration Runner."""

    PROJECT = "project"
    MANIFEST_SNAPSHOT = "manifest_snapshot"
    FACT_BUNDLE = "fact_bundle"


class CalibrationFormat(StrEnum):
    """Input syntax represented by one calibration scenario."""

    MARKDOWN = "markdown"
    TOML = "toml"
    YAML = "yaml"
    JSON = "json"
    RULES = "rules"
    MANIFEST = "manifest"


class CalibrationFactDimension(StrEnum):
    """Normalized Manifest dimension represented by one labeled fact."""

    TOOL = "tool"
    PERMISSION = "permission"
    CONTROL = "control"
    RUNTIME_IDENTITY = "runtime_identity"
    RELATIONSHIP = "relationship"
    UNKNOWN = "unknown"
    COVERAGE = "coverage"


class CalibrationFactState(StrEnum):
    """Expected state of a normalized fact in a calibration Case."""

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class CalibrationRuleOutcome(StrEnum):
    """Expected result for one Rule under test."""

    MATCH = "match"
    NO_MATCH = "no_match"


class CalibrationDisposition(StrEnum):
    """Reviewer disposition, independent from deterministic Rule outcome."""

    ACTIONABLE = "actionable"
    ACCEPTED_RISK = "accepted_risk"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    AMBIGUOUS = "ambiguous"


class CalibrationReviewStatus(StrEnum):
    """Review maturity of one seed label."""

    SEEDED = "seeded"
    REVIEWED = "reviewed"
    ADJUDICATED = "adjudicated"


class CalibrationEvidenceReference(CalibrationModel):
    """Value-free location inside an inert calibration fixture."""

    asset_path: NonEmptyText
    field_path: NonEmptyText | None = None
    start_line: PositiveLine | None = None
    end_line: PositiveLine | None = None

    @field_validator("asset_path")
    @classmethod
    def asset_path_must_be_relative(cls, value: str) -> str:
        from agentsec.domain.base import validate_relative_path

        return validate_relative_path(value)

    @field_validator("field_path")
    @classmethod
    def field_path_must_be_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _safe_field_path(value)

    @model_validator(mode="after")
    def line_range_must_be_coherent(self) -> CalibrationEvidenceReference:
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("evidence line range must be provided together")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("evidence line range is invalid")
        return self

    def sort_key(self) -> tuple[str, str, int, int]:
        return (
            self.asset_path,
            self.field_path or "",
            self.start_line or 0,
            self.end_line or 0,
        )


class CalibrationFixture(CalibrationModel):
    """Portable fixture reference; the loader verifies containment and existence."""

    kind: CalibrationInputKind
    path: NonEmptyText
    formats: tuple[CalibrationFormat, ...]
    assets: tuple[NonEmptyText, ...] = ()

    @field_validator("path")
    @classmethod
    def fixture_path_must_be_relative(cls, value: str) -> str:
        from agentsec.domain.base import validate_relative_path

        return validate_relative_path(value)

    @field_validator("assets")
    @classmethod
    def assets_must_be_relative(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        from agentsec.domain.base import validate_relative_path

        normalized = tuple(validate_relative_path(value) for value in values)
        if normalized != tuple(sorted(set(normalized))):
            raise ValueError("fixture assets must be sorted and unique")
        return normalized

    @model_validator(mode="after")
    def fixture_values_must_be_coherent(self) -> CalibrationFixture:
        if not self.formats or self.formats != tuple(
            sorted(set(self.formats), key=lambda item: item.value)
        ):
            raise ValueError("fixture formats must be non-empty, sorted, and unique")
        if self.kind is CalibrationInputKind.PROJECT and not self.assets:
            raise ValueError("project fixtures require declared assets")
        if self.kind is not CalibrationInputKind.PROJECT and self.assets:
            raise ValueError("non-project fixtures cannot declare project assets")
        if self.kind is CalibrationInputKind.MANIFEST_SNAPSHOT and (
            CalibrationFormat.MANIFEST not in self.formats
        ):
            raise ValueError("manifest snapshots require the manifest format")
        if self.kind is CalibrationInputKind.FACT_BUNDLE and (
            CalibrationFormat.JSON not in self.formats
        ):
            raise ValueError("fact bundles require the JSON format")
        return self


class CalibrationFact(CalibrationModel):
    """One expected normalized fact without raw source values."""

    fact_id: StableId
    dimension: CalibrationFactDimension
    key: StableId
    state: CalibrationFactState
    target_id: StableId | None = None
    evidence: tuple[CalibrationEvidenceReference, ...] = ()

    @field_validator("fact_id", "key", "target_id")
    @classmethod
    def identifiers_must_be_stable(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _stable_id(value)

    @model_validator(mode="after")
    def fact_must_be_coherent(self) -> CalibrationFact:
        evidence_keys = tuple(item.sort_key() for item in self.evidence)
        if evidence_keys != tuple(sorted(set(evidence_keys))):
            raise ValueError("fact evidence must be sorted and unique")
        if self.state is not CalibrationFactState.ABSENT and not self.evidence:
            raise ValueError("present or unknown facts require evidence")
        return self


class CalibrationRuleExpectation(CalibrationModel):
    """One expected Rule result used by a future deterministic evaluator."""

    rule_id: StableId
    outcome: CalibrationRuleOutcome
    correlations: tuple[CapabilityCorrelation, ...] = ()
    confidences: tuple[EvidenceConfidence, ...] = ()
    min_findings: int = Field(default=0, ge=0, le=4096)
    max_findings: int = Field(default=0, ge=0, le=4096)
    fact_ids: tuple[StableId, ...] = ()
    rationale_code: StableId

    @field_validator("rule_id", "rationale_code")
    @classmethod
    def rule_identifiers_must_be_stable(cls, value: str) -> str:
        if value.startswith("CAP-"):
            if not re.fullmatch(r"^CAP-[A-Z0-9]+-[0-9]{3}$", value):
                raise ValueError("Rule ID must use CAP-TOPIC-NNN form")
            return value
        return _stable_id(value)

    @field_validator("fact_ids")
    @classmethod
    def fact_ids_must_be_sorted(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("expectation fact_ids must be sorted and unique")
        return tuple(_stable_id(value) for value in values)

    @model_validator(mode="after")
    def expectation_must_be_coherent(self) -> CalibrationRuleExpectation:
        if not self.fact_ids:
            raise ValueError("Rule expectation requires supporting fact_ids")
        correlations = tuple(
            sorted(set(self.correlations), key=lambda item: item.value)
        )
        confidences = tuple(sorted(set(self.confidences), key=lambda item: item.value))
        if self.correlations != correlations or self.confidences != confidences:
            raise ValueError("correlations and confidences must be sorted and unique")
        if self.max_findings < self.min_findings:
            raise ValueError("max_findings must not be less than min_findings")
        if self.outcome is CalibrationRuleOutcome.MATCH:
            if not self.correlations or not self.confidences:
                raise ValueError(
                    "matching expectation requires correlation and confidence"
                )
            if self.min_findings < 1:
                raise ValueError("matching expectation requires at least one Finding")
        else:
            if self.correlations or self.confidences:
                raise ValueError("no-match expectation cannot declare correlation")
            if self.min_findings != 0 or self.max_findings != 0:
                raise ValueError("no-match expectation must have zero Finding bounds")
        return self


class CalibrationGroundTruth(CalibrationModel):
    """Reviewed labels for Coverage, facts, Rules, and Evidence Confidence."""

    coverage: Literal["complete", "incomplete"]
    unknown_dimensions: tuple[ManifestUnknownDimension, ...] = ()
    facts: tuple[CalibrationFact, ...]
    rule_expectations: tuple[CalibrationRuleExpectation, ...]
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def ground_truth_must_be_sorted_and_referentially_integral(
        self,
    ) -> CalibrationGroundTruth:
        fact_ids = tuple(item.fact_id for item in self.facts)
        if fact_ids != tuple(sorted(set(fact_ids))):
            raise ValueError("ground-truth facts must be sorted and unique")
        rule_ids = tuple(item.rule_id for item in self.rule_expectations)
        if rule_ids != tuple(sorted(set(rule_ids))):
            raise ValueError("Rule expectations must be sorted and unique")
        unknowns = tuple(
            sorted(set(self.unknown_dimensions), key=lambda item: item.value)
        )
        if self.unknown_dimensions != unknowns:
            raise ValueError("unknown_dimensions must be sorted and unique")
        known_facts = set(fact_ids)
        for expectation in self.rule_expectations:
            if not set(expectation.fact_ids) <= known_facts:
                raise ValueError("Rule expectation references an unknown fact")
        if self.coverage == "incomplete" and not self.unknown_dimensions:
            raise ValueError("incomplete ground truth requires an Unknown dimension")
        return self


class CalibrationReview(CalibrationModel):
    """Review provenance for one seed label without personal data."""

    status: CalibrationReviewStatus
    disposition: CalibrationDisposition
    reviewer_refs: tuple[StableId, ...]
    rationale_code: StableId

    @field_validator("reviewer_refs")
    @classmethod
    def reviewer_refs_must_be_stable(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_stable_id(value) for value in values)
        if normalized != tuple(sorted(set(normalized))):
            raise ValueError("reviewer_refs must be sorted and unique")
        return normalized

    @field_validator("rationale_code")
    @classmethod
    def review_rationale_must_be_stable(cls, value: str) -> str:
        return _stable_id(value)

    @model_validator(mode="after")
    def reviewed_status_requires_reviewer(self) -> CalibrationReview:
        if (
            self.status
            in {
                CalibrationReviewStatus.REVIEWED,
                CalibrationReviewStatus.ADJUDICATED,
            }
            and not self.reviewer_refs
        ):
            raise ValueError("reviewed labels require reviewer_refs")
        return self


class CalibrationCase(CalibrationModel):
    """One bounded, labeled calibration scenario."""

    format: Literal["agentsec-capability-calibration-case"] = (
        "agentsec-capability-calibration-case"
    )
    schema_version: InterfaceVersionString = CALIBRATION_CASE_SCHEMA_VERSION
    case_id: NonEmptyText
    case_kind: CalibrationCaseKind
    language: CalibrationLanguage
    framework_id: StableId
    purpose: NonEmptyText
    fixture: CalibrationFixture
    source_formats: tuple[CalibrationFormat, ...]
    ground_truth: CalibrationGroundTruth
    review: CalibrationReview
    tags: tuple[StableId, ...] = ()

    @field_validator("case_id")
    @classmethod
    def case_id_must_be_stable(cls, value: str) -> str:
        return _case_id(value)

    @field_validator("framework_id")
    @classmethod
    def framework_id_must_be_stable(cls, value: str) -> str:
        return _stable_id(value)

    @field_validator("source_formats")
    @classmethod
    def source_formats_must_be_sorted(
        cls, values: tuple[CalibrationFormat, ...]
    ) -> tuple[CalibrationFormat, ...]:
        normalized = tuple(sorted(set(values), key=lambda item: item.value))
        if not normalized or values != normalized:
            raise ValueError("source_formats must be non-empty, sorted, and unique")
        return normalized

    @field_validator("tags")
    @classmethod
    def tags_must_be_sorted(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_stable_id(value) for value in values)
        if normalized != tuple(sorted(set(normalized))):
            raise ValueError("tags must be sorted and unique")
        return normalized

    @model_validator(mode="after")
    def case_labels_must_match_case_kind(self) -> CalibrationCase:
        outcomes = {item.outcome for item in self.ground_truth.rule_expectations}
        if self.case_kind is CalibrationCaseKind.POSITIVE and (
            CalibrationRuleOutcome.MATCH not in outcomes
        ):
            raise ValueError("positive Case requires a matching Rule expectation")
        if (
            self.case_kind
            in {
                CalibrationCaseKind.NEGATIVE,
                CalibrationCaseKind.NEAR_MISS,
            }
            and CalibrationRuleOutcome.NO_MATCH not in outcomes
        ):
            raise ValueError(
                "negative or near-miss Case requires a no-match expectation"
            )
        if (
            self.case_kind is CalibrationCaseKind.INCOMPLETE
            and self.ground_truth.coverage != "incomplete"
        ):
            raise ValueError("incomplete Case requires incomplete Coverage")
        if (
            self.case_kind is CalibrationCaseKind.UNKNOWN
            and not self.ground_truth.unknown_dimensions
        ):
            raise ValueError("Unknown Case requires Unknown dimensions")
        if (
            self.case_kind is CalibrationCaseKind.CONFLICT
            and not self.ground_truth.unknown_dimensions
        ):
            raise ValueError("conflict Case requires an explicit Unknown dimension")
        return self


class CalibrationCorpusIndex(CalibrationModel):
    """Deterministic index for a directory of Calibration Cases."""

    format: Literal["agentsec-capability-calibration-corpus"] = (
        "agentsec-capability-calibration-corpus"
    )
    schema_version: InterfaceVersionString = CALIBRATION_CASE_SCHEMA_VERSION
    corpus_id: StableId
    title: NonEmptyText
    description: NonEmptyText
    capability_rule_pack_version: InterfaceVersionString = CAPABILITY_RULE_PACK_VERSION
    case_paths: tuple[NonEmptyText, ...]
    labels_version: InterfaceVersionString = CALIBRATION_CASE_SCHEMA_VERSION

    @field_validator("corpus_id")
    @classmethod
    def corpus_id_must_be_stable(cls, value: str) -> str:
        return _stable_id(value)

    @field_validator("case_paths")
    @classmethod
    def case_paths_must_be_safe(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        from agentsec.domain.base import validate_relative_path

        normalized = tuple(validate_relative_path(value) for value in values)
        if not normalized or normalized != tuple(sorted(set(normalized))):
            raise ValueError(
                "case_paths must be non-empty, sorted, unique, and relative"
            )
        return normalized
