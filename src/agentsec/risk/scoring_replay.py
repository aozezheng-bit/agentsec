"""Deterministic end-to-end Agentic scoring replay contracts (P2-24)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Literal

from agentsec.domain import Severity
from agentsec.manifests import AgentManifest, CapabilityDiffer
from agentsec.risk.agentic_factors import (
    DeterministicAgenticFactorExtractor,
    encode_agentic_factor_vector_json,
)
from agentsec.risk.cvss import CvssBaseAssessment, severity_for_cvss_score
from agentsec.risk.drift_score import (
    DeterministicDriftScoreEngine,
    DriftScoreContext,
    encode_drift_score_json,
)
from agentsec.risk.governance_score import (
    DeterministicGovernanceScoreEngine,
    GovernanceScoreContext,
    encode_governance_score_json,
)
from agentsec.risk.overall_score import (
    DeterministicOverallScoreEngine,
    OverallHardGateMatch,
    encode_overall_score_json,
)
from agentsec.risk.technical_score import (
    DeterministicTechnicalScoreEngine,
    encode_technical_score_json,
)
from agentsec.risk.threat_mitigation import (
    DeterministicThreatMitigationEvaluator,
    encode_threat_mitigation_vector_json,
)
from agentsec.versioning import (
    AGENTIC_FACTOR_MODEL_VERSION,
    CAPABILITY_DIFF_SCHEMA_VERSION,
    DRIFT_SCORE_MODEL_VERSION,
    GOVERNANCE_SCORE_MODEL_VERSION,
    OVERALL_SCORE_MODEL_VERSION,
    SCORING_REPLAY_MODEL_VERSION,
    TECHNICAL_SCORE_MODEL_VERSION,
    THREAT_MITIGATION_MODEL_VERSION,
)

SCORING_REPLAY_FORMAT: Literal["agentsec-scoring-replay"] = "agentsec-scoring-replay"
SCORING_REPLAY_FORMAT_VERSION: Literal["0.1.0"] = "0.1.0"
SCORING_REPLAY_SUITE_FORMAT: Literal["agentsec-scoring-replay-suite"] = (
    "agentsec-scoring-replay-suite"
)
SCORING_REPLAY_BASIS = (
    "AgentSec P2-24 deterministic scoring replay contract 0.1.0",
    (
        "Identical manifests, contexts, Gate evidence, and model versions "
        "must replay identically"
    ),
    "Every scoring-stage artifact is bound by canonical SHA-256",
    "Replay output contains no raw source values and never executes scanned content",
)
_CASE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")


@dataclass(frozen=True, slots=True)
class ScoringReplayRequest:
    """One complete, explicit scoring replay input."""

    case_id: str
    before: AgentManifest = dataclass_field(repr=False)
    after: AgentManifest = dataclass_field(repr=False)
    drift_context: DriftScoreContext = dataclass_field(
        default_factory=DriftScoreContext
    )
    governance_context: GovernanceScoreContext | None = None
    cvss: CvssBaseAssessment | None = dataclass_field(default=None, repr=False)
    gate_matches: tuple[OverallHardGateMatch, ...] = dataclass_field(
        default=(), repr=False
    )

    def __post_init__(self) -> None:
        if _CASE_ID_PATTERN.fullmatch(self.case_id) is None:
            raise ValueError("scoring replay case_id must use stable lowercase form")
        if not isinstance(self.before, AgentManifest) or not isinstance(
            self.after, AgentManifest
        ):
            raise TypeError("scoring replay before/after must be AgentManifest")
        if not isinstance(self.drift_context, DriftScoreContext):
            raise TypeError("scoring replay drift_context is invalid")
        if self.governance_context is not None:
            if not isinstance(self.governance_context, GovernanceScoreContext):
                raise TypeError("scoring replay governance_context is invalid")
            if self.governance_context.drift != self.drift_context:
                raise ValueError(
                    "governance and drift contexts must use the same Drift context"
                )
        if self.cvss is not None and not isinstance(self.cvss, CvssBaseAssessment):
            raise TypeError("scoring replay CVSS input is invalid")
        if not isinstance(self.gate_matches, tuple) or any(
            not isinstance(item, OverallHardGateMatch) for item in self.gate_matches
        ):
            raise TypeError("scoring replay gate_matches must be a typed tuple")


@dataclass(frozen=True, slots=True)
class ScoringReplayComponentHashes:
    """Canonical hashes of every scoring-stage artifact."""

    factor_vector: str
    threat_mitigation: str
    capability_diff: str
    technical_score: str
    drift_score: str
    governance_score: str
    overall_score: str

    def __post_init__(self) -> None:
        for value in self.to_dict().values():
            _validate_hash(value)

    def to_dict(self) -> dict[str, str]:
        return {
            "factor_vector": self.factor_vector,
            "threat_mitigation": self.threat_mitigation,
            "capability_diff": self.capability_diff,
            "technical_score": self.technical_score,
            "drift_score": self.drift_score,
            "governance_score": self.governance_score,
            "overall_score": self.overall_score,
        }


@dataclass(frozen=True, slots=True)
class ScoringReplayVersions:
    """Complete independent model vector required for replay comparability."""

    agentic_factor: str
    threat_mitigation: str
    capability_diff: str
    technical_score: str
    drift_score: str
    governance_score: str
    overall_score: str
    scoring_replay: str

    def __post_init__(self) -> None:
        expected = {
            "agentic_factor": AGENTIC_FACTOR_MODEL_VERSION,
            "threat_mitigation": THREAT_MITIGATION_MODEL_VERSION,
            "capability_diff": CAPABILITY_DIFF_SCHEMA_VERSION,
            "technical_score": TECHNICAL_SCORE_MODEL_VERSION,
            "drift_score": DRIFT_SCORE_MODEL_VERSION,
            "governance_score": GOVERNANCE_SCORE_MODEL_VERSION,
            "overall_score": OVERALL_SCORE_MODEL_VERSION,
            "scoring_replay": SCORING_REPLAY_MODEL_VERSION,
        }
        if self.to_dict() != expected:
            raise ValueError("scoring replay version vector is inconsistent")

    def to_dict(self) -> dict[str, str]:
        return {
            "agentic_factor": self.agentic_factor,
            "threat_mitigation": self.threat_mitigation,
            "capability_diff": self.capability_diff,
            "technical_score": self.technical_score,
            "drift_score": self.drift_score,
            "governance_score": self.governance_score,
            "overall_score": self.overall_score,
            "scoring_replay": self.scoring_replay,
        }


@dataclass(frozen=True, slots=True)
class ScoringReplayResult:
    """Compact replay result containing scores and all component fingerprints."""

    format: Literal["agentsec-scoring-replay"]
    format_version: Literal["0.1.0"]
    case_id: str
    agent_id: str
    before_manifest_sha256: str
    after_manifest_sha256: str
    versions: ScoringReplayVersions
    component_hashes: ScoringReplayComponentHashes
    technical_score: float
    drift_score: float
    governance_score: float
    base_overall_score: float
    overall_score: float
    severity: Severity
    hard_gate_triggered: bool
    hard_gate_floor: str | None
    coverage_complete: bool
    replay_sha256: str
    mapping_basis: tuple[str, ...] = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if self.format != SCORING_REPLAY_FORMAT:
            raise ValueError("scoring replay format is unsupported")
        if self.format_version != SCORING_REPLAY_FORMAT_VERSION:
            raise ValueError("scoring replay format version is unsupported")
        if _CASE_ID_PATTERN.fullmatch(self.case_id) is None:
            raise ValueError("scoring replay case_id is invalid")
        _validate_hash(self.before_manifest_sha256)
        _validate_hash(self.after_manifest_sha256)
        _validate_hash(self.replay_sha256)
        for value in (
            self.technical_score,
            self.drift_score,
            self.governance_score,
            self.base_overall_score,
            self.overall_score,
        ):
            if not 0.0 <= value <= 10.0:
                raise ValueError("scoring replay score must be within 0 to 10")
        if self.base_overall_score != max(
            self.technical_score, self.drift_score, self.governance_score
        ):
            raise ValueError("scoring replay base Overall Score is inconsistent")
        if self.overall_score < self.base_overall_score:
            raise ValueError("scoring replay Overall Score cannot reduce base risk")
        if severity_for_cvss_score(self.overall_score) is not self.severity:
            raise ValueError("scoring replay Severity is inconsistent")
        if self.hard_gate_triggered != (self.hard_gate_floor is not None):
            raise ValueError("scoring replay Hard Gate state is inconsistent")
        if self.hard_gate_floor not in {None, "high", "critical"}:
            raise ValueError("scoring replay Hard Gate floor is invalid")
        if self.replay_sha256 != _replay_hash(self.to_dict(include_hash=False)):
            raise ValueError("scoring replay hash is inconsistent")
        if len(set(self.mapping_basis)) != len(self.mapping_basis):
            raise ValueError("scoring replay mapping basis must be unique")

    def to_dict(self, *, include_hash: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "format": self.format,
            "format_version": self.format_version,
            "case_id": self.case_id,
            "agent_id": self.agent_id,
            "before_manifest_sha256": self.before_manifest_sha256,
            "after_manifest_sha256": self.after_manifest_sha256,
            "versions": self.versions.to_dict(),
            "component_hashes": self.component_hashes.to_dict(),
            "technical_score": self.technical_score,
            "drift_score": self.drift_score,
            "governance_score": self.governance_score,
            "base_overall_score": self.base_overall_score,
            "overall_score": self.overall_score,
            "severity": self.severity.value,
            "hard_gate_triggered": self.hard_gate_triggered,
            "hard_gate_floor": self.hard_gate_floor,
            "coverage_complete": self.coverage_complete,
            "mapping_basis": list(self.mapping_basis),
        }
        if include_hash:
            payload["replay_sha256"] = self.replay_sha256
        return payload


@dataclass(frozen=True, slots=True)
class ScoringReplaySuiteResult:
    """Ordered deterministic replay results for one regression suite."""

    format: Literal["agentsec-scoring-replay-suite"]
    format_version: Literal["0.1.0"]
    model_version: str
    cases: tuple[ScoringReplayResult, ...]
    suite_sha256: str

    def __post_init__(self) -> None:
        if self.format != SCORING_REPLAY_SUITE_FORMAT:
            raise ValueError("scoring replay suite format is unsupported")
        if self.format_version != SCORING_REPLAY_FORMAT_VERSION:
            raise ValueError("scoring replay suite version is unsupported")
        if self.model_version != SCORING_REPLAY_MODEL_VERSION:
            raise ValueError("scoring replay model version is unsupported")
        case_ids = tuple(item.case_id for item in self.cases)
        if not self.cases or case_ids != tuple(sorted(set(case_ids))):
            raise ValueError("scoring replay suite cases must be sorted and unique")
        _validate_hash(self.suite_sha256)
        if self.suite_sha256 != _replay_hash(self.to_dict(include_hash=False)):
            raise ValueError("scoring replay suite hash is inconsistent")

    def to_dict(self, *, include_hash: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "format": self.format,
            "format_version": self.format_version,
            "model_version": self.model_version,
            "cases": [item.to_dict() for item in self.cases],
        }
        if include_hash:
            payload["suite_sha256"] = self.suite_sha256
        return payload


class ScoringReplayError(RuntimeError):
    """Safe deterministic scoring replay failure."""


def encode_scoring_replay_suite_json(result: ScoringReplaySuiteResult) -> str:
    """Encode a frozen replay suite deterministically."""

    if not isinstance(result, ScoringReplaySuiteResult):
        raise TypeError("result must be ScoringReplaySuiteResult")
    return (
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


class DeterministicScoringReplayRunner:
    """Replay the complete P2-18 through P2-23 scoring chain."""

    def run(self, request: ScoringReplayRequest) -> ScoringReplayResult:
        if not isinstance(request, ScoringReplayRequest):
            raise TypeError("scoring replay requires ScoringReplayRequest")
        try:
            factors = DeterministicAgenticFactorExtractor().extract(request.after)
            threats = DeterministicThreatMitigationEvaluator().evaluate(
                request.after, factors
            )
            technical = DeterministicTechnicalScoreEngine().score(
                factors, threats, cvss=request.cvss
            )
            capability_diff = CapabilityDiffer().compare(
                before=request.before, after=request.after
            )
            drift = DeterministicDriftScoreEngine().score(
                request.before,
                request.after,
                diff=capability_diff,
                context=request.drift_context,
            )
            governance_context = request.governance_context or GovernanceScoreContext(
                drift=request.drift_context
            )
            governance = DeterministicGovernanceScoreEngine().score(
                request.after,
                factors,
                threats,
                context=governance_context,
                drift=drift,
            )
            overall = DeterministicOverallScoreEngine().score(
                technical,
                drift,
                governance,
                gate_matches=request.gate_matches,
            )
            component_hashes = ScoringReplayComponentHashes(
                factor_vector=_text_hash(encode_agentic_factor_vector_json(factors)),
                threat_mitigation=_text_hash(
                    encode_threat_mitigation_vector_json(threats)
                ),
                capability_diff=_object_hash(capability_diff.model_dump(mode="json")),
                technical_score=_text_hash(encode_technical_score_json(technical)),
                drift_score=_text_hash(encode_drift_score_json(drift)),
                governance_score=_text_hash(encode_governance_score_json(governance)),
                overall_score=_text_hash(encode_overall_score_json(overall)),
            )
            versions = ScoringReplayVersions(
                agentic_factor=AGENTIC_FACTOR_MODEL_VERSION,
                threat_mitigation=THREAT_MITIGATION_MODEL_VERSION,
                capability_diff=CAPABILITY_DIFF_SCHEMA_VERSION,
                technical_score=TECHNICAL_SCORE_MODEL_VERSION,
                drift_score=DRIFT_SCORE_MODEL_VERSION,
                governance_score=GOVERNANCE_SCORE_MODEL_VERSION,
                overall_score=OVERALL_SCORE_MODEL_VERSION,
                scoring_replay=SCORING_REPLAY_MODEL_VERSION,
            )
            unsigned: dict[str, object] = {
                "format": SCORING_REPLAY_FORMAT,
                "format_version": SCORING_REPLAY_FORMAT_VERSION,
                "case_id": request.case_id,
                "agent_id": request.after.identity.agent_id,
                "before_manifest_sha256": drift.before_manifest_sha256,
                "after_manifest_sha256": drift.after_manifest_sha256,
                "versions": versions.to_dict(),
                "component_hashes": component_hashes.to_dict(),
                "technical_score": technical.technical_score,
                "drift_score": drift.drift_score,
                "governance_score": governance.governance_score,
                "base_overall_score": overall.base_overall_score,
                "overall_score": overall.overall_score,
                "severity": overall.severity.value,
                "hard_gate_triggered": overall.hard_gate.triggered,
                "hard_gate_floor": (
                    overall.hard_gate.floor.value if overall.hard_gate.floor else None
                ),
                "coverage_complete": capability_diff.complete,
                "mapping_basis": list(SCORING_REPLAY_BASIS),
            }
            return ScoringReplayResult(
                format=SCORING_REPLAY_FORMAT,
                format_version=SCORING_REPLAY_FORMAT_VERSION,
                case_id=request.case_id,
                agent_id=request.after.identity.agent_id,
                before_manifest_sha256=drift.before_manifest_sha256,
                after_manifest_sha256=drift.after_manifest_sha256,
                versions=versions,
                component_hashes=component_hashes,
                technical_score=technical.technical_score,
                drift_score=drift.drift_score,
                governance_score=governance.governance_score,
                base_overall_score=overall.base_overall_score,
                overall_score=overall.overall_score,
                severity=overall.severity,
                hard_gate_triggered=overall.hard_gate.triggered,
                hard_gate_floor=(
                    overall.hard_gate.floor.value if overall.hard_gate.floor else None
                ),
                coverage_complete=capability_diff.complete,
                replay_sha256=_replay_hash(unsigned),
                mapping_basis=SCORING_REPLAY_BASIS,
            )
        except (TypeError, ValueError, RuntimeError) as error:
            raise ScoringReplayError("scoring replay failed safely") from error

    def run_suite(
        self, requests: tuple[ScoringReplayRequest, ...]
    ) -> ScoringReplaySuiteResult:
        if not isinstance(requests, tuple) or not requests:
            raise TypeError("scoring replay suite requires a non-empty tuple")
        if any(not isinstance(item, ScoringReplayRequest) for item in requests):
            raise TypeError("scoring replay suite contains an invalid request")
        case_ids = tuple(item.case_id for item in requests)
        if len(set(case_ids)) != len(case_ids):
            raise ScoringReplayError("scoring replay case IDs must be unique")
        cases = tuple(
            sorted((self.run(item) for item in requests), key=lambda x: x.case_id)
        )
        unsigned: dict[str, object] = {
            "format": SCORING_REPLAY_SUITE_FORMAT,
            "format_version": SCORING_REPLAY_FORMAT_VERSION,
            "model_version": SCORING_REPLAY_MODEL_VERSION,
            "cases": [item.to_dict() for item in cases],
        }
        return ScoringReplaySuiteResult(
            format=SCORING_REPLAY_SUITE_FORMAT,
            format_version=SCORING_REPLAY_FORMAT_VERSION,
            model_version=SCORING_REPLAY_MODEL_VERSION,
            cases=cases,
            suite_sha256=_replay_hash(unsigned),
        )


def _text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _object_hash(payload: object) -> str:
    return _text_hash(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    )


def _replay_hash(payload: object) -> str:
    return _object_hash(payload)


def _validate_hash(value: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("scoring replay hash must be lowercase SHA-256")


__all__ = [
    "SCORING_REPLAY_BASIS",
    "SCORING_REPLAY_FORMAT",
    "SCORING_REPLAY_FORMAT_VERSION",
    "SCORING_REPLAY_SUITE_FORMAT",
    "DeterministicScoringReplayRunner",
    "ScoringReplayComponentHashes",
    "ScoringReplayError",
    "ScoringReplayRequest",
    "ScoringReplayResult",
    "ScoringReplaySuiteResult",
    "ScoringReplayVersions",
    "encode_scoring_replay_suite_json",
]
