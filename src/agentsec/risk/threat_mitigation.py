"""Deterministic Threat and Mitigation assessment (P2-19).

This module consumes the P2-18 Agentic Factor Vector and finalized Manifest
controls.  It records threat signals and bounded static mitigations but does
not calculate Technical, Drift, Governance, or Overall scores.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from dataclasses import replace as dataclass_replace
from enum import StrEnum
from typing import Literal

from agentsec.domain import EvidenceConfidence
from agentsec.manifests import (
    AgentManifest,
    ManifestControl,
    ManifestControlKind,
    ManifestControlState,
    ManifestSourceReference,
    ManifestUnknown,
    ManifestUnknownDimension,
    encode_agent_manifest_json,
)
from agentsec.risk.agentic_factors import (
    AgenticFactorAssessment,
    AgenticFactorEvidence,
    AgenticFactorId,
    AgenticFactorVector,
)
from agentsec.versioning import (
    AGENTIC_FACTOR_MODEL_VERSION,
    THREAT_MITIGATION_MODEL_VERSION,
)

THREAT_MITIGATION_FORMAT: Literal["agentsec-threat-mitigation-vector"] = (
    "agentsec-threat-mitigation-vector"
)
THREAT_MITIGATION_FORMAT_VERSION: Literal["0.1.0"] = "0.1.0"
STATIC_MITIGATION_MULTIPLIER = 0.9
NO_MITIGATION_MULTIPLIER = 1.0
THREAT_MITIGATION_BASIS = (
    "AgentSec P2-19 deterministic Threat/Mitigation contract 0.1.0",
    "Static factor evidence is a potential threat signal, not exploitability proof",
    "Static control declarations receive at most a limited 0.9 multiplier",
    "Runtime verification is required before stronger mitigation authority",
)


class ThreatId(StrEnum):
    """Stable threat signals derived from one Agentic Factor."""

    INSTRUCTION_CONTROL_BYPASS = "instruction_control_bypass"
    CODE_EXECUTION_EXPOSURE = "code_execution_exposure"
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"
    EXTERNAL_NETWORK_EXPOSURE = "external_network_exposure"
    PRODUCTION_SIDE_EFFECT = "production_side_effect"
    PERSISTENT_STATE_TAMPERING = "persistent_state_tampering"
    DELEGATION_SCOPE_EXPANSION = "delegation_scope_expansion"
    EXTERNAL_IDENTITY_USE = "external_identity_use"
    AUTONOMOUS_SIDE_EFFECT = "autonomous_side_effect"
    APPROVAL_BYPASS = "approval_bypass"


class ThreatState(StrEnum):
    """Static threat signal state, explicitly separate from vulnerability proof."""

    ABSENT = "absent"
    UNKNOWN = "unknown"
    PRESENT_STATIC = "present_static"


class MitigationState(StrEnum):
    """State of a relevant static control declaration."""

    NOT_APPLICABLE = "not_applicable"
    ABSENT = "absent"
    DECLARED = "declared"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


_THREAT_ORDER = (
    (ThreatId.INSTRUCTION_CONTROL_BYPASS, AgenticFactorId.INSTRUCTION_OVERRIDE),
    (ThreatId.CODE_EXECUTION_EXPOSURE, AgenticFactorId.CODE_EXECUTION),
    (ThreatId.SENSITIVE_DATA_ACCESS, AgenticFactorId.SECRET_ACCESS),
    (ThreatId.EXTERNAL_NETWORK_EXPOSURE, AgenticFactorId.EXTERNAL_NETWORK),
    (ThreatId.PRODUCTION_SIDE_EFFECT, AgenticFactorId.PRODUCTION_ACCESS),
    (ThreatId.PERSISTENT_STATE_TAMPERING, AgenticFactorId.PERSISTENT_MEMORY),
    (ThreatId.DELEGATION_SCOPE_EXPANSION, AgenticFactorId.SUBAGENT_DELEGATION),
    (ThreatId.EXTERNAL_IDENTITY_USE, AgenticFactorId.EXTERNAL_IDENTITY),
    (ThreatId.AUTONOMOUS_SIDE_EFFECT, AgenticFactorId.AUTONOMOUS_ACTION),
    (ThreatId.APPROVAL_BYPASS, AgenticFactorId.APPROVAL_BYPASS),
)

_FACTOR_MITIGATION_KINDS: dict[AgenticFactorId, frozenset[ManifestControlKind]] = {
    AgenticFactorId.INSTRUCTION_OVERRIDE: frozenset(
        {ManifestControlKind.PREFIX_RULE, ManifestControlKind.TRUST}
    ),
    AgenticFactorId.CODE_EXECUTION: frozenset(
        {
            ManifestControlKind.HUMAN_APPROVAL,
            ManifestControlKind.SANDBOX,
            ManifestControlKind.PREFIX_RULE,
            ManifestControlKind.TOOL_FILTER,
            ManifestControlKind.TIMEOUT,
        }
    ),
    AgenticFactorId.SECRET_ACCESS: frozenset(
        {
            ManifestControlKind.HUMAN_APPROVAL,
            ManifestControlKind.SECRET_HANDLING,
            ManifestControlKind.TOOL_FILTER,
        }
    ),
    AgenticFactorId.EXTERNAL_NETWORK: frozenset(
        {
            ManifestControlKind.HUMAN_APPROVAL,
            ManifestControlKind.NETWORK_POLICY,
            ManifestControlKind.TOOL_FILTER,
        }
    ),
    AgenticFactorId.PRODUCTION_ACCESS: frozenset(
        {
            ManifestControlKind.HUMAN_APPROVAL,
            ManifestControlKind.TRUST,
            ManifestControlKind.TOOL_FILTER,
        }
    ),
    AgenticFactorId.PERSISTENT_MEMORY: frozenset(
        {ManifestControlKind.HUMAN_APPROVAL, ManifestControlKind.TOOL_FILTER}
    ),
    AgenticFactorId.SUBAGENT_DELEGATION: frozenset(
        {ManifestControlKind.TRUST, ManifestControlKind.TOOL_FILTER}
    ),
    AgenticFactorId.EXTERNAL_IDENTITY: frozenset(
        {ManifestControlKind.TRUST, ManifestControlKind.TOOL_FILTER}
    ),
    AgenticFactorId.AUTONOMOUS_ACTION: frozenset(
        {ManifestControlKind.HUMAN_APPROVAL, ManifestControlKind.TOOL_FILTER}
    ),
    AgenticFactorId.APPROVAL_BYPASS: frozenset({ManifestControlKind.HUMAN_APPROVAL}),
}


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    """One static threat signal derived from one Agentic Factor."""

    threat_id: ThreatId
    factor_id: AgenticFactorId
    state: ThreatState
    factor_value: float
    confidence: EvidenceConfidence
    evidence: tuple[AgenticFactorEvidence, ...] = ()
    relevant_unknown_ids: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.threat_id, ThreatId):
            raise TypeError("threat_id must be ThreatId")
        if not isinstance(self.factor_id, AgenticFactorId):
            raise TypeError("threat factor_id must be AgenticFactorId")
        if self.factor_value not in {0.0, 0.5, 1.0}:
            raise ValueError("threat factor_value must be 0.0, 0.5, or 1.0")
        expected = {
            0.0: ThreatState.ABSENT,
            0.5: ThreatState.UNKNOWN,
            1.0: ThreatState.PRESENT_STATIC,
        }[self.factor_value]
        if self.state is not expected:
            raise ValueError("threat state must match factor value")
        if not isinstance(self.confidence, EvidenceConfidence):
            raise TypeError("threat confidence must be EvidenceConfidence")
        _validate_evidence(self.evidence)
        _validate_string_tuple(self.relevant_unknown_ids, "threat unknown IDs")
        _validate_string_tuple(self.rationale, "threat rationale")
        _validate_string_tuple(self.limitations, "threat limitations")
        if self.state is not ThreatState.ABSENT and not self.limitations:
            raise ValueError("potential or present threats require limitations")

    def to_dict(self) -> dict[str, object]:
        return {
            "threat_id": self.threat_id.value,
            "factor_id": self.factor_id.value,
            "state": self.state.value,
            "factor_value": self.factor_value,
            "confidence": self.confidence.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "relevant_unknown_ids": list(self.relevant_unknown_ids),
            "rationale": list(self.rationale),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class MitigationAssessment:
    """A bounded static-control assessment for one threat signal."""

    state: MitigationState
    multiplier: float
    confidence: EvidenceConfidence | None
    control_kinds: tuple[ManifestControlKind, ...] = ()
    evidence: tuple[AgenticFactorEvidence, ...] = ()
    relevant_unknown_ids: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.state, MitigationState):
            raise TypeError("mitigation state must be MitigationState")
        if not 0.0 <= self.multiplier <= 1.0:
            raise ValueError("mitigation multiplier must be between 0 and 1")
        if self.multiplier < STATIC_MITIGATION_MULTIPLIER:
            raise ValueError(
                "static mitigation cannot reduce risk below the approved floor"
            )
        if self.state is MitigationState.NOT_APPLICABLE:
            if self.confidence is not None or self.evidence or self.control_kinds:
                raise ValueError("not-applicable mitigation cannot contain controls")
            if self.multiplier != NO_MITIGATION_MULTIPLIER:
                raise ValueError("not-applicable mitigation multiplier must be 1")
        elif self.confidence is None:
            raise ValueError("applicable mitigation requires confidence")
        _validate_enum_tuple(self.control_kinds, "control kinds")
        _validate_evidence(self.evidence)
        _validate_string_tuple(self.relevant_unknown_ids, "mitigation unknown IDs")
        _validate_string_tuple(self.rationale, "mitigation rationale")
        _validate_string_tuple(self.limitations, "mitigation limitations")

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "multiplier": self.multiplier,
            "confidence": self.confidence.value if self.confidence else None,
            "control_kinds": [item.value for item in self.control_kinds],
            "evidence": [item.to_dict() for item in self.evidence],
            "relevant_unknown_ids": list(self.relevant_unknown_ids),
            "rationale": list(self.rationale),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class ThreatMitigationAssessment:
    """One threat and its independently assessed bounded mitigation."""

    threat: ThreatAssessment
    mitigation: MitigationAssessment

    def __post_init__(self) -> None:
        if not isinstance(self.threat, ThreatAssessment):
            raise TypeError("threat assessment is invalid")
        if not isinstance(self.mitigation, MitigationAssessment):
            raise TypeError("mitigation assessment is invalid")
        if self.threat.state is ThreatState.UNKNOWN and (
            self.mitigation.multiplier != NO_MITIGATION_MULTIPLIER
        ):
            raise ValueError("unknown threats cannot receive mitigation reduction")

    def to_dict(self) -> dict[str, object]:
        return {
            "threat": self.threat.to_dict(),
            "mitigation": self.mitigation.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ThreatMitigationVector:
    """Versioned ten-signal Threat/Mitigation vector."""

    format: Literal["agentsec-threat-mitigation-vector"]
    format_version: Literal["0.1.0"]
    model_version: str
    agentic_factor_model_version: str
    manifest_schema_version: str
    agent_id: str
    manifest_sha256: str
    static_mitigation_floor: float
    assessments: tuple[ThreatMitigationAssessment, ...] = dataclass_field(repr=False)
    mapping_basis: tuple[str, ...] = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if self.format != THREAT_MITIGATION_FORMAT:
            raise ValueError("Threat/Mitigation format is unsupported")
        if self.format_version != THREAT_MITIGATION_FORMAT_VERSION:
            raise ValueError("Threat/Mitigation format version is unsupported")
        if self.model_version != THREAT_MITIGATION_MODEL_VERSION:
            raise ValueError("Threat/Mitigation model version is unsupported")
        if self.agentic_factor_model_version != AGENTIC_FACTOR_MODEL_VERSION:
            raise ValueError("Agentic Factor model version is unsupported")
        if not self.agent_id.strip():
            raise ValueError("Threat/Mitigation Agent ID must not be empty")
        if len(self.manifest_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in self.manifest_sha256
        ):
            raise ValueError("manifest_sha256 must be lowercase SHA-256")
        if self.static_mitigation_floor != STATIC_MITIGATION_MULTIPLIER:
            raise ValueError("static mitigation floor is inconsistent")
        factor_ids = tuple(item.threat.factor_id for item in self.assessments)
        expected = tuple(factor_id for _, factor_id in _THREAT_ORDER)
        if factor_ids != expected:
            raise ValueError(
                "Threat/Mitigation assessments must use stable factor order"
            )
        _validate_unique_strings(self.mapping_basis, "mapping basis")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "model_version": self.model_version,
            "agentic_factor_model_version": self.agentic_factor_model_version,
            "manifest_schema_version": self.manifest_schema_version,
            "agent_id": self.agent_id,
            "manifest_sha256": self.manifest_sha256,
            "static_mitigation_floor": self.static_mitigation_floor,
            "assessments": [item.to_dict() for item in self.assessments],
            "mapping_basis": list(self.mapping_basis),
        }


class ThreatMitigationEvaluationError(RuntimeError):
    """Safe failure while evaluating Threat and Mitigation inputs."""


def encode_threat_mitigation_vector_json(vector: ThreatMitigationVector) -> str:
    """Encode the versioned Threat/Mitigation vector deterministically."""

    if not isinstance(vector, ThreatMitigationVector):
        raise TypeError("vector must be ThreatMitigationVector")
    return (
        json.dumps(vector.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


class DeterministicThreatMitigationEvaluator:
    """Evaluate static threat signals and conservative control declarations."""

    def evaluate(
        self,
        manifest: AgentManifest,
        factors: AgenticFactorVector,
    ) -> ThreatMitigationVector:
        if not isinstance(manifest, AgentManifest):
            raise TypeError("Threat/Mitigation evaluation requires AgentManifest")
        if not isinstance(factors, AgenticFactorVector):
            raise TypeError("Threat/Mitigation evaluation requires Factor Vector")
        try:
            manifest_hash = _manifest_sha256(manifest)
            if factors.agent_id != manifest.identity.agent_id:
                raise ValueError("Factor Vector Agent binding is inconsistent")
            if factors.manifest_sha256 != manifest_hash:
                raise ValueError("Factor Vector Manifest hash is inconsistent")
            by_factor = {item.factor_id: item for item in factors.factors}
            assessments = tuple(
                self._evaluate_one(
                    manifest,
                    threat_id,
                    factor_id,
                    by_factor[factor_id],
                    manifest_hash,
                )
                for threat_id, factor_id in _THREAT_ORDER
            )
            return ThreatMitigationVector(
                format=THREAT_MITIGATION_FORMAT,
                format_version=THREAT_MITIGATION_FORMAT_VERSION,
                model_version=THREAT_MITIGATION_MODEL_VERSION,
                agentic_factor_model_version=AGENTIC_FACTOR_MODEL_VERSION,
                manifest_schema_version=manifest.schema_version,
                agent_id=manifest.identity.agent_id,
                manifest_sha256=manifest_hash,
                static_mitigation_floor=STATIC_MITIGATION_MULTIPLIER,
                assessments=assessments,
                mapping_basis=THREAT_MITIGATION_BASIS,
            )
        except (TypeError, ValueError, KeyError) as error:
            raise ThreatMitigationEvaluationError(
                "Threat/Mitigation evaluation failed safely"
            ) from error

    def _evaluate_one(
        self,
        manifest: AgentManifest,
        threat_id: ThreatId,
        factor_id: AgenticFactorId,
        factor: AgenticFactorAssessment,
        manifest_hash: str,
    ) -> ThreatMitigationAssessment:
        del manifest_hash
        threat = ThreatAssessment(
            threat_id=threat_id,
            factor_id=factor_id,
            state={
                0.0: ThreatState.ABSENT,
                0.5: ThreatState.UNKNOWN,
                1.0: ThreatState.PRESENT_STATIC,
            }[factor.value],
            factor_value=factor.value,
            confidence=factor.confidence,
            evidence=factor.evidence,
            relevant_unknown_ids=factor.relevant_unknown_ids,
            rationale=factor.rationale
            + ("Threat state is derived from static Factor evidence only.",),
            limitations=(
                (
                    "This signal does not prove runtime reachability, "
                    "exploitability, or successful impact."
                ),
            )
            if factor.value > 0
            else (),
        )
        if threat.state is ThreatState.ABSENT:
            mitigation = MitigationAssessment(
                state=MitigationState.NOT_APPLICABLE,
                multiplier=NO_MITIGATION_MULTIPLIER,
                confidence=None,
                rationale=("No static threat signal requires mitigation assessment.",),
            )
        else:
            mitigation = self._mitigation(manifest, factor_id)
            if (
                threat.state is ThreatState.UNKNOWN
                and mitigation.multiplier != NO_MITIGATION_MULTIPLIER
            ):
                mitigation = dataclass_replace(
                    mitigation,
                    multiplier=NO_MITIGATION_MULTIPLIER,
                    limitations=_unique_strings(
                        mitigation.limitations
                        + ("Unknown threat state prevents mitigation reduction.",)
                    ),
                )
        return ThreatMitigationAssessment(threat=threat, mitigation=mitigation)

    def _mitigation(
        self,
        manifest: AgentManifest,
        factor_id: AgenticFactorId,
    ) -> MitigationAssessment:
        kinds = _FACTOR_MITIGATION_KINDS[factor_id]
        matching = tuple(
            control for control in manifest.controls.controls if control.kind in kinds
        )
        unknowns = _relevant_control_unknowns(manifest, kinds)
        evidence = _control_evidence(matching, manifest)
        control_kinds = tuple(
            sorted({control.kind for control in matching}, key=lambda item: item.value)
        )
        states = {control.state for control in matching}
        if any(
            state
            in {
                ManifestControlState.ENABLED,
                ManifestControlState.REQUIRED,
                ManifestControlState.OPTIONAL,
                ManifestControlState.ALLOW,
                ManifestControlState.PROMPT,
                ManifestControlState.CONFIGURED,
            }
            for state in states
        ):
            return MitigationAssessment(
                state=MitigationState.DECLARED,
                multiplier=STATIC_MITIGATION_MULTIPLIER,
                confidence=EvidenceConfidence.B,
                control_kinds=control_kinds,
                evidence=evidence,
                relevant_unknown_ids=tuple(
                    sorted(item.unknown_id for item in unknowns)
                ),
                rationale=("A relevant static control is declared in the Manifest.",),
                limitations=(
                    (
                        "Static control declarations receive only a limited "
                        "reduction; runtime enforcement is unverified."
                    ),
                ),
            )
        if any(state is ManifestControlState.UNKNOWN for state in states) or unknowns:
            return MitigationAssessment(
                state=MitigationState.UNKNOWN,
                multiplier=NO_MITIGATION_MULTIPLIER,
                confidence=EvidenceConfidence.D,
                control_kinds=control_kinds,
                evidence=evidence,
                relevant_unknown_ids=tuple(
                    sorted(item.unknown_id for item in unknowns)
                ),
                rationale=("Relevant control coverage or control state is unknown.",),
                limitations=(
                    (
                        "Unknown control state cannot be treated as an effective "
                        "mitigation."
                    ),
                ),
            )
        if matching and all(state is ManifestControlState.DISABLED for state in states):
            return MitigationAssessment(
                state=MitigationState.DISABLED,
                multiplier=NO_MITIGATION_MULTIPLIER,
                confidence=EvidenceConfidence.B,
                control_kinds=control_kinds,
                evidence=evidence,
                rationale=("All matching static controls are explicitly disabled.",),
                limitations=(
                    "Disabled controls do not reduce the static threat signal.",
                ),
            )
        return MitigationAssessment(
            state=MitigationState.ABSENT,
            multiplier=NO_MITIGATION_MULTIPLIER,
            confidence=EvidenceConfidence.D,
            relevant_unknown_ids=tuple(sorted(item.unknown_id for item in unknowns)),
            rationale=("No relevant mitigation control was materialized.",),
            limitations=(
                (
                    "Absence of a static control is not proof that no runtime "
                    "control exists."
                ),
            ),
        )


def _manifest_sha256(manifest: AgentManifest) -> str:
    return hashlib.sha256(
        encode_agent_manifest_json(manifest).encode("utf-8")
    ).hexdigest()


def _control_evidence(
    controls: Iterable[ManifestControl],
    manifest: AgentManifest,
) -> tuple[AgenticFactorEvidence, ...]:
    source_hashes = {
        source.locator.sort_key(): source.content_sha256 for source in manifest.sources
    }
    references: list[ManifestSourceReference] = []
    for control in controls:
        references.extend(control.sources)
    by_key: dict[tuple[str, str, str, str, int, int], AgenticFactorEvidence] = {}
    for reference in references:
        by_key[reference.sort_key()] = AgenticFactorEvidence(
            locator=reference.locator,
            content_sha256=source_hashes[reference.locator.sort_key()],
            field_path=reference.field_path,
            start_line=reference.start_line,
            end_line=reference.end_line,
        )
    return tuple(by_key[key] for key in sorted(by_key))


def _relevant_control_unknowns(
    manifest: AgentManifest,
    kinds: frozenset[ManifestControlKind],
) -> tuple[ManifestUnknown, ...]:
    kind_values = {kind.value for kind in kinds}
    return tuple(
        unknown
        for unknown in manifest.unknowns
        if unknown.dimension is ManifestUnknownDimension.CONTROLS
        and (
            unknown.field is None
            or unknown.field == "controls.resolution"
            or any(kind in unknown.field for kind in kind_values)
        )
    )


def _validate_evidence(evidence: tuple[AgenticFactorEvidence, ...]) -> None:
    if any(not isinstance(item, AgenticFactorEvidence) for item in evidence):
        raise TypeError("invalid Threat/Mitigation evidence")
    keys = tuple(item.sort_key() for item in evidence)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ValueError("Threat/Mitigation evidence must be sorted and unique")


def _validate_enum_tuple(values: tuple[ManifestControlKind, ...], label: str) -> None:
    if tuple(sorted(value.value for value in values)) != tuple(
        value.value for value in values
    ):
        raise ValueError(f"{label} must be sorted")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


def _validate_string_tuple(values: tuple[str, ...], label: str) -> None:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} values must be non-empty text")
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{label} must be sorted and unique")


def _validate_unique_strings(values: tuple[str, ...], label: str) -> None:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{label} values must be non-empty text")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} values must be unique")


def _unique_strings(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({value for value in values if value.strip()}))


__all__ = [
    "NO_MITIGATION_MULTIPLIER",
    "STATIC_MITIGATION_MULTIPLIER",
    "THREAT_MITIGATION_BASIS",
    "THREAT_MITIGATION_FORMAT",
    "THREAT_MITIGATION_FORMAT_VERSION",
    "DeterministicThreatMitigationEvaluator",
    "MitigationAssessment",
    "MitigationState",
    "ThreatAssessment",
    "ThreatId",
    "ThreatMitigationAssessment",
    "ThreatMitigationEvaluationError",
    "ThreatMitigationVector",
    "ThreatState",
    "encode_threat_mitigation_vector_json",
]
