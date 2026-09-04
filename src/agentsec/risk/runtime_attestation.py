"""Runtime Attestation trust, ingestion, and Evidence Reconciliation (RISK-07).

AgentSec never executes a scanned Agent to produce an attestation.  RISK-06
accepts a separately produced, value-minimized runtime observation artifact and
RISK-07 verifies its external trust metadata before reconciling it with the
static Operation Context and RISK-04 report. The result can establish evidence
that an operation was observed, but it does not grant permission, authenticate
an Agent, or block CI.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from agentsec.domain import EvidenceConfidence
from agentsec.risk.context import (
    OperationAction,
    OperationContextSet,
    OperationTarget,
    canonical_operation_context_sha256,
)
from agentsec.risk.context_rules import (
    ContextRiskReport,
    canonical_context_risk_sha256,
)
from agentsec.versioning import (
    EVIDENCE_RECONCILIATION_REPORT_VERSION,
    RUNTIME_ATTESTATION_REPORT_VERSION,
    RUNTIME_REPLAY_STORE_VERSION,
    RUNTIME_TRUST_REGISTRY_VERSION,
    RUNTIME_TRUST_VERIFICATION_REPORT_VERSION,
)

RUNTIME_ATTESTATION_FORMAT: Literal["agentsec-runtime-attestation"] = (
    "agentsec-runtime-attestation"
)
RUNTIME_ATTESTATION_FORMAT_VERSION = RUNTIME_ATTESTATION_REPORT_VERSION
EVIDENCE_RECONCILIATION_FORMAT: Literal["agentsec-evidence-reconciliation"] = (
    "agentsec-evidence-reconciliation"
)
EVIDENCE_RECONCILIATION_FORMAT_VERSION = EVIDENCE_RECONCILIATION_REPORT_VERSION
RUNTIME_TRUST_REGISTRY_FORMAT_VERSION = RUNTIME_TRUST_REGISTRY_VERSION
RUNTIME_TRUST_VERIFICATION_FORMAT_VERSION = RUNTIME_TRUST_VERIFICATION_REPORT_VERSION
RUNTIME_REPLAY_STORE_FORMAT_VERSION = RUNTIME_REPLAY_STORE_VERSION
RUNTIME_TRUST_REGISTRY_FORMAT: Literal["agentsec-runtime-trust-registry"] = (
    "agentsec-runtime-trust-registry"
)
RUNTIME_TRUST_VERIFICATION_FORMAT: Literal["agentsec-runtime-trust-verification"] = (
    "agentsec-runtime-trust-verification"
)
RUNTIME_REPLAY_STORE_FORMAT: Literal["agentsec-runtime-replay-store"] = (
    "agentsec-runtime-replay-store"
)
RUNTIME_ATTESTATION_BASIS = (
    "AgentSec RISK-07 external Runtime Attestation contract 0.2.0",
    (
        "Attestation is produced outside the static scanner and is ingested as "
        "untrusted evidence"
    ),
    "Runtime evidence can increase evidence confidence only after trust verification",
)
EVIDENCE_RECONCILIATION_BASIS = (
    "AgentSec RISK-07 deterministic Evidence Reconciliation contract 0.2.0",
    "Reconciliation binds runtime observations to Operation Context and RISK-04 hashes",
    (
        "Unmatched or conflicting observations remain explicit and do not become "
        "runtime proof"
    ),
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_STABLE_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_UTC_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE_TEXT_PATTERN = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|bearer\s+[A-Za-z0-9._~+/=-]+|"
    r"(?:password|passwd|secret|token|api[_-]?key|credential)\s*[:=]\s*\S+|"
    r"https?://\S+|(?:\d{1,3}\.){3}\d{1,3})"
)
_MAX_RUNTIME_ATTESTATION_BYTES = 2_097_152
_MAX_RUNTIME_OBSERVATIONS = 128
_MAX_LIMITATIONS = 32
_MAX_LIMITATION_LENGTH = 512
_MIN_RUNTIME_KEY_BYTES = 32


class RuntimeAttestationError(ValueError):
    """Raised when runtime evidence is malformed or cannot be reconciled."""


class RuntimeAttestationMethod(StrEnum):
    SIGNED_ATTESTATION = "signed_attestation"
    RUNTIME_VERIFICATION = "runtime_verification"
    REPRODUCIBLE_TEST = "reproducible_test"
    ACTUAL_TOOL_ENUMERATION = "actual_tool_enumeration"


class RuntimeSignatureAlgorithm(StrEnum):
    """Signature algorithm supported without network or target execution."""

    HMAC_SHA256 = "hmac_sha256"


class RuntimeVerificationStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    REJECTED = "rejected"


class RuntimeTrustStatus(StrEnum):
    """Outcome of trusted issuer, signature, time, and replay checks."""

    TRUSTED = "trusted"
    MISSING = "missing"
    UNKNOWN_ISSUER = "unknown_issuer"
    KEY_REVOKED = "key_revoked"
    KEY_MISMATCH = "key_mismatch"
    SIGNATURE_INVALID = "signature_invalid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    REPLAYED = "replayed"
    REPLAY_STORE_ERROR = "replay_store_error"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    UNVERIFIED_ATTESTATION = "unverified_attestation"
    KEY_UNAVAILABLE = "key_unavailable"


class ReconciliationStatus(StrEnum):
    RECONCILED = "reconciled"
    PARTIAL = "partial"
    CONFLICT = "conflict"
    UNVERIFIED = "unverified"


@dataclass(frozen=True, slots=True)
class RuntimeObservation:
    """One sanitized runtime observation for a declared operation."""

    observation_id: str
    operation_id: str
    action: OperationAction
    target: OperationTarget
    observed: bool
    evidence_sha256: str
    source_ref: str
    observed_at: str

    def __post_init__(self) -> None:
        _require_prefixed_id(
            self.observation_id, "runtime observation ID", "runtime-observation-sha256:"
        )
        _require_stable_id(self.operation_id, "runtime observation operation_id")
        if not isinstance(self.action, OperationAction):
            raise TypeError("runtime observation action is invalid")
        if not isinstance(self.target, OperationTarget):
            raise TypeError("runtime observation target is invalid")
        if not isinstance(self.observed, bool):
            raise TypeError("runtime observation observed must be bool")
        _require_digest(self.evidence_sha256, "runtime observation evidence_sha256")
        _require_stable_id(self.source_ref, "runtime observation source_ref")
        if _UTC_TIMESTAMP_PATTERN.fullmatch(self.observed_at) is None:
            raise RuntimeAttestationError(
                "runtime observation observed_at must use UTC RFC3339 seconds"
            )
        expected = runtime_observation_id(
            operation_id=self.operation_id,
            action=self.action,
            target=self.target,
            observed=self.observed,
            evidence_sha256=self.evidence_sha256,
            source_ref=self.source_ref,
            observed_at=self.observed_at,
        )
        if self.observation_id != expected:
            raise RuntimeAttestationError("runtime observation ID is inconsistent")

    def sort_key(self) -> tuple[str, str]:
        return (self.operation_id, self.observation_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "observation_id": self.observation_id,
            "operation_id": self.operation_id,
            "action": self.action.value,
            "target": self.target.value,
            "observed": self.observed,
            "evidence_sha256": self.evidence_sha256,
            "source_ref": self.source_ref,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True, slots=True)
class RuntimeAttestation:
    """External runtime evidence with an explicit verification declaration."""

    format: Literal["agentsec-runtime-attestation"]
    format_version: str
    attestation_id: str
    agent_snapshot_sha256: str
    context_sha256: str
    issuer: str
    key_id: str
    signature_algorithm: RuntimeSignatureAlgorithm
    issued_at: str
    expires_at: str
    nonce: str
    method: RuntimeAttestationMethod
    verification_status: RuntimeVerificationStatus
    observations: tuple[RuntimeObservation, ...]
    limitations: tuple[str, ...]
    evidence_confidence: EvidenceConfidence
    runtime_verified: bool
    signature: str
    report_only: Literal[True] = True
    policy_authority: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != RUNTIME_ATTESTATION_FORMAT:
            raise RuntimeAttestationError("runtime attestation format is unsupported")
        if self.format_version != RUNTIME_ATTESTATION_FORMAT_VERSION:
            raise RuntimeAttestationError("runtime attestation version is unsupported")
        _require_prefixed_id(
            self.attestation_id,
            "runtime attestation ID",
            "runtime-attestation-sha256:",
        )
        _require_digest(self.agent_snapshot_sha256, "agent snapshot digest")
        _require_digest(self.context_sha256, "runtime context digest")
        _require_stable_id(self.issuer, "runtime attestation issuer")
        _require_stable_id(self.key_id, "runtime attestation key_id")
        if not isinstance(self.signature_algorithm, RuntimeSignatureAlgorithm):
            raise TypeError("runtime attestation signature algorithm is invalid")
        if _UTC_TIMESTAMP_PATTERN.fullmatch(self.issued_at) is None:
            raise RuntimeAttestationError(
                "runtime attestation issued_at must use UTC RFC3339 seconds"
            )
        if _UTC_TIMESTAMP_PATTERN.fullmatch(self.expires_at) is None:
            raise RuntimeAttestationError(
                "runtime attestation expires_at must use UTC RFC3339 seconds"
            )
        if _parse_utc(self.expires_at) <= _parse_utc(self.issued_at):
            raise RuntimeAttestationError(
                "runtime attestation expires_at must be after issued_at"
            )
        if _NONCE_PATTERN.fullmatch(self.nonce) is None:
            raise RuntimeAttestationError("runtime attestation nonce is invalid")
        _require_hex_digest(self.signature, "runtime attestation signature")
        if not isinstance(self.method, RuntimeAttestationMethod):
            raise TypeError("runtime attestation method is invalid")
        if not isinstance(self.verification_status, RuntimeVerificationStatus):
            raise TypeError("runtime attestation verification status is invalid")
        if not self.observations:
            raise RuntimeAttestationError("runtime attestation requires observations")
        if len(self.observations) > _MAX_RUNTIME_OBSERVATIONS:
            raise RuntimeAttestationError(
                "runtime attestation observation limit exceeded"
            )
        if self.observations != tuple(
            sorted(self.observations, key=RuntimeObservation.sort_key)
        ):
            raise RuntimeAttestationError("runtime observations must be sorted")
        ids = tuple(item.observation_id for item in self.observations)
        if len(ids) != len(set(ids)):
            raise RuntimeAttestationError("runtime observations must be unique")
        _require_bounded_text_tuple(
            self.limitations,
            "runtime attestation limitations",
            maximum_items=_MAX_LIMITATIONS,
            maximum_length=_MAX_LIMITATION_LENGTH,
        )
        _require_value_minimized_text_tuple(
            self.limitations,
            "runtime attestation limitations",
        )
        if not isinstance(self.evidence_confidence, EvidenceConfidence):
            raise TypeError("runtime attestation confidence is invalid")
        if not isinstance(self.runtime_verified, bool):
            raise TypeError("runtime_verified must be bool")
        if self.runtime_verified:
            raise RuntimeAttestationError(
                "untrusted Runtime Attestation cannot set runtime_verified"
            )
        if self.evidence_confidence is not EvidenceConfidence.D:
            raise RuntimeAttestationError(
                "untrusted Runtime Attestation must have Confidence D"
            )
        if (
            self.report_only is not True
            or self.policy_authority is not False
            or self.ci_blocked is not False
        ):
            raise RuntimeAttestationError(
                "runtime attestation authority fields are invalid"
            )
        expected = runtime_attestation_id(
            agent_snapshot_sha256=self.agent_snapshot_sha256,
            context_sha256=self.context_sha256,
            issuer=self.issuer,
            key_id=self.key_id,
            signature_algorithm=self.signature_algorithm,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            nonce=self.nonce,
            method=self.method,
            verification_status=self.verification_status,
            observations=self.observations,
            limitations=self.limitations,
            evidence_confidence=self.evidence_confidence,
        )
        if self.attestation_id != expected:
            raise RuntimeAttestationError("runtime attestation ID is inconsistent")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "attestation_id": self.attestation_id,
            "agent_snapshot_sha256": self.agent_snapshot_sha256,
            "context_sha256": self.context_sha256,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "signature_algorithm": self.signature_algorithm.value,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "method": self.method.value,
            "verification_status": self.verification_status.value,
            "observations": [item.to_dict() for item in self.observations],
            "limitations": list(self.limitations),
            "evidence_confidence": self.evidence_confidence.value,
            "runtime_verified": self.runtime_verified,
            "signature": self.signature,
            "report_only": self.report_only,
            "policy_authority": self.policy_authority,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "policy_authority": self.policy_authority,
                "ci_blocked": self.ci_blocked,
            },
        }

    def signing_dict(self) -> dict[str, object]:
        """Return canonical signed content, excluding detached signature."""

        payload = self.to_dict()
        payload.pop("signature", None)
        return payload


@dataclass(frozen=True, slots=True)
class RuntimeContextMismatch:
    """A declared/runtime action or target mismatch."""

    operation_id: str
    observation_id: str
    declared_action: OperationAction
    observed_action: OperationAction
    declared_target: OperationTarget
    observed_target: OperationTarget
    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_stable_id(self.operation_id, "runtime mismatch operation_id")
        _require_prefixed_id(
            self.observation_id,
            "runtime mismatch observation_id",
            "runtime-observation-sha256:",
        )
        if not isinstance(self.declared_action, OperationAction) or not isinstance(
            self.observed_action, OperationAction
        ):
            raise TypeError("runtime mismatch actions are invalid")
        if not isinstance(self.declared_target, OperationTarget) or not isinstance(
            self.observed_target, OperationTarget
        ):
            raise TypeError("runtime mismatch targets are invalid")
        _require_text_tuple(self.fields, "runtime mismatch fields")

    def sort_key(self) -> tuple[str, str]:
        return (self.operation_id, self.observation_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "observation_id": self.observation_id,
            "declared_action": self.declared_action.value,
            "observed_action": self.observed_action.value,
            "declared_target": self.declared_target.value,
            "observed_target": self.observed_target.value,
            "fields": list(self.fields),
        }


@dataclass(frozen=True, slots=True)
class RuntimeTrustDecision:
    """Fail-closed trust result for one external Runtime Attestation."""

    verification_id: str
    source_attestation_sha256: str
    trust_registry_sha256: str | None
    issuer: str
    key_id: str
    signature_algorithm: RuntimeSignatureAlgorithm
    status: RuntimeTrustStatus
    issuer_trusted: bool
    key_trusted: bool
    signature_verified: bool
    time_valid: bool
    replay_detected: bool
    evaluated_at: str
    reason_codes: tuple[str, ...]
    key_fingerprint_sha256: str | None = None
    report_only: Literal[True] = True
    policy_authority: Literal[False] = False
    ci_blocked: Literal[False] = False

    @property
    def trusted(self) -> bool:
        return self.status is RuntimeTrustStatus.TRUSTED

    def __post_init__(self) -> None:
        _require_prefixed_id(
            self.verification_id,
            "runtime trust verification ID",
            "runtime-trust-verification-sha256:",
        )
        _require_digest(
            self.source_attestation_sha256,
            "runtime trust source attestation digest",
        )
        if self.trust_registry_sha256 is not None:
            _require_digest(
                self.trust_registry_sha256,
                "runtime trust registry digest",
            )
        _require_stable_id(self.issuer, "runtime trust issuer")
        _require_stable_id(self.key_id, "runtime trust key_id")
        if not isinstance(self.signature_algorithm, RuntimeSignatureAlgorithm):
            raise TypeError("runtime trust signature algorithm is invalid")
        if not isinstance(self.status, RuntimeTrustStatus):
            raise TypeError("runtime trust status is invalid")
        for value, label in (
            (self.issuer_trusted, "issuer_trusted"),
            (self.key_trusted, "key_trusted"),
            (self.signature_verified, "signature_verified"),
            (self.time_valid, "time_valid"),
            (self.replay_detected, "replay_detected"),
        ):
            if not isinstance(value, bool):
                raise TypeError(f"runtime trust {label} must be bool")
        if _UTC_TIMESTAMP_PATTERN.fullmatch(self.evaluated_at) is None:
            raise RuntimeAttestationError(
                "runtime trust evaluated_at must use UTC RFC3339 seconds"
            )
        _require_bounded_text_tuple(
            self.reason_codes,
            "runtime trust reason_codes",
            maximum_items=16,
            maximum_length=128,
        )
        if self.key_fingerprint_sha256 is not None:
            _require_digest(
                self.key_fingerprint_sha256, "runtime trust key fingerprint"
            )
        if (
            self.report_only is not True
            or self.policy_authority is not False
            or self.ci_blocked is not False
        ):
            raise RuntimeAttestationError("runtime trust authority fields are invalid")
        expected_id = runtime_trust_verification_id(
            source_attestation_sha256=self.source_attestation_sha256,
            trust_registry_sha256=self.trust_registry_sha256,
            issuer=self.issuer,
            key_id=self.key_id,
            signature_algorithm=self.signature_algorithm,
            status=self.status,
            trusted=self.trusted,
            issuer_trusted=self.issuer_trusted,
            key_trusted=self.key_trusted,
            signature_verified=self.signature_verified,
            time_valid=self.time_valid,
            replay_detected=self.replay_detected,
            evaluated_at=self.evaluated_at,
            reason_codes=self.reason_codes,
            key_fingerprint_sha256=self.key_fingerprint_sha256,
        )
        if self.verification_id != expected_id:
            raise RuntimeAttestationError(
                "runtime trust verification ID is inconsistent"
            )
        if self.trusted and not (
            self.issuer_trusted
            and self.key_trusted
            and self.signature_verified
            and self.time_valid
            and not self.replay_detected
        ):
            raise RuntimeAttestationError(
                "trusted runtime decision has inconsistent verification flags"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "format": RUNTIME_TRUST_VERIFICATION_FORMAT,
            "format_version": RUNTIME_TRUST_VERIFICATION_FORMAT_VERSION,
            "verification_id": self.verification_id,
            "source_attestation_sha256": self.source_attestation_sha256,
            "trust_registry_sha256": self.trust_registry_sha256,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "signature_algorithm": self.signature_algorithm.value,
            "status": self.status.value,
            "trusted": self.trusted,
            "issuer_trusted": self.issuer_trusted,
            "key_trusted": self.key_trusted,
            "signature_verified": self.signature_verified,
            "time_valid": self.time_valid,
            "replay_detected": self.replay_detected,
            "evaluated_at": self.evaluated_at,
            "reason_codes": list(self.reason_codes),
            "key_fingerprint_sha256": self.key_fingerprint_sha256,
            "report_only": self.report_only,
            "policy_authority": self.policy_authority,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "policy_authority": self.policy_authority,
                "ci_blocked": self.ci_blocked,
            },
        }


@dataclass(frozen=True, slots=True)
class EvidenceReconciliationReport:
    """RISK-06 report binding runtime observations to static evidence."""

    format: Literal["agentsec-evidence-reconciliation"]
    format_version: str
    reconciliation_id: str
    source_agent_snapshot_sha256: str
    source_context_sha256: str
    source_risk_report_sha256: str
    source_attestation_sha256: str
    status: ReconciliationStatus
    runtime_verified: bool
    current_posture_eligible: bool
    evidence_confidence: EvidenceConfidence
    context_coverage_complete: bool
    unknown_context_dimensions: tuple[str, ...]
    matched_operation_ids: tuple[str, ...]
    declared_not_observed_operation_ids: tuple[str, ...]
    observed_not_declared_operation_ids: tuple[str, ...]
    mismatches: tuple[RuntimeContextMismatch, ...]
    reconciled_risk_finding_ids: tuple[str, ...]
    unreconciled_risk_finding_ids: tuple[str, ...]
    limitations: tuple[str, ...]
    source_trust_verification_id: str | None = None
    trust_verified: bool = False
    report_only: Literal[True] = True
    policy_authority: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != EVIDENCE_RECONCILIATION_FORMAT:
            raise RuntimeAttestationError("reconciliation format is unsupported")
        if self.format_version != EVIDENCE_RECONCILIATION_FORMAT_VERSION:
            raise RuntimeAttestationError("reconciliation version is unsupported")
        _require_prefixed_id(
            self.reconciliation_id, "reconciliation ID", "reconciliation-sha256:"
        )
        for value, label in (
            (
                self.source_agent_snapshot_sha256,
                "reconciliation Agent Snapshot digest",
            ),
            (self.source_context_sha256, "reconciliation context digest"),
            (self.source_risk_report_sha256, "reconciliation risk digest"),
            (self.source_attestation_sha256, "reconciliation attestation digest"),
        ):
            _require_digest(value, label)
        if not isinstance(self.status, ReconciliationStatus):
            raise TypeError("reconciliation status is invalid")
        if not isinstance(self.runtime_verified, bool) or not isinstance(
            self.current_posture_eligible, bool
        ):
            raise TypeError("reconciliation verification flags must be bool")
        if not isinstance(self.evidence_confidence, EvidenceConfidence):
            raise TypeError("reconciliation confidence is invalid")
        if not isinstance(self.context_coverage_complete, bool):
            raise TypeError("reconciliation context coverage flag must be bool")
        _validate_sorted_unique(
            self.unknown_context_dimensions,
            "reconciliation unknown context dimensions",
        )
        if self.context_coverage_complete and self.unknown_context_dimensions:
            raise RuntimeAttestationError(
                "complete context coverage cannot contain unknown dimensions"
            )
        for values, label in (
            (self.matched_operation_ids, "matched operation IDs"),
            (self.declared_not_observed_operation_ids, "declared-not-observed IDs"),
            (self.observed_not_declared_operation_ids, "observed-not-declared IDs"),
            (self.reconciled_risk_finding_ids, "reconciled Finding IDs"),
            (self.unreconciled_risk_finding_ids, "unreconciled Finding IDs"),
        ):
            _validate_sorted_unique(values, label)
        if self.mismatches != tuple(
            sorted(self.mismatches, key=RuntimeContextMismatch.sort_key)
        ):
            raise RuntimeAttestationError("reconciliation mismatches must be sorted")
        _require_text_tuple(self.limitations, "reconciliation limitations")
        if self.source_trust_verification_id is not None:
            _require_prefixed_id(
                self.source_trust_verification_id,
                "reconciliation trust verification ID",
                "runtime-trust-verification-sha256:",
            )
        if not isinstance(self.trust_verified, bool):
            raise TypeError("reconciliation trust_verified must be bool")
        if self.trust_verified != self.runtime_verified:
            raise RuntimeAttestationError(
                "reconciliation trust_verified is inconsistent with runtime_verified"
            )
        matched = set(self.matched_operation_ids)
        declared_not_observed = set(self.declared_not_observed_operation_ids)
        if matched & declared_not_observed:
            raise RuntimeAttestationError(
                "matched and declared-not-observed operation IDs overlap"
            )
        reconciled_findings = set(self.reconciled_risk_finding_ids)
        unreconciled_findings = set(self.unreconciled_risk_finding_ids)
        if reconciled_findings & unreconciled_findings:
            raise RuntimeAttestationError(
                "reconciled and unreconciled Finding IDs overlap"
            )
        if self.current_posture_eligible and not self.runtime_verified:
            raise RuntimeAttestationError(
                "posture eligibility requires runtime verification"
            )
        expected_confidence = (
            EvidenceConfidence.A
            if self.current_posture_eligible
            else EvidenceConfidence.B
            if self.runtime_verified
            else EvidenceConfidence.D
        )
        if self.evidence_confidence is not expected_confidence:
            raise RuntimeAttestationError("reconciliation confidence is inconsistent")
        has_gap = bool(
            self.declared_not_observed_operation_ids
            or self.observed_not_declared_operation_ids
            or self.mismatches
            or self.unreconciled_risk_finding_ids
            or not self.context_coverage_complete
            or self.unknown_context_dimensions
        )
        if self.status is ReconciliationStatus.UNVERIFIED and self.runtime_verified:
            raise RuntimeAttestationError(
                "verified runtime evidence cannot have unverified status"
            )
        if self.status is ReconciliationStatus.RECONCILED and (
            not self.runtime_verified or has_gap or not self.current_posture_eligible
        ):
            raise RuntimeAttestationError(
                "reconciled status requires complete verified evidence"
            )
        if self.status is ReconciliationStatus.CONFLICT and not (
            self.mismatches or self.observed_not_declared_operation_ids
        ):
            raise RuntimeAttestationError(
                "conflict status requires an explicit runtime mismatch"
            )
        if self.status is ReconciliationStatus.PARTIAL and (
            not self.runtime_verified or not has_gap
        ):
            raise RuntimeAttestationError(
                "partial status requires verified evidence with an explicit gap"
            )
        if (
            self.report_only is not True
            or self.policy_authority is not False
            or self.ci_blocked is not False
        ):
            raise RuntimeAttestationError("reconciliation authority fields are invalid")
        expected = evidence_reconciliation_id(
            source_agent_snapshot_sha256=self.source_agent_snapshot_sha256,
            source_context_sha256=self.source_context_sha256,
            source_risk_report_sha256=self.source_risk_report_sha256,
            source_attestation_sha256=self.source_attestation_sha256,
            status=self.status,
            runtime_verified=self.runtime_verified,
            current_posture_eligible=self.current_posture_eligible,
            evidence_confidence=self.evidence_confidence,
            context_coverage_complete=self.context_coverage_complete,
            unknown_context_dimensions=self.unknown_context_dimensions,
            matched_operation_ids=self.matched_operation_ids,
            declared_not_observed_operation_ids=self.declared_not_observed_operation_ids,
            observed_not_declared_operation_ids=self.observed_not_declared_operation_ids,
            mismatches=self.mismatches,
            reconciled_risk_finding_ids=self.reconciled_risk_finding_ids,
            unreconciled_risk_finding_ids=self.unreconciled_risk_finding_ids,
            limitations=self.limitations,
            source_trust_verification_id=self.source_trust_verification_id,
            trust_verified=self.trust_verified,
        )
        if self.reconciliation_id != expected:
            raise RuntimeAttestationError("reconciliation ID is inconsistent")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "reconciliation_id": self.reconciliation_id,
            "source_agent_snapshot_sha256": self.source_agent_snapshot_sha256,
            "source_context_sha256": self.source_context_sha256,
            "source_risk_report_sha256": self.source_risk_report_sha256,
            "source_attestation_sha256": self.source_attestation_sha256,
            "status": self.status.value,
            "runtime_verified": self.runtime_verified,
            "current_posture_eligible": self.current_posture_eligible,
            "evidence_confidence": self.evidence_confidence.value,
            "context_coverage_complete": self.context_coverage_complete,
            "unknown_context_dimensions": list(self.unknown_context_dimensions),
            "matched_operation_ids": list(self.matched_operation_ids),
            "declared_not_observed_operation_ids": list(
                self.declared_not_observed_operation_ids
            ),
            "observed_not_declared_operation_ids": list(
                self.observed_not_declared_operation_ids
            ),
            "mismatches": [item.to_dict() for item in self.mismatches],
            "reconciled_risk_finding_ids": list(self.reconciled_risk_finding_ids),
            "unreconciled_risk_finding_ids": list(self.unreconciled_risk_finding_ids),
            "limitations": list(self.limitations),
            "source_trust_verification_id": self.source_trust_verification_id,
            "trust_verified": self.trust_verified,
            "report_only": self.report_only,
            "policy_authority": self.policy_authority,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "policy_authority": self.policy_authority,
                "ci_blocked": self.ci_blocked,
            },
        }


class DeterministicRuntimeEvidenceReconciler:
    """Reconcile external runtime observations without executing anything."""

    def reconcile(
        self,
        context_set: OperationContextSet,
        risk_report: ContextRiskReport,
        attestation: RuntimeAttestation,
        *,
        expected_agent_snapshot_sha256: str,
        trust_decision: RuntimeTrustDecision | None = None,
    ) -> EvidenceReconciliationReport:
        if not isinstance(context_set, OperationContextSet):
            raise TypeError("runtime reconciler requires OperationContextSet")
        if not isinstance(risk_report, ContextRiskReport):
            raise TypeError("runtime reconciler requires ContextRiskReport")
        if not isinstance(attestation, RuntimeAttestation):
            raise TypeError("runtime reconciler requires RuntimeAttestation")
        if trust_decision is not None and not isinstance(
            trust_decision, RuntimeTrustDecision
        ):
            raise TypeError("runtime reconciler trust decision is invalid")
        _require_digest(
            expected_agent_snapshot_sha256,
            "expected agent snapshot digest",
        )
        if attestation.agent_snapshot_sha256 != expected_agent_snapshot_sha256:
            raise RuntimeAttestationError(
                "runtime attestation is not bound to the expected Agent Snapshot"
            )
        context_digest = canonical_operation_context_sha256(context_set)
        if risk_report.source_context_sha256 != context_digest:
            raise RuntimeAttestationError(
                "RISK-04 report is not bound to Operation Context"
            )
        if attestation.context_sha256 != context_digest:
            raise RuntimeAttestationError(
                "runtime attestation is not bound to Operation Context"
            )
        attestation_digest = canonical_runtime_attestation_sha256(attestation)
        if trust_decision is not None and (
            trust_decision.source_attestation_sha256 != attestation_digest
        ):
            raise RuntimeAttestationError(
                "runtime trust decision is not bound to Runtime Attestation"
            )
        contexts = {item.operation_id: item for item in context_set.contexts}
        observations = tuple(item for item in attestation.observations if item.observed)
        by_operation: dict[str, list[RuntimeObservation]] = {}
        for observation in observations:
            by_operation.setdefault(observation.operation_id, []).append(observation)
        matched: set[str] = set()
        declared_not_observed: set[str] = set()
        observed_not_declared: set[str] = set()
        mismatches: list[RuntimeContextMismatch] = []
        for operation_id, runtime_observations in sorted(by_operation.items()):
            declared = contexts.get(operation_id)
            if declared is None:
                observed_not_declared.add(operation_id)
                continue
            for observation in runtime_observations:
                fields: list[str] = []
                if observation.action is not declared.action:
                    fields.append("action")
                if observation.target is not declared.target:
                    fields.append("target")
                if fields:
                    mismatches.append(
                        RuntimeContextMismatch(
                            operation_id=operation_id,
                            observation_id=observation.observation_id,
                            declared_action=declared.action,
                            observed_action=observation.action,
                            declared_target=declared.target,
                            observed_target=observation.target,
                            fields=tuple(fields),
                        )
                    )
                else:
                    matched.add(operation_id)
        for operation_id in contexts:
            if operation_id not in matched:
                declared_not_observed.add(operation_id)
        risk_finding_ids = {item.finding_id for item in risk_report.risk_findings}
        reconciled_risk = {
            item.finding_id
            for item in risk_report.risk_findings
            if set(item.context_ids).issubset(matched)
        }
        unreconciled_risk = risk_finding_ids - reconciled_risk
        coverage_complete = (
            context_set.coverage_complete and risk_report.coverage_complete
        )
        unknown_context_dimensions = tuple(
            sorted(
                set(context_set.unknown_dimensions)
                | set(risk_report.unknown_dimensions)
            )
        )
        runtime_verified = bool(
            attestation.verification_status is RuntimeVerificationStatus.VERIFIED
            and trust_decision is not None
            and trust_decision.trusted
        )
        if not runtime_verified:
            status = ReconciliationStatus.UNVERIFIED
        elif mismatches or observed_not_declared:
            status = ReconciliationStatus.CONFLICT
        elif (
            declared_not_observed
            or unreconciled_risk
            or not coverage_complete
            or unknown_context_dimensions
        ):
            status = ReconciliationStatus.PARTIAL
        else:
            status = ReconciliationStatus.RECONCILED
        eligible = runtime_verified and status is ReconciliationStatus.RECONCILED
        confidence = (
            EvidenceConfidence.A
            if eligible
            else EvidenceConfidence.B
            if runtime_verified
            else EvidenceConfidence.D
        )
        limitations = [
            (
                "Runtime observations are external evidence; AgentSec did not "
                "execute the target Agent."
            ),
            (
                "Runtime verification does not grant permission, authenticate "
                "identity, or prove exploitability."
            ),
        ]
        if trust_decision is None:
            limitations.append(
                "No trusted issuer decision was supplied; runtime evidence is"
                " treated as unverified."
            )
        elif not trust_decision.trusted:
            limitations.append(
                "Runtime Attestation trust verification failed; runtime evidence"
                " is treated as unverified."
            )
        if status is not ReconciliationStatus.RECONCILED:
            limitations.append(
                "The runtime evidence is not fully reconciled with every "
                "declared operation; current posture remains ineligible."
            )
        if not coverage_complete or unknown_context_dimensions:
            limitations.append(
                "Static Operation Context coverage is incomplete; unknown "
                "dimensions remain explicit and current posture is ineligible."
            )
        return EvidenceReconciliationReport(
            format=EVIDENCE_RECONCILIATION_FORMAT,
            format_version=EVIDENCE_RECONCILIATION_FORMAT_VERSION,
            reconciliation_id=evidence_reconciliation_id(
                source_agent_snapshot_sha256=attestation.agent_snapshot_sha256,
                source_context_sha256=context_digest,
                source_risk_report_sha256=canonical_context_risk_sha256(risk_report),
                source_attestation_sha256=attestation_digest,
                status=status,
                runtime_verified=runtime_verified,
                current_posture_eligible=eligible,
                evidence_confidence=confidence,
                context_coverage_complete=coverage_complete,
                unknown_context_dimensions=unknown_context_dimensions,
                matched_operation_ids=tuple(sorted(matched)),
                declared_not_observed_operation_ids=tuple(
                    sorted(declared_not_observed)
                ),
                observed_not_declared_operation_ids=tuple(
                    sorted(observed_not_declared)
                ),
                mismatches=tuple(
                    sorted(mismatches, key=RuntimeContextMismatch.sort_key)
                ),
                reconciled_risk_finding_ids=tuple(sorted(reconciled_risk)),
                unreconciled_risk_finding_ids=tuple(sorted(unreconciled_risk)),
                limitations=tuple(dict.fromkeys(limitations)),
                source_trust_verification_id=(
                    trust_decision.verification_id if trust_decision else None
                ),
                trust_verified=runtime_verified,
            ),
            source_agent_snapshot_sha256=attestation.agent_snapshot_sha256,
            source_context_sha256=context_digest,
            source_risk_report_sha256=canonical_context_risk_sha256(risk_report),
            source_attestation_sha256=attestation_digest,
            status=status,
            runtime_verified=runtime_verified,
            current_posture_eligible=eligible,
            evidence_confidence=confidence,
            context_coverage_complete=coverage_complete,
            unknown_context_dimensions=unknown_context_dimensions,
            matched_operation_ids=tuple(sorted(matched)),
            declared_not_observed_operation_ids=tuple(sorted(declared_not_observed)),
            observed_not_declared_operation_ids=tuple(sorted(observed_not_declared)),
            mismatches=tuple(sorted(mismatches, key=RuntimeContextMismatch.sort_key)),
            reconciled_risk_finding_ids=tuple(sorted(reconciled_risk)),
            unreconciled_risk_finding_ids=tuple(sorted(unreconciled_risk)),
            limitations=tuple(dict.fromkeys(limitations)),
            source_trust_verification_id=(
                trust_decision.verification_id if trust_decision else None
            ),
            trust_verified=runtime_verified,
        )


def build_runtime_observation(
    *,
    operation_id: str,
    action: OperationAction,
    target: OperationTarget,
    observed: bool,
    evidence_sha256: str,
    source_ref: str,
    observed_at: str,
) -> RuntimeObservation:
    return RuntimeObservation(
        observation_id=runtime_observation_id(
            operation_id=operation_id,
            action=action,
            target=target,
            observed=observed,
            evidence_sha256=evidence_sha256,
            source_ref=source_ref,
            observed_at=observed_at,
        ),
        operation_id=operation_id,
        action=action,
        target=target,
        observed=observed,
        evidence_sha256=evidence_sha256,
        source_ref=source_ref,
        observed_at=observed_at,
    )


def build_runtime_attestation(
    *,
    agent_snapshot_sha256: str,
    context_sha256: str,
    issuer: str,
    method: RuntimeAttestationMethod,
    verification_status: RuntimeVerificationStatus,
    observations: tuple[RuntimeObservation, ...],
    limitations: tuple[str, ...],
    key_id: str,
    signature_algorithm: RuntimeSignatureAlgorithm,
    issued_at: str,
    expires_at: str,
    nonce: str,
    signing_key: bytes | None = None,
    signature: str | None = None,
) -> RuntimeAttestation:
    confidence = EvidenceConfidence.D
    ordered_observations = tuple(sorted(observations, key=RuntimeObservation.sort_key))
    attestation_identifier = runtime_attestation_id(
        agent_snapshot_sha256=agent_snapshot_sha256,
        context_sha256=context_sha256,
        issuer=issuer,
        key_id=key_id,
        signature_algorithm=signature_algorithm,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        method=method,
        verification_status=verification_status,
        observations=ordered_observations,
        limitations=limitations,
        evidence_confidence=confidence,
    )
    unsigned = {
        "format": RUNTIME_ATTESTATION_FORMAT,
        "format_version": RUNTIME_ATTESTATION_FORMAT_VERSION,
        "attestation_id": attestation_identifier,
        "agent_snapshot_sha256": agent_snapshot_sha256,
        "context_sha256": context_sha256,
        "issuer": issuer,
        "key_id": key_id,
        "signature_algorithm": signature_algorithm.value,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
        "method": method.value,
        "verification_status": verification_status.value,
        "observations": [item.to_dict() for item in ordered_observations],
        "limitations": list(limitations),
        "evidence_confidence": confidence.value,
        "runtime_verified": False,
        "report_only": True,
        "policy_authority": False,
        "ci_blocked": False,
        "authority": {
            "report_only": True,
            "policy_authority": False,
            "ci_blocked": False,
        },
    }
    if signing_key is not None and signature is not None:
        raise RuntimeAttestationError(
            "provide either runtime signing_key or signature, not both"
        )
    if signing_key is not None:
        _require_runtime_key(signing_key)
        signature = hmac.new(
            signing_key,
            _canonical_bytes(unsigned),
            hashlib.sha256,
        ).hexdigest()
    if signature is None:
        raise RuntimeAttestationError(
            "runtime attestation requires signature or signing_key"
        )
    return RuntimeAttestation(
        format=RUNTIME_ATTESTATION_FORMAT,
        format_version=RUNTIME_ATTESTATION_FORMAT_VERSION,
        attestation_id=attestation_identifier,
        agent_snapshot_sha256=agent_snapshot_sha256,
        context_sha256=context_sha256,
        issuer=issuer,
        key_id=key_id,
        signature_algorithm=signature_algorithm,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        method=method,
        verification_status=verification_status,
        observations=ordered_observations,
        limitations=limitations,
        evidence_confidence=confidence,
        runtime_verified=False,
        signature=signature,
    )


def runtime_observation_id(
    *,
    operation_id: str,
    action: OperationAction,
    target: OperationTarget,
    observed: bool,
    evidence_sha256: str,
    source_ref: str,
    observed_at: str,
) -> str:
    payload = {
        "operation_id": operation_id,
        "action": action.value,
        "target": target.value,
        "observed": observed,
        "evidence_sha256": evidence_sha256,
        "source_ref": source_ref,
        "observed_at": observed_at,
    }
    return "runtime-observation-sha256:" + _digest_payload(payload)


def runtime_attestation_id(
    *,
    agent_snapshot_sha256: str,
    context_sha256: str,
    issuer: str,
    key_id: str,
    signature_algorithm: RuntimeSignatureAlgorithm,
    issued_at: str,
    expires_at: str,
    nonce: str,
    method: RuntimeAttestationMethod,
    verification_status: RuntimeVerificationStatus,
    observations: tuple[RuntimeObservation, ...],
    limitations: tuple[str, ...],
    evidence_confidence: EvidenceConfidence,
) -> str:
    payload = {
        "format": RUNTIME_ATTESTATION_FORMAT,
        "format_version": RUNTIME_ATTESTATION_FORMAT_VERSION,
        "agent_snapshot_sha256": agent_snapshot_sha256,
        "context_sha256": context_sha256,
        "issuer": issuer,
        "key_id": key_id,
        "signature_algorithm": signature_algorithm.value,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
        "method": method.value,
        "verification_status": verification_status.value,
        "observations": [item.to_dict() for item in observations],
        "limitations": list(limitations),
        "evidence_confidence": evidence_confidence.value,
        "runtime_verified": False,
        "report_only": True,
        "policy_authority": False,
        "ci_blocked": False,
        "authority": {
            "report_only": True,
            "policy_authority": False,
            "ci_blocked": False,
        },
    }
    return "runtime-attestation-sha256:" + _digest_payload(payload)


def evidence_reconciliation_id(**values: object) -> str:
    return "reconciliation-sha256:" + _digest_payload(values)


def runtime_trust_verification_id(**values: object) -> str:
    payload = {
        "format": RUNTIME_TRUST_VERIFICATION_FORMAT,
        "format_version": RUNTIME_TRUST_VERIFICATION_FORMAT_VERSION,
        **values,
        "report_only": True,
        "policy_authority": False,
        "ci_blocked": False,
    }
    return "runtime-trust-verification-sha256:" + _digest_payload(payload)


def canonical_runtime_attestation_sha256(attestation: RuntimeAttestation) -> str:
    if not isinstance(attestation, RuntimeAttestation):
        raise TypeError("runtime attestation is invalid")
    return _digest_payload(attestation.to_dict())


def runtime_attestation_signing_bytes(attestation: RuntimeAttestation) -> bytes:
    """Return canonical bytes covered by detached Runtime Attestation signature."""

    if not isinstance(attestation, RuntimeAttestation):
        raise TypeError("runtime attestation signing input is invalid")
    return _canonical_bytes(attestation.signing_dict())


def sign_runtime_attestation(
    attestation: RuntimeAttestation,
    key: bytes,
) -> RuntimeAttestation:
    """Return attestation signed with an in-memory HMAC key.

    The key is never serialized. This helper is for an approved external
    attestation producer or tests; AgentSec never obtains keys from scanned
    workspaces.
    """

    _require_runtime_key(key)
    signature = hmac.new(
        key,
        runtime_attestation_signing_bytes(attestation),
        hashlib.sha256,
    ).hexdigest()
    return replace(attestation, signature=signature)


def canonical_evidence_reconciliation_sha256(
    report: EvidenceReconciliationReport,
) -> str:
    if not isinstance(report, EvidenceReconciliationReport):
        raise TypeError("evidence reconciliation report is invalid")
    return _digest_payload(report.to_dict())


def encode_runtime_attestation_json(attestation: RuntimeAttestation) -> str:
    if not isinstance(attestation, RuntimeAttestation):
        raise TypeError("runtime attestation encoder requires RuntimeAttestation")
    return (
        json.dumps(attestation.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def decode_runtime_attestation_json(payload: str) -> RuntimeAttestation:
    if not isinstance(payload, str):
        raise TypeError("runtime attestation decoder requires text")
    if len(payload.encode("utf-8")) > _MAX_RUNTIME_ATTESTATION_BYTES:
        raise RuntimeAttestationError("runtime attestation exceeds size limit")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeAttestationError("runtime attestation JSON is invalid") from error
    if not isinstance(value, dict):
        raise RuntimeAttestationError("runtime attestation JSON must be an object")
    if value.get("format") != RUNTIME_ATTESTATION_FORMAT:
        raise RuntimeAttestationError("runtime attestation format is invalid")
    _require_exact_keys(
        value,
        {
            "format",
            "format_version",
            "attestation_id",
            "agent_snapshot_sha256",
            "context_sha256",
            "issuer",
            "key_id",
            "signature_algorithm",
            "issued_at",
            "expires_at",
            "nonce",
            "method",
            "verification_status",
            "observations",
            "limitations",
            "evidence_confidence",
            "runtime_verified",
            "signature",
            "report_only",
            "policy_authority",
            "ci_blocked",
            "authority",
        },
        "runtime attestation",
    )
    raw_observations = value.get("observations")
    if not isinstance(raw_observations, list) or any(
        not isinstance(item, dict) for item in raw_observations
    ):
        raise RuntimeAttestationError("runtime attestation observations are invalid")
    observations = tuple(
        RuntimeObservation(
            observation_id=_string(item, "observation_id"),
            operation_id=_string(item, "operation_id"),
            action=OperationAction(_string(item, "action")),
            target=OperationTarget(_string(item, "target")),
            observed=_bool(item, "observed"),
            evidence_sha256=_string(item, "evidence_sha256"),
            source_ref=_string(item, "source_ref"),
            observed_at=_string(item, "observed_at"),
        )
        for item in raw_observations
    )
    authority = value.get("authority")
    if (
        not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("policy_authority") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise RuntimeAttestationError("runtime attestation authority is invalid")
    if (
        _bool(value, "report_only") is not True
        or _bool(value, "policy_authority") is not False
        or _bool(value, "ci_blocked") is not False
    ):
        raise RuntimeAttestationError(
            "runtime attestation authority fields are invalid"
        )
    return RuntimeAttestation(
        format=RUNTIME_ATTESTATION_FORMAT,
        format_version=_string(value, "format_version"),
        attestation_id=_string(value, "attestation_id"),
        agent_snapshot_sha256=_string(value, "agent_snapshot_sha256"),
        context_sha256=_string(value, "context_sha256"),
        issuer=_string(value, "issuer"),
        key_id=_string(value, "key_id"),
        signature_algorithm=RuntimeSignatureAlgorithm(
            _string(value, "signature_algorithm")
        ),
        issued_at=_string(value, "issued_at"),
        expires_at=_string(value, "expires_at"),
        nonce=_string(value, "nonce"),
        method=RuntimeAttestationMethod(_string(value, "method")),
        verification_status=RuntimeVerificationStatus(
            _string(value, "verification_status")
        ),
        observations=observations,
        limitations=_string_tuple(value, "limitations"),
        evidence_confidence=EvidenceConfidence(_string(value, "evidence_confidence")),
        runtime_verified=_bool(value, "runtime_verified"),
        signature=_string(value, "signature"),
    )


def encode_evidence_reconciliation_json(report: EvidenceReconciliationReport) -> str:
    if not isinstance(report, EvidenceReconciliationReport):
        raise TypeError("reconciliation encoder requires EvidenceReconciliationReport")
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def decode_evidence_reconciliation_json(payload: str) -> EvidenceReconciliationReport:
    """Decode and validate a serialized reconciliation report."""

    if not isinstance(payload, str):
        raise TypeError("reconciliation decoder requires text")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeAttestationError("reconciliation JSON is invalid") from error
    if not isinstance(value, dict):
        raise RuntimeAttestationError("reconciliation JSON must be an object")
    if value.get("format") != EVIDENCE_RECONCILIATION_FORMAT:
        raise RuntimeAttestationError("reconciliation format is invalid")
    _require_exact_keys(
        value,
        {
            "format",
            "format_version",
            "reconciliation_id",
            "source_agent_snapshot_sha256",
            "source_context_sha256",
            "source_risk_report_sha256",
            "source_attestation_sha256",
            "source_trust_verification_id",
            "trust_verified",
            "status",
            "runtime_verified",
            "current_posture_eligible",
            "evidence_confidence",
            "context_coverage_complete",
            "unknown_context_dimensions",
            "matched_operation_ids",
            "declared_not_observed_operation_ids",
            "observed_not_declared_operation_ids",
            "mismatches",
            "reconciled_risk_finding_ids",
            "unreconciled_risk_finding_ids",
            "limitations",
            "report_only",
            "policy_authority",
            "ci_blocked",
            "authority",
        },
        "reconciliation",
    )
    authority = value.get("authority")
    if (
        not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("policy_authority") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise RuntimeAttestationError("reconciliation authority is invalid")
    if (
        _bool(value, "report_only") is not True
        or _bool(value, "policy_authority") is not False
        or _bool(value, "ci_blocked") is not False
    ):
        raise RuntimeAttestationError("reconciliation authority fields are invalid")

    def _string_tuple_field(name: str) -> tuple[str, ...]:
        values = _string_tuple(value, name)
        return values

    raw_mismatches = value.get("mismatches")
    if not isinstance(raw_mismatches, list) or any(
        not isinstance(item, dict) for item in raw_mismatches
    ):
        raise RuntimeAttestationError("reconciliation mismatches are invalid")
    try:
        mismatches = tuple(
            RuntimeContextMismatch(
                operation_id=_string(item, "operation_id"),
                observation_id=_string(item, "observation_id"),
                declared_action=OperationAction(_string(item, "declared_action")),
                observed_action=OperationAction(_string(item, "observed_action")),
                declared_target=OperationTarget(_string(item, "declared_target")),
                observed_target=OperationTarget(_string(item, "observed_target")),
                fields=_string_tuple(item, "fields"),
            )
            for item in raw_mismatches
        )
        return EvidenceReconciliationReport(
            format=EVIDENCE_RECONCILIATION_FORMAT,
            format_version=_string(value, "format_version"),
            reconciliation_id=_string(value, "reconciliation_id"),
            source_agent_snapshot_sha256=_string(value, "source_agent_snapshot_sha256"),
            source_context_sha256=_string(value, "source_context_sha256"),
            source_risk_report_sha256=_string(value, "source_risk_report_sha256"),
            source_attestation_sha256=_string(value, "source_attestation_sha256"),
            status=ReconciliationStatus(_string(value, "status")),
            runtime_verified=_bool(value, "runtime_verified"),
            current_posture_eligible=_bool(value, "current_posture_eligible"),
            evidence_confidence=EvidenceConfidence(
                _string(value, "evidence_confidence")
            ),
            context_coverage_complete=_bool(value, "context_coverage_complete"),
            unknown_context_dimensions=_string_tuple_field(
                "unknown_context_dimensions"
            ),
            matched_operation_ids=_string_tuple_field("matched_operation_ids"),
            declared_not_observed_operation_ids=_string_tuple_field(
                "declared_not_observed_operation_ids"
            ),
            observed_not_declared_operation_ids=_string_tuple_field(
                "observed_not_declared_operation_ids"
            ),
            mismatches=mismatches,
            reconciled_risk_finding_ids=_string_tuple_field(
                "reconciled_risk_finding_ids"
            ),
            unreconciled_risk_finding_ids=_string_tuple_field(
                "unreconciled_risk_finding_ids"
            ),
            limitations=_string_tuple_field("limitations"),
            source_trust_verification_id=(
                value.get("source_trust_verification_id")
                if value.get("source_trust_verification_id") is None
                or isinstance(value.get("source_trust_verification_id"), str)
                else (_ for _ in ()).throw(
                    RuntimeAttestationError(
                        "reconciliation trust verification ID is invalid"
                    )
                )
            ),
            trust_verified=_bool(value, "trust_verified"),
        )
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, RuntimeAttestationError):
            raise
        raise RuntimeAttestationError("reconciliation fields are invalid") from error


def export_runtime_attestation_json_schema(output_directory: Path) -> tuple[Path, Path]:
    if not isinstance(output_directory, Path):
        raise TypeError("runtime schema directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    attestation_path = output_directory / "runtime-attestation.schema.json"
    reconciliation_path = output_directory / "evidence-reconciliation.schema.json"
    observation_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "observation_id",
            "operation_id",
            "action",
            "target",
            "observed",
            "evidence_sha256",
            "source_ref",
            "observed_at",
        ],
        "properties": {
            "observation_id": {
                "type": "string",
                "pattern": "^runtime-observation-sha256:[0-9a-f]{64}$",
            },
            "operation_id": {"type": "string", "minLength": 1},
            "action": {"enum": [item.value for item in OperationAction]},
            "target": {"enum": [item.value for item in OperationTarget]},
            "observed": {"type": "boolean"},
            "evidence_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "source_ref": {
                "type": "string",
                "pattern": "^[A-Za-z][A-Za-z0-9._:-]{0,127}$",
            },
            "observed_at": {
                "type": "string",
                "pattern": ("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
            },
        },
    }
    authority = {
        "type": "object",
        "additionalProperties": False,
        "required": ["report_only", "policy_authority", "ci_blocked"],
        "properties": {
            "report_only": {"const": True},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
        },
    }
    attestation_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/runtime/runtime-attestation.schema.json",
        "title": "AgentSec Runtime Attestation",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "attestation_id",
            "agent_snapshot_sha256",
            "context_sha256",
            "issuer",
            "key_id",
            "signature_algorithm",
            "issued_at",
            "expires_at",
            "nonce",
            "method",
            "verification_status",
            "observations",
            "limitations",
            "evidence_confidence",
            "runtime_verified",
            "signature",
            "report_only",
            "policy_authority",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": RUNTIME_ATTESTATION_FORMAT},
            "format_version": {"const": RUNTIME_ATTESTATION_FORMAT_VERSION},
            "attestation_id": {
                "type": "string",
                "pattern": "^runtime-attestation-sha256:[0-9a-f]{64}$",
            },
            "agent_snapshot_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "context_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "issuer": {
                "type": "string",
                "pattern": "^[A-Za-z][A-Za-z0-9._:-]{0,127}$",
            },
            "key_id": {
                "type": "string",
                "pattern": "^[A-Za-z][A-Za-z0-9._:-]{0,127}$",
            },
            "signature_algorithm": {
                "enum": [item.value for item in RuntimeSignatureAlgorithm]
            },
            "issued_at": {
                "type": "string",
                "pattern": ("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
            },
            "expires_at": {
                "type": "string",
                "pattern": ("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
            },
            "nonce": {
                "type": "string",
                "pattern": "^[A-Za-z0-9._:-]{16,128}$",
            },
            "method": {"enum": [item.value for item in RuntimeAttestationMethod]},
            "verification_status": {
                "enum": [item.value for item in RuntimeVerificationStatus]
            },
            "observations": {
                "type": "array",
                "minItems": 1,
                "maxItems": _MAX_RUNTIME_OBSERVATIONS,
                "items": observation_schema,
            },
            "limitations": {
                "type": "array",
                "minItems": 1,
                "maxItems": _MAX_LIMITATIONS,
                "items": {"type": "string", "maxLength": _MAX_LIMITATION_LENGTH},
            },
            "evidence_confidence": {
                "enum": [item.value for item in EvidenceConfidence]
            },
            "runtime_verified": {"const": False},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "report_only": {"const": True},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
            "authority": authority,
        },
    }
    mismatch_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "operation_id",
            "observation_id",
            "declared_action",
            "observed_action",
            "declared_target",
            "observed_target",
            "fields",
        ],
        "properties": {
            "operation_id": {"type": "string"},
            "observation_id": {"type": "string"},
            "declared_action": {"type": "string"},
            "observed_action": {"type": "string"},
            "declared_target": {"type": "string"},
            "observed_target": {"type": "string"},
            "fields": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        },
    }
    reconciliation_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/runtime/evidence-reconciliation.schema.json",
        "title": "AgentSec Evidence Reconciliation Report",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "reconciliation_id",
            "source_agent_snapshot_sha256",
            "source_context_sha256",
            "source_risk_report_sha256",
            "source_attestation_sha256",
            "source_trust_verification_id",
            "trust_verified",
            "status",
            "runtime_verified",
            "current_posture_eligible",
            "evidence_confidence",
            "context_coverage_complete",
            "unknown_context_dimensions",
            "matched_operation_ids",
            "declared_not_observed_operation_ids",
            "observed_not_declared_operation_ids",
            "mismatches",
            "reconciled_risk_finding_ids",
            "unreconciled_risk_finding_ids",
            "limitations",
            "report_only",
            "policy_authority",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": EVIDENCE_RECONCILIATION_FORMAT},
            "format_version": {"const": EVIDENCE_RECONCILIATION_FORMAT_VERSION},
            "reconciliation_id": {
                "type": "string",
                "pattern": "^reconciliation-sha256:[0-9a-f]{64}$",
            },
            "source_agent_snapshot_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_context_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "source_risk_report_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_attestation_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_trust_verification_id": {
                "type": ["string", "null"],
                "pattern": "^runtime-trust-verification-sha256:[0-9a-f]{64}$",
            },
            "trust_verified": {"type": "boolean"},
            "status": {"enum": [item.value for item in ReconciliationStatus]},
            "runtime_verified": {"type": "boolean"},
            "current_posture_eligible": {"type": "boolean"},
            "evidence_confidence": {
                "enum": [item.value for item in EvidenceConfidence]
            },
            "context_coverage_complete": {"type": "boolean"},
            "unknown_context_dimensions": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "matched_operation_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "declared_not_observed_operation_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "observed_not_declared_operation_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "mismatches": {"type": "array", "items": mismatch_schema},
            "reconciled_risk_finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "unreconciled_risk_finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "limitations": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string"},
            },
            "report_only": {"const": True},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
            "authority": authority,
        },
    }
    attestation_path.write_text(
        json.dumps(attestation_schema, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    reconciliation_path.write_text(
        json.dumps(reconciliation_schema, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return attestation_path, reconciliation_path


def _digest_payload(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")


def _json_default(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, RuntimeObservation):
        return value.to_dict()
    if isinstance(value, RuntimeContextMismatch):
        return value.to_dict()
    return str(value)


def _require_stable_id(value: str, label: str) -> None:
    if not isinstance(value, str) or _STABLE_ID_PATTERN.fullmatch(value) is None:
        raise RuntimeAttestationError(f"{label} is invalid")


def _require_prefixed_id(value: str, label: str, prefix: str) -> None:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or not _SHA256_PATTERN.fullmatch(value[len(prefix) :])
    ):
        raise RuntimeAttestationError(f"{label} is invalid")


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise RuntimeAttestationError(f"{label} must be lowercase SHA-256")


def _require_hex_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or _HEX_PATTERN.fullmatch(value) is None:
        raise RuntimeAttestationError(f"{label} must be lowercase hexadecimal SHA-256")


def _parse_utc(value: str) -> datetime:
    if _UTC_TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise RuntimeAttestationError("timestamp must use UTC RFC3339 seconds")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _require_runtime_key(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) < _MIN_RUNTIME_KEY_BYTES:
        raise RuntimeAttestationError(
            f"runtime signing key must contain at least {_MIN_RUNTIME_KEY_BYTES} bytes"
        )


def _require_safe_text(value: str, label: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise RuntimeAttestationError(f"{label} is invalid")


def _require_text_tuple(values: tuple[str, ...], label: str) -> None:
    if (
        not isinstance(values, tuple)
        or not values
        or any(not isinstance(item, str) or not item.strip() for item in values)
        or len(values) != len(set(values))
    ):
        raise RuntimeAttestationError(f"{label} is invalid")


def _require_bounded_text_tuple(
    values: tuple[str, ...],
    label: str,
    *,
    maximum_items: int,
    maximum_length: int,
) -> None:
    _require_text_tuple(values, label)
    if len(values) > maximum_items or any(
        len(item) > maximum_length for item in values
    ):
        raise RuntimeAttestationError(f"{label} exceeds its limit")


def _require_value_minimized_text_tuple(values: tuple[str, ...], label: str) -> None:
    for value in values:
        _require_safe_text(value, label, _MAX_LIMITATION_LENGTH)
        if _SENSITIVE_TEXT_PATTERN.search(value) is not None:
            raise RuntimeAttestationError(f"{label} contains sensitive material")


def _validate_sorted_unique(values: tuple[str, ...], label: str) -> None:
    if values != tuple(sorted(set(values))):
        raise RuntimeAttestationError(f"{label} must be sorted and unique")


def _require_exact_keys(
    value: dict[str, object],
    expected: set[str],
    label: str,
) -> None:
    if set(value) != expected:
        raise RuntimeAttestationError(f"{label} fields are invalid")


def _string(value: dict[str, object], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str):
        raise RuntimeAttestationError(f"runtime attestation field {name} is invalid")
    return item


def _string_tuple(value: dict[str, object], name: str) -> tuple[str, ...]:
    item = value.get(name)
    if not isinstance(item, list) or any(not isinstance(entry, str) for entry in item):
        raise RuntimeAttestationError(f"runtime attestation field {name} is invalid")
    return tuple(item)


def _bool(value: dict[str, object], name: str) -> bool:
    item = value.get(name)
    if not isinstance(item, bool):
        raise RuntimeAttestationError(f"runtime attestation field {name} is invalid")
    return item


__all__ = [
    "EVIDENCE_RECONCILIATION_BASIS",
    "EVIDENCE_RECONCILIATION_FORMAT",
    "EVIDENCE_RECONCILIATION_FORMAT_VERSION",
    "EvidenceReconciliationReport",
    "ReconciliationStatus",
    "RUNTIME_ATTESTATION_BASIS",
    "RUNTIME_ATTESTATION_FORMAT",
    "RUNTIME_ATTESTATION_FORMAT_VERSION",
    "RUNTIME_REPLAY_STORE_FORMAT",
    "RUNTIME_REPLAY_STORE_FORMAT_VERSION",
    "RUNTIME_TRUST_REGISTRY_FORMAT",
    "RUNTIME_TRUST_REGISTRY_FORMAT_VERSION",
    "RUNTIME_TRUST_VERIFICATION_FORMAT",
    "RUNTIME_TRUST_VERIFICATION_FORMAT_VERSION",
    "RuntimeAttestation",
    "RuntimeAttestationError",
    "RuntimeAttestationMethod",
    "RuntimeContextMismatch",
    "RuntimeObservation",
    "RuntimeVerificationStatus",
    "DeterministicRuntimeEvidenceReconciler",
    "build_runtime_attestation",
    "build_runtime_observation",
    "canonical_evidence_reconciliation_sha256",
    "canonical_runtime_attestation_sha256",
    "decode_evidence_reconciliation_json",
    "decode_runtime_attestation_json",
    "evidence_reconciliation_id",
    "encode_evidence_reconciliation_json",
    "encode_runtime_attestation_json",
    "export_runtime_attestation_json_schema",
    "runtime_attestation_id",
    "runtime_observation_id",
    "runtime_trust_verification_id",
]
