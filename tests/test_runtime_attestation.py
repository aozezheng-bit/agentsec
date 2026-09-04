"""RISK-06 Runtime Attestation and Evidence Reconciliation tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agentsec.domain import EvidenceConfidence
from agentsec.risk import (
    AuthorizationContext,
    AuthorizationState,
    ControlEffectiveness,
    DataClassification,
    DataRetention,
    DataScope,
    DataSharingScope,
    DeterministicContextRuleEngine,
    DeterministicRuntimeEvidenceReconciler,
    Frequency,
    OperationAction,
    OperationContext,
    OperationContextSet,
    OperationContextStatus,
    OperationEvidenceMethod,
    OperationPurpose,
    OperationReversibility,
    OperationScope,
    OperationTarget,
    OperationTrigger,
    ReconciliationStatus,
    RuntimeAttestation,
    RuntimeAttestationError,
    RuntimeAttestationMethod,
    RuntimeObservation,
    RuntimeVerificationStatus,
    build_operation_evidence,
    build_runtime_attestation,
    build_runtime_observation,
    canonical_operation_context_sha256,
    decode_runtime_attestation_json,
    encode_runtime_attestation_json,
    export_runtime_attestation_json_schema,
)

_HASH = "a" * 64
_SNAPSHOT = "b" * 64


def _context(
    operation_id: str,
    *,
    action: OperationAction = OperationAction.READ,
    target: OperationTarget = OperationTarget.PUBLIC_WEB,
) -> OperationContext:
    evidence = build_operation_evidence(
        source_path=f"evidence/{operation_id.replace('.', '-')}.md",
        content_sha256=_HASH,
        extraction_method=OperationEvidenceMethod.STATIC_DECLARATION,
        confidence=EvidenceConfidence.B,
        start_line=1,
        end_line=1,
    )
    return OperationContext(
        operation_id=operation_id,
        action=action,
        target=target,
        data_scope=DataScope(
            classification=DataClassification.PUBLIC,
            sharing=DataSharingScope.NONE,
            retention=DataRetention.EPHEMERAL,
        ),
        trigger=OperationTrigger.USER_REQUESTED,
        purpose=(
            OperationPurpose.SEARCH
            if action is OperationAction.READ
            else OperationPurpose.EXTERNAL_COMMUNICATION
        ),
        authorization=AuthorizationContext(state=AuthorizationState.NOT_REQUIRED),
        reversibility=OperationReversibility.REVERSIBLE,
        scope=OperationScope.SINGLE_ITEM,
        frequency=Frequency.ONE_TIME,
        controls=ControlEffectiveness(),
        evidence=(evidence,),
        status=OperationContextStatus.COMPLETE,
    )


def _set(*contexts: OperationContext) -> OperationContextSet:
    return OperationContextSet(
        subject_id="runtime-test-agent",
        contexts=tuple(sorted(contexts, key=lambda item: item.operation_id)),
        coverage_complete=True,
        unknown_dimensions=(),
    )


def _observation(
    operation_id: str,
    *,
    action: OperationAction = OperationAction.READ,
    target: OperationTarget = OperationTarget.PUBLIC_WEB,
    observed: bool = True,
) -> RuntimeObservation:
    return build_runtime_observation(
        operation_id=operation_id,
        action=action,
        target=target,
        observed=observed,
        evidence_sha256=hashlib.sha256(
            f"evidence:{operation_id}:{action}:{target}:{observed}".encode()
        ).hexdigest(),
        source_ref="sandbox-event:001",
        observed_at="2026-09-04T00:00:00Z",
    )


def _attestation(
    context_set: OperationContextSet,
    observations: tuple[RuntimeObservation, ...],
    *,
    status: RuntimeVerificationStatus = RuntimeVerificationStatus.VERIFIED,
    snapshot: str = _SNAPSHOT,
) -> RuntimeAttestation:
    return build_runtime_attestation(
        agent_snapshot_sha256=snapshot,
        context_sha256=canonical_operation_context_sha256(context_set),
        issuer="external-sandbox",
        method=RuntimeAttestationMethod.RUNTIME_VERIFICATION,
        verification_status=status,
        observations=observations,
        limitations=("External sandbox supplied sanitized evidence.",),
    )


def test_observation_and_attestation_ids_are_deterministic_and_build_sorts() -> None:
    first = _observation("operation.b")
    second = _observation("operation.a")
    attestation = _attestation(
        _set(_context("operation.a"), _context("operation.b")),
        (first, second),
    )

    assert attestation.observations[0].operation_id == "operation.a"
    assert attestation.observations[1].operation_id == "operation.b"
    assert attestation.attestation_id.startswith("runtime-attestation-sha256:")
    assert attestation.evidence_confidence is EvidenceConfidence.A


def test_verified_attestation_reconciles_and_allows_confidence_a_only_as_evidence() -> (
    None
):
    context_set = _set(_context("operation.read"))
    risk_report = DeterministicContextRuleEngine().run(context_set)
    attestation = _attestation(context_set, (_observation("operation.read"),))

    report = DeterministicRuntimeEvidenceReconciler().reconcile(
        context_set,
        risk_report,
        attestation,
        expected_agent_snapshot_sha256=_SNAPSHOT,
    )

    assert report.status is ReconciliationStatus.RECONCILED
    assert report.runtime_verified is True
    assert report.current_posture_eligible is True
    assert report.evidence_confidence is EvidenceConfidence.A
    assert report.report_only is True
    assert report.policy_authority is False
    assert report.ci_blocked is False


def test_unverified_attestation_is_explicit_and_cannot_use_confidence_a() -> None:
    context_set = _set(_context("operation.read"))
    risk_report = DeterministicContextRuleEngine().run(context_set)
    attestation = _attestation(
        context_set,
        (_observation("operation.read"),),
        status=RuntimeVerificationStatus.UNVERIFIED,
    )

    report = DeterministicRuntimeEvidenceReconciler().reconcile(
        context_set,
        risk_report,
        attestation,
        expected_agent_snapshot_sha256=_SNAPSHOT,
    )

    assert report.status is ReconciliationStatus.UNVERIFIED
    assert report.current_posture_eligible is False
    assert report.evidence_confidence is EvidenceConfidence.D


def test_partial_coverage_and_observed_false_are_not_matches() -> None:
    context_set = _set(_context("operation.a"), _context("operation.b"))
    risk_report = DeterministicContextRuleEngine().run(context_set)
    attestation = _attestation(
        context_set,
        (_observation("operation.a", observed=False),),
    )

    report = DeterministicRuntimeEvidenceReconciler().reconcile(
        context_set,
        risk_report,
        attestation,
        expected_agent_snapshot_sha256=_SNAPSHOT,
    )

    assert report.status is ReconciliationStatus.PARTIAL
    assert report.matched_operation_ids == ()
    assert report.declared_not_observed_operation_ids == (
        "operation.a",
        "operation.b",
    )


def test_action_and_target_mismatch_are_conflicts() -> None:
    context_set = _set(
        _context(
            "operation.read",
            action=OperationAction.READ,
            target=OperationTarget.PUBLIC_WEB,
        )
    )
    risk_report = DeterministicContextRuleEngine().run(context_set)
    attestation = _attestation(
        context_set,
        (
            _observation(
                "operation.read",
                action=OperationAction.SEND,
                target=OperationTarget.EXTERNAL_SERVICE,
            ),
        ),
    )

    report = DeterministicRuntimeEvidenceReconciler().reconcile(
        context_set,
        risk_report,
        attestation,
        expected_agent_snapshot_sha256=_SNAPSHOT,
    )

    assert report.status is ReconciliationStatus.CONFLICT
    assert report.mismatches[0].fields == ("action", "target")
    assert report.observed_not_declared_operation_ids == ()


def test_observed_not_declared_operation_is_conflict() -> None:
    context_set = _set(_context("operation.declared"))
    risk_report = DeterministicContextRuleEngine().run(context_set)
    attestation = _attestation(
        context_set,
        (_observation("operation.undeclared"),),
    )

    report = DeterministicRuntimeEvidenceReconciler().reconcile(
        context_set,
        risk_report,
        attestation,
        expected_agent_snapshot_sha256=_SNAPSHOT,
    )

    assert report.status is ReconciliationStatus.CONFLICT
    assert report.observed_not_declared_operation_ids == ("operation.undeclared",)
    assert report.current_posture_eligible is False


def test_context_risk_and_snapshot_bindings_are_strict() -> None:
    context_set = _set(_context("operation.read"))
    risk_report = DeterministicContextRuleEngine().run(context_set)
    attestation = _attestation(context_set, (_observation("operation.read"),))

    with pytest.raises(RuntimeAttestationError, match="expected Agent Snapshot"):
        DeterministicRuntimeEvidenceReconciler().reconcile(
            context_set,
            risk_report,
            attestation,
            expected_agent_snapshot_sha256="c" * 64,
        )

    with pytest.raises(RuntimeAttestationError, match="Operation Context"):
        bad_attestation = _attestation(
            context_set,
            (_observation("operation.read"),),
            snapshot=_SNAPSHOT,
        )
        # Rebuild a validly self-consistent artifact with a different context hash.
        bad_attestation = build_runtime_attestation(
            agent_snapshot_sha256=_SNAPSHOT,
            context_sha256="d" * 64,
            issuer=bad_attestation.issuer,
            method=bad_attestation.method,
            verification_status=bad_attestation.verification_status,
            observations=bad_attestation.observations,
            limitations=bad_attestation.limitations,
        )
        DeterministicRuntimeEvidenceReconciler().reconcile(
            context_set,
            risk_report,
            bad_attestation,
            expected_agent_snapshot_sha256=_SNAPSHOT,
        )

    other_context = _set(_context("operation.other"))
    other_risk = DeterministicContextRuleEngine().run(other_context)
    with pytest.raises(RuntimeAttestationError, match="RISK-04"):
        DeterministicRuntimeEvidenceReconciler().reconcile(
            context_set,
            other_risk,
            attestation,
            expected_agent_snapshot_sha256=_SNAPSHOT,
        )


def test_decoder_rejects_format_and_authority_tampering_and_round_trips() -> None:
    context_set = _set(_context("operation.read"))
    attestation = _attestation(context_set, (_observation("operation.read"),))
    encoded = encode_runtime_attestation_json(attestation)
    decoded = decode_runtime_attestation_json(encoded)
    assert encode_runtime_attestation_json(decoded) == encoded

    malformed_format = json.loads(encoded)
    malformed_format["format"] = "other"
    with pytest.raises(RuntimeAttestationError, match="format"):
        decode_runtime_attestation_json(json.dumps(malformed_format))

    malformed_authority = json.loads(encoded)
    malformed_authority["authority"]["report_only"] = False
    with pytest.raises(RuntimeAttestationError, match="authority"):
        decode_runtime_attestation_json(json.dumps(malformed_authority))

    assert "secret" not in encoded.casefold()
    assert "credential" not in encoded.casefold()


def test_runtime_schema_export_is_self_contained(tmp_path: Path) -> None:
    attestation_path, reconciliation_path = export_runtime_attestation_json_schema(
        tmp_path
    )
    attestation_schema = json.loads(attestation_path.read_text(encoding="utf-8"))
    reconciliation_schema = json.loads(reconciliation_path.read_text(encoding="utf-8"))
    assert attestation_schema["properties"]["report_only"]["const"] is True
    assert reconciliation_schema["properties"]["policy_authority"]["const"] is False


def test_attestation_rejects_raw_url_and_secret_like_metadata() -> None:
    with pytest.raises(RuntimeAttestationError, match="source_ref"):
        build_runtime_observation(
            operation_id="operation.read",
            action=OperationAction.READ,
            target=OperationTarget.PUBLIC_WEB,
            observed=True,
            evidence_sha256=_HASH,
            source_ref="https://runtime.example/event/1",
            observed_at="2026-09-04T00:00:00Z",
        )

    context_set = _set(_context("operation.read"))
    with pytest.raises(RuntimeAttestationError, match="sensitive material"):
        build_runtime_attestation(
            agent_snapshot_sha256=_SNAPSHOT,
            context_sha256=canonical_operation_context_sha256(context_set),
            issuer="external-sandbox",
            method=RuntimeAttestationMethod.RUNTIME_VERIFICATION,
            verification_status=RuntimeVerificationStatus.VERIFIED,
            observations=(_observation("operation.read"),),
            limitations=("token=raw-sensitive-value",),
        )
