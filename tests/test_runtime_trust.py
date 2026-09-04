"""RISK-07 Runtime Attestation trust and replay controls."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
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
    DeterministicRuntimeTrustVerifier,
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
    RuntimeAttestation,
    RuntimeAttestationMethod,
    RuntimeIssuerStatus,
    RuntimeReplayStore,
    RuntimeReplayStoreError,
    RuntimeSignatureAlgorithm,
    RuntimeTrustRegistry,
    RuntimeTrustStatus,
    RuntimeVerificationStatus,
    TrustedRuntimeIssuer,
    build_operation_evidence,
    build_runtime_attestation,
    build_runtime_observation,
    build_runtime_trust_registry,
    canonical_operation_context_sha256,
    encode_runtime_trust_registry_json,
    encode_runtime_trust_verification_json,
    export_runtime_trust_json_schemas,
    sign_runtime_attestation,
)

_KEY = b"k" * 32
_NOW = datetime(2026, 9, 4, 0, 30, tzinfo=UTC)
_SNAPSHOT = "b" * 64


def _context(operation_id: str) -> OperationContext:
    evidence = build_operation_evidence(
        source_path=f"evidence/{operation_id}.md",
        content_sha256="a" * 64,
        extraction_method=OperationEvidenceMethod.STATIC_DECLARATION,
        confidence=EvidenceConfidence.B,
        start_line=1,
        end_line=1,
    )
    return OperationContext(
        operation_id=operation_id,
        action=OperationAction.READ,
        target=OperationTarget.PUBLIC_WEB,
        data_scope=DataScope(
            classification=DataClassification.PUBLIC,
            sharing=DataSharingScope.NONE,
            retention=DataRetention.EPHEMERAL,
        ),
        trigger=OperationTrigger.USER_REQUESTED,
        purpose=OperationPurpose.SEARCH,
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
        subject_id="runtime-trust-test-agent",
        contexts=tuple(sorted(contexts, key=lambda item: item.operation_id)),
        coverage_complete=True,
        unknown_dimensions=(),
    )


def _attestation(
    context_set: OperationContextSet,
    *,
    nonce: str = "nonce-00000000001",
    issued_at: str = "2026-09-04T00:00:00Z",
    expires_at: str = "2026-09-04T01:00:00Z",
    status: RuntimeVerificationStatus = RuntimeVerificationStatus.VERIFIED,
) -> RuntimeAttestation:
    observation = build_runtime_observation(
        operation_id="operation.read",
        action=OperationAction.READ,
        target=OperationTarget.PUBLIC_WEB,
        observed=True,
        evidence_sha256=hashlib.sha256(b"runtime-event").hexdigest(),
        source_ref="sandbox:event",
        observed_at="2026-09-04T00:00:00Z",
    )
    unsigned = build_runtime_attestation(
        agent_snapshot_sha256=_SNAPSHOT,
        context_sha256=canonical_operation_context_sha256(context_set),
        issuer="sandbox",
        key_id="key-1",
        signature_algorithm=RuntimeSignatureAlgorithm.HMAC_SHA256,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        method=RuntimeAttestationMethod.RUNTIME_VERIFICATION,
        verification_status=status,
        observations=(observation,),
        limitations=("sanitized external evidence",),
        signature="0" * 64,
    )
    return sign_runtime_attestation(unsigned, _KEY)


def _registry(
    *,
    env_var: str = "AGENTSEC_RUNTIME_TEST_KEY",
    status: RuntimeIssuerStatus = RuntimeIssuerStatus.ACTIVE,
) -> RuntimeTrustRegistry:
    return build_runtime_trust_registry(
        (
            TrustedRuntimeIssuer(
                issuer="sandbox",
                key_id="key-1",
                algorithm=RuntimeSignatureAlgorithm.HMAC_SHA256,
                secret_env_var=env_var,
                status=status,
            ),
        )
    )


def test_valid_signature_time_and_first_nonce_are_trusted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context_set = _set(_context("operation.read"))
    monkeypatch.setenv("AGENTSEC_RUNTIME_TEST_KEY", _KEY.decode())
    decision = DeterministicRuntimeTrustVerifier().verify(
        _attestation(context_set),
        _registry(),
        replay_store=RuntimeReplayStore(tmp_path / "replay.json"),
        now=_NOW,
    )
    assert decision.status is RuntimeTrustStatus.TRUSTED
    assert decision.trusted is True
    assert decision.signature_verified is True
    assert decision.time_valid is True
    assert decision.replay_detected is False
    assert decision.report_only is True


def test_signature_issuer_key_and_status_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context_set = _set(_context("operation.read"))
    monkeypatch.setenv("AGENTSEC_RUNTIME_TEST_KEY", _KEY.decode())
    attestation = _attestation(context_set)
    bad = sign_runtime_attestation(
        build_runtime_attestation(
            agent_snapshot_sha256=_SNAPSHOT,
            context_sha256=attestation.context_sha256,
            issuer="sandbox",
            key_id="key-1",
            signature_algorithm=RuntimeSignatureAlgorithm.HMAC_SHA256,
            issued_at=attestation.issued_at,
            expires_at=attestation.expires_at,
            nonce=attestation.nonce,
            method=attestation.method,
            verification_status=attestation.verification_status,
            observations=attestation.observations,
            limitations=attestation.limitations,
            signature="0" * 64,
        ),
        b"w" * 32,
    )
    assert (
        DeterministicRuntimeTrustVerifier().verify(bad, _registry(), now=_NOW).status
        is RuntimeTrustStatus.SIGNATURE_INVALID
    )
    unknown = build_runtime_trust_registry(
        (
            TrustedRuntimeIssuer(
                issuer="other",
                key_id="key-1",
                algorithm=RuntimeSignatureAlgorithm.HMAC_SHA256,
                secret_env_var="AGENTSEC_RUNTIME_TEST_KEY",
            ),
        )
    )
    assert (
        DeterministicRuntimeTrustVerifier()
        .verify(attestation, unknown, now=_NOW)
        .status
        is RuntimeTrustStatus.UNKNOWN_ISSUER
    )
    revoked = _registry(status=RuntimeIssuerStatus.REVOKED)
    assert (
        DeterministicRuntimeTrustVerifier()
        .verify(attestation, revoked, now=_NOW)
        .status
        is RuntimeTrustStatus.KEY_REVOKED
    )
    missing = _registry(env_var="MISSING_RUNTIME_KEY")
    assert (
        DeterministicRuntimeTrustVerifier()
        .verify(attestation, missing, now=_NOW)
        .status
        is RuntimeTrustStatus.KEY_UNAVAILABLE
    )


def test_time_and_declared_verification_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context_set = _set(_context("operation.read"))
    monkeypatch.setenv("AGENTSEC_RUNTIME_TEST_KEY", _KEY.decode())
    verifier = DeterministicRuntimeTrustVerifier()
    assert (
        verifier.verify(
            _attestation(
                context_set,
                issued_at="2026-09-04T02:00:00Z",
                expires_at="2026-09-04T03:00:00Z",
            ),
            _registry(),
            now=_NOW,
        ).status
        is RuntimeTrustStatus.NOT_YET_VALID
    )
    assert (
        verifier.verify(
            _attestation(context_set, expires_at="2026-09-04T00:00:01Z"),
            _registry(),
            now=_NOW,
        ).status
        is RuntimeTrustStatus.EXPIRED
    )
    assert (
        verifier.verify(
            _attestation(
                context_set,
                status=RuntimeVerificationStatus.UNVERIFIED,
            ),
            _registry(),
            now=_NOW,
        ).status
        is RuntimeTrustStatus.UNVERIFIED_ATTESTATION
    )


def test_nonce_replay_is_persisted_without_raw_nonce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context_set = _set(_context("operation.read"))
    monkeypatch.setenv("AGENTSEC_RUNTIME_TEST_KEY", _KEY.decode())
    store = RuntimeReplayStore(tmp_path / "replay.json")
    verifier = DeterministicRuntimeTrustVerifier()
    attestation = _attestation(context_set)
    assert verifier.verify(
        attestation, _registry(), replay_store=store, now=_NOW
    ).trusted
    replay = verifier.verify(attestation, _registry(), replay_store=store, now=_NOW)
    assert replay.status is RuntimeTrustStatus.REPLAYED
    payload = json.loads((tmp_path / "replay.json").read_text(encoding="utf-8"))
    encoded = json.dumps(payload, ensure_ascii=False)
    assert attestation.nonce not in encoded
    assert "secret" not in encoded.casefold()


def test_replay_store_rejects_symlink_and_bad_lock(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "replay.json"
    link.symlink_to(target)
    with pytest.raises(RuntimeReplayStoreError, match="symlink"):
        RuntimeReplayStore(link)
    store = RuntimeReplayStore(tmp_path / "safe.json")
    lock = tmp_path / ".safe.json.lock"
    lock.write_text("locked", encoding="utf-8")
    context_set = _set(_context("operation.read"))
    with pytest.raises(RuntimeReplayStoreError, match="locked"):
        store.check_and_record(_attestation(context_set), accepted_at=_NOW)


def test_registry_and_trust_report_are_value_minimized_and_round_trip() -> None:
    registry = _registry()
    encoded = encode_runtime_trust_registry_json(registry)
    assert _KEY.decode() not in encoded
    assert "AGENTSEC_RUNTIME_TEST_KEY" in encoded
    decoded = json.loads(
        encode_runtime_trust_verification_json(
            DeterministicRuntimeTrustVerifier().verify(
                _attestation(_set(_context("operation.read"))), None, now=_NOW
            )
        )
    )
    assert decoded["status"] == "missing"
    assert decoded["report_only"] is True


def test_trust_binding_controls_reconciliation_confidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context_set = _set(_context("operation.read"))
    risk_report = DeterministicContextRuleEngine().run(context_set)
    attestation = _attestation(context_set)
    monkeypatch.setenv("AGENTSEC_RUNTIME_TEST_KEY", _KEY.decode())
    decision = DeterministicRuntimeTrustVerifier().verify(
        attestation,
        _registry(),
        replay_store=RuntimeReplayStore(tmp_path / "replay.json"),
        now=_NOW,
    )
    report = DeterministicRuntimeEvidenceReconciler().reconcile(
        context_set,
        risk_report,
        attestation,
        expected_agent_snapshot_sha256=_SNAPSHOT,
        trust_decision=decision,
    )
    assert report.evidence_confidence is EvidenceConfidence.A
    assert report.trust_verified is True
    with pytest.raises(ValueError, match="inconsistent"):
        DeterministicRuntimeEvidenceReconciler().reconcile(
            context_set,
            risk_report,
            attestation,
            expected_agent_snapshot_sha256=_SNAPSHOT,
            trust_decision=decision.__class__(
                verification_id=decision.verification_id,
                source_attestation_sha256="c" * 64,
                trust_registry_sha256=decision.trust_registry_sha256,
                issuer=decision.issuer,
                key_id=decision.key_id,
                signature_algorithm=decision.signature_algorithm,
                status=decision.status,
                issuer_trusted=True,
                key_trusted=True,
                signature_verified=True,
                time_valid=True,
                replay_detected=False,
                evaluated_at=decision.evaluated_at,
                reason_codes=decision.reason_codes,
                key_fingerprint_sha256=decision.key_fingerprint_sha256,
            ),
        )


def test_runtime_trust_schema_export_writes_all_contracts(tmp_path: Path) -> None:
    paths = export_runtime_trust_json_schemas(tmp_path)
    assert {path.name for path in paths} == {
        "runtime-trust-registry.schema.json",
        "runtime-trust-verification.schema.json",
        "runtime-replay-store.schema.json",
    }
