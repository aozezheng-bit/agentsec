"""Tests for the RISK-01 Operation Context Contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.domain import EvidenceConfidence
from agentsec.risk import (
    AuthorizationContext,
    AuthorizationState,
    ControlEffectiveness,
    ControlState,
    DataClassification,
    DataRetention,
    DataScope,
    DataSharingScope,
    Frequency,
    OperationAction,
    OperationContext,
    OperationContextSet,
    OperationContextStatus,
    OperationEvidence,
    OperationEvidenceMethod,
    OperationPurpose,
    OperationReversibility,
    OperationScope,
    OperationTarget,
    OperationTrigger,
    build_operation_evidence,
    canonical_operation_context_sha256,
    export_operation_context_json_schema,
)

_HASH = "a" * 64


def _evidence(
    *,
    path: str = "AGENTS.md",
    line: int = 1,
    method: OperationEvidenceMethod = OperationEvidenceMethod.STATIC_DECLARATION,
) -> OperationEvidence:
    return build_operation_evidence(
        source_path=path,
        content_sha256=_HASH,
        start_line=line,
        end_line=line,
        field_path=None,
        extraction_method=method,
        confidence=EvidenceConfidence.D,
    )


def _context(
    *,
    operation_id: str = "operation-public-search",
    action: OperationAction = OperationAction.READ,
    target: OperationTarget = OperationTarget.PUBLIC_WEB,
    classification: DataClassification = DataClassification.PUBLIC,
    sharing: DataSharingScope = DataSharingScope.NONE,
    retention: DataRetention = DataRetention.EPHEMERAL,
    trigger: OperationTrigger = OperationTrigger.USER_REQUESTED,
    purpose: OperationPurpose = OperationPurpose.SEARCH,
    authorization: AuthorizationState = AuthorizationState.USER_CONFIRMED,
    status: OperationContextStatus = OperationContextStatus.COMPLETE,
    evidence: tuple[OperationEvidence, ...] | None = None,
) -> OperationContext:
    return OperationContext(
        operation_id=operation_id,
        action=action,
        target=target,
        data_scope=DataScope(
            classification=classification,
            sharing=sharing,
            retention=retention,
        ),
        trigger=trigger,
        purpose=purpose,
        authorization=AuthorizationContext(
            state=authorization,
            approval_required=authorization is AuthorizationState.APPROVAL_MISSING,
            approval_present=False,
        ),
        reversibility=OperationReversibility.REVERSIBLE,
        scope=OperationScope.SINGLE_ITEM,
        frequency=Frequency.ONE_TIME,
        controls=ControlEffectiveness(
            approval=ControlState.NOT_APPLICABLE,
            user_consent=ControlState.PRESENT,
            allowlist=ControlState.UNKNOWN,
            audit=ControlState.PRESENT,
            retention=ControlState.PRESENT,
            redaction=ControlState.UNKNOWN,
            rate_limit=ControlState.UNKNOWN,
        ),
        evidence=evidence or (_evidence(),),
        status=status,
    )


def test_public_web_search_is_a_complete_non_authorizing_context() -> None:
    context = _context()

    assert context.action is OperationAction.READ
    assert context.target is OperationTarget.PUBLIC_WEB
    assert context.data_scope.classification is DataClassification.PUBLIC
    assert context.status is OperationContextStatus.COMPLETE
    assert context.runtime_verified is False
    assert context.runtime_authority is False
    assert context.evidence[0].confidence is EvidenceConfidence.D


def test_controlled_non_sensitive_memory_is_representable() -> None:
    context = _context(
        operation_id="operation-store-preference",
        action=OperationAction.STORE,
        target=OperationTarget.USER_PROFILE,
        classification=DataClassification.USER_PREFERENCE,
        sharing=DataSharingScope.MAIN_SESSION,
        retention=DataRetention.BOUNDED,
        purpose=OperationPurpose.PERSISTENCE,
        trigger=OperationTrigger.USER_CONFIRMED,
    )

    assert context.data_scope.classification is DataClassification.USER_PREFERENCE
    assert context.data_scope.retention is DataRetention.BOUNDED
    assert context.authorization.state is AuthorizationState.USER_CONFIRMED


def test_scheduled_personal_mail_read_is_explicitly_described() -> None:
    context = _context(
        operation_id="operation-scheduled-mail-read",
        action=OperationAction.READ,
        target=OperationTarget.USER_MAILBOX,
        classification=DataClassification.PERSONAL,
        sharing=DataSharingScope.MAIN_SESSION,
        retention=DataRetention.SESSION,
        trigger=OperationTrigger.SCHEDULED,
        purpose=OperationPurpose.NOTIFICATION,
        authorization=AuthorizationState.APPROVAL_MISSING,
        status=OperationContextStatus.COMPLETE,
    ).model_copy(
        update={
            "authorization": AuthorizationContext(
                state=AuthorizationState.APPROVAL_MISSING,
                approval_required=True,
                approval_present=False,
            )
        }
    )

    assert context.trigger is OperationTrigger.SCHEDULED
    assert context.authorization.approval_required is True
    assert context.authorization.approval_present is False


def test_secret_external_send_context_is_supported_without_scoring_or_authority() -> (
    None
):
    context = _context(
        operation_id="operation-send-secret",
        action=OperationAction.SEND,
        target=OperationTarget.EXTERNAL_SERVICE,
        classification=DataClassification.SECRET,
        sharing=DataSharingScope.EXTERNAL,
        retention=DataRetention.EPHEMERAL,
        trigger=OperationTrigger.AUTONOMOUS,
        purpose=OperationPurpose.EXTERNAL_COMMUNICATION,
        authorization=AuthorizationState.APPROVAL_MISSING,
        status=OperationContextStatus.COMPLETE,
    ).model_copy(
        update={
            "authorization": AuthorizationContext(
                state=AuthorizationState.APPROVAL_MISSING,
                approval_required=True,
                approval_present=False,
            ),
            "reversibility": OperationReversibility.IRREVERSIBLE,
            "scope": OperationScope.EXTERNAL,
        }
    )

    assert context.data_scope.classification is DataClassification.SECRET
    assert context.authorization.state is AuthorizationState.APPROVAL_MISSING
    assert context.runtime_verified is False


def test_unknown_context_requires_needs_context_or_unknown_status() -> None:
    evidence = (_evidence(method=OperationEvidenceMethod.STATIC_DIFF),)
    unknown = OperationContext(
        operation_id="operation-unknown",
        action=OperationAction.READ,
        target=OperationTarget.UNKNOWN,
        data_scope=DataScope(
            classification=DataClassification.UNKNOWN,
            sharing=DataSharingScope.UNKNOWN,
            retention=DataRetention.UNKNOWN,
        ),
        trigger=OperationTrigger.UNKNOWN,
        purpose=OperationPurpose.UNKNOWN,
        authorization=AuthorizationContext(
            state=AuthorizationState.UNKNOWN,
            approval_required=None,
            approval_present=None,
        ),
        reversibility=OperationReversibility.UNKNOWN,
        scope=OperationScope.UNKNOWN,
        frequency=Frequency.UNKNOWN,
        controls=ControlEffectiveness(),
        evidence=evidence,
        status=OperationContextStatus.NEEDS_CONTEXT,
    )

    assert unknown.status is OperationContextStatus.NEEDS_CONTEXT
    with pytest.raises(
        ValidationError, match="complete context cannot contain unknown"
    ):
        _context(
            operation_id="operation-invalid-complete",
            target=OperationTarget.UNKNOWN,
            classification=DataClassification.UNKNOWN,
            trigger=OperationTrigger.UNKNOWN,
            purpose=OperationPurpose.UNKNOWN,
            authorization=AuthorizationState.UNKNOWN,
            status=OperationContextStatus.COMPLETE,
        )


def test_context_status_cannot_claim_needs_context_when_primary_fields_are_known() -> (
    None
):
    with pytest.raises(ValidationError, match="needs_context status requires"):
        _context(
            operation_id="operation-invalid-needs-context",
            status=OperationContextStatus.NEEDS_CONTEXT,
        )


def test_evidence_id_is_bound_to_safe_source_metadata() -> None:
    evidence = _evidence(path="docs/AGENTS.md", line=3)
    assert evidence.evidence_id.startswith("operation-evidence-sha256:")
    assert evidence.source_path == "docs/AGENTS.md"
    assert evidence.start_line == 3
    assert evidence.end_line == 3
    assert evidence.secret_values_included is False
    assert evidence.value_minimized is True

    tampered = evidence.model_copy(
        update={"evidence_id": "operation-evidence-sha256:" + "b" * 64}
    )
    with pytest.raises(ValidationError, match="Evidence ID is inconsistent"):
        OperationEvidence.model_validate(tampered.model_dump())


def test_evidence_rejects_unsafe_path_and_bad_line_range() -> None:
    with pytest.raises(ValueError, match="path must not traverse"):
        build_operation_evidence(
            source_path="../AGENTS.md",
            content_sha256=_HASH,
            extraction_method=OperationEvidenceMethod.STATIC_DECLARATION,
            confidence=EvidenceConfidence.D,
        )

    with pytest.raises(ValidationError, match="line range"):
        build_operation_evidence(
            source_path="AGENTS.md",
            content_sha256=_HASH,
            start_line=3,
            end_line=2,
            extraction_method=OperationEvidenceMethod.STATIC_DECLARATION,
            confidence=EvidenceConfidence.D,
        )


def test_authorization_and_control_invariants_are_strict() -> None:
    with pytest.raises(ValidationError, match="approval_present"):
        AuthorizationContext(
            state=AuthorizationState.NOT_REQUIRED,
            approval_required=False,
            approval_present=True,
        )

    with pytest.raises(ValidationError, match="APPROVAL_MISSING"):
        AuthorizationContext(
            state=AuthorizationState.APPROVAL_MISSING,
            approval_required=True,
            approval_present=True,
        )


def test_operation_context_set_is_sorted_deterministic_and_report_only() -> None:
    first = _context(operation_id="operation-a")
    second = _context(
        operation_id="operation-b",
        action=OperationAction.STORE,
        target=OperationTarget.USER_PROFILE,
        classification=DataClassification.USER_PREFERENCE,
        purpose=OperationPurpose.PERSISTENCE,
    )
    context_set = OperationContextSet(
        subject_id="agent-001",
        contexts=(first, second),
        coverage_complete=True,
        unknown_dimensions=(),
    )

    assert tuple(item.operation_id for item in context_set.contexts) == (
        "operation-a",
        "operation-b",
    )
    assert context_set.report_only is True
    assert context_set.runtime_verified is False
    assert context_set.runtime_authority is False
    assert canonical_operation_context_sha256(context_set) == (
        canonical_operation_context_sha256(context_set)
    )

    payload = context_set.model_dump(mode="json")
    assert payload["format"] == "agentsec-operation-context-set"
    assert payload["contexts"][0]["operation_id"] == "operation-a"


def test_operation_context_schema_export_is_versioned(tmp_path: Path) -> None:
    path = export_operation_context_json_schema(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path.name == "operation-context.schema.json"
    assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert payload["x-agentsec-operation-context-schema-version"] == "0.1.0"
    assert payload["properties"]["contexts"]["type"] == "array"
    assert hashlib.sha256(path.read_bytes()).hexdigest()
