"""Tests for RISK-04 context-aware deterministic rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.domain import EvidenceConfidence, FindingCategory, Severity
from agentsec.risk import (
    AuthorizationContext,
    AuthorizationState,
    ContextRiskFindingKind,
    ContextRuleId,
    ContextRuleMatch,
    ContextRuleMetadata,
    ControlEffectiveness,
    DataClassification,
    DataRetention,
    DataScope,
    DataSharingScope,
    DeterministicContextRuleEngine,
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
    decode_context_risk_json,
    encode_context_risk_json,
    export_context_risk_json_schema,
)

_HASH = "a" * 64


def _evidence(path: str, line: int = 1) -> OperationEvidence:
    return build_operation_evidence(
        source_path=path,
        content_sha256=_HASH,
        extraction_method=OperationEvidenceMethod.STATIC_DECLARATION,
        confidence=EvidenceConfidence.B,
        start_line=line,
        end_line=line,
    )


def _context(
    operation_id: str,
    *,
    action: OperationAction = OperationAction.READ,
    target: OperationTarget = OperationTarget.PUBLIC_WEB,
    classification: DataClassification = DataClassification.PUBLIC,
    sharing: DataSharingScope = DataSharingScope.NONE,
    retention: DataRetention = DataRetention.EPHEMERAL,
    trigger: OperationTrigger = OperationTrigger.USER_CONFIRMED,
    purpose: OperationPurpose = OperationPurpose.SEARCH,
    authorization: AuthorizationState = AuthorizationState.USER_CONFIRMED,
    controls: ControlEffectiveness | None = None,
    reversibility: OperationReversibility = OperationReversibility.REVERSIBLE,
    scope: OperationScope = OperationScope.SINGLE_ITEM,
    frequency: Frequency = Frequency.ONE_TIME,
    evidence_path: str | None = None,
    status: OperationContextStatus | None = None,
) -> OperationContext:
    if status is None:
        status = (
            OperationContextStatus.NEEDS_CONTEXT
            if authorization is AuthorizationState.UNKNOWN
            else OperationContextStatus.COMPLETE
        )
    if authorization is AuthorizationState.APPROVAL_MISSING:
        auth = AuthorizationContext(
            state=authorization,
            approval_required=True,
            approval_present=False,
        )
    elif authorization is AuthorizationState.USER_CONFIRMED:
        auth = AuthorizationContext(
            state=authorization,
            approval_required=True,
            approval_present=True,
        )
    else:
        auth = AuthorizationContext(state=authorization)
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
        authorization=auth,
        reversibility=reversibility,
        scope=scope,
        frequency=frequency,
        controls=controls or ControlEffectiveness(),
        evidence=(
            _evidence(evidence_path or f"evidence/{operation_id.replace('.', '-')}.md"),
        ),
        status=status,
    )


def _set(
    *contexts: OperationContext,
    complete: bool = True,
    unknown_dimensions: tuple[str, ...] = (),
) -> OperationContextSet:
    return OperationContextSet(
        subject_id="test-agent",
        contexts=tuple(sorted(contexts, key=lambda item: item.operation_id)),
        coverage_complete=complete,
        unknown_dimensions=unknown_dimensions,
    )


def test_public_web_read_of_public_data_does_not_trigger_risk() -> None:
    report = DeterministicContextRuleEngine().run(
        _set(
            _context(
                "operation.public-read",
                target=OperationTarget.PUBLIC_WEB,
                classification=DataClassification.PUBLIC,
            )
        )
    )

    assert report.risk_findings == ()
    assert report.coverage_findings == ()
    assert report.report_only is True
    assert report.runtime_verified is False
    assert report.policy_authority is False
    assert report.ci_blocked is False


def test_sensitive_external_transfer_is_reported_with_context_evidence() -> None:
    context = _context(
        "operation.send-secret",
        action=OperationAction.SEND,
        target=OperationTarget.EXTERNAL_SERVICE,
        classification=DataClassification.SECRET,
        sharing=DataSharingScope.EXTERNAL,
        purpose=OperationPurpose.EXTERNAL_COMMUNICATION,
        authorization=AuthorizationState.APPROVAL_MISSING,
        reversibility=OperationReversibility.IRREVERSIBLE,
        scope=OperationScope.EXTERNAL,
    )
    report = DeterministicContextRuleEngine().run(_set(context))

    matches = [
        finding
        for finding in report.risk_findings
        if finding.rule_id == ContextRuleId.SENSITIVE_EXTERNAL_TRANSFER
    ]
    assert len(matches) == 1
    assert matches[0].severity is Severity.CRITICAL
    assert matches[0].context_ids == (context.operation_id,)
    assert matches[0].evidence_ids == (context.evidence[0].evidence_id,)
    assert matches[0].confidence is EvidenceConfidence.B


def test_scheduled_sensitive_operation_is_reported_without_persona_risk() -> None:
    context = _context(
        "operation.scheduled-mail",
        action=OperationAction.READ,
        target=OperationTarget.USER_MAILBOX,
        classification=DataClassification.PERSONAL,
        sharing=DataSharingScope.MAIN_SESSION,
        retention=DataRetention.SESSION,
        trigger=OperationTrigger.SCHEDULED,
        purpose=OperationPurpose.NOTIFICATION,
        authorization=AuthorizationState.UNKNOWN,
    )
    report = DeterministicContextRuleEngine().run(
        _set(
            context,
            complete=False,
            unknown_dimensions=("operation.scheduled-mail.authorization.state",),
        )
    )

    assert any(
        finding.rule_id == ContextRuleId.AUTONOMOUS_SENSITIVE_OPERATION
        for finding in report.risk_findings
    )
    assert any(
        finding.kind is ContextRiskFindingKind.COVERAGE
        for finding in report.coverage_findings
    )


def test_control_file_without_authorization_matches_high_impact_and_specific_rule() -> (
    None
):
    context = _context(
        "operation.modify-agents",
        action=OperationAction.MODIFY_POLICY,
        target=OperationTarget.AGENT_CONTROL_FILE,
        classification=DataClassification.INTERNAL,
        purpose=OperationPurpose.CONTROL_FILE_UPDATE,
        authorization=AuthorizationState.APPROVAL_MISSING,
        scope=OperationScope.WORKSPACE,
    )
    report = DeterministicContextRuleEngine().run(_set(context))
    rule_ids = {finding.rule_id for finding in report.risk_findings}

    assert ContextRuleId.HIGH_IMPACT_WITHOUT_AUTHORIZATION in rule_ids
    assert ContextRuleId.CONTROL_FILE_WITHOUT_AUTHORIZATION in rule_ids
    by_rule = {finding.rule_id: finding for finding in report.risk_findings}
    assert by_rule[ContextRuleId.HIGH_IMPACT_WITHOUT_AUTHORIZATION].severity is (
        Severity.CRITICAL
    )
    assert by_rule[ContextRuleId.CONTROL_FILE_WITHOUT_AUTHORIZATION].severity is (
        Severity.HIGH
    )


def test_secret_read_and_external_send_form_a_cross_operation_chain() -> None:
    read = _context(
        "operation.read-secret",
        action=OperationAction.READ,
        target=OperationTarget.SECRET,
        classification=DataClassification.SECRET,
        sharing=DataSharingScope.NONE,
        purpose=OperationPurpose.ANALYSIS,
    )
    send = _context(
        "operation.send-external",
        action=OperationAction.SEND,
        target=OperationTarget.EXTERNAL_MESSAGE_CHANNEL,
        classification=DataClassification.UNKNOWN,
        sharing=DataSharingScope.EXTERNAL,
        purpose=OperationPurpose.EXTERNAL_COMMUNICATION,
        authorization=AuthorizationState.APPROVAL_MISSING,
        status=OperationContextStatus.NEEDS_CONTEXT,
    )
    report = DeterministicContextRuleEngine().run(
        _set(
            read,
            send,
            complete=False,
            unknown_dimensions=("operation.send-external.data_scope.classification",),
        )
    )

    chain = [
        finding
        for finding in report.risk_findings
        if finding.rule_id == ContextRuleId.SECRET_TO_EXTERNAL_CHAIN
    ]
    assert len(chain) == 1
    assert chain[0].context_ids == (read.operation_id, send.operation_id)
    assert chain[0].severity is Severity.CRITICAL


def test_indefinite_external_persistence_is_reported() -> None:
    context = _context(
        "operation.store-personal",
        action=OperationAction.STORE,
        target=OperationTarget.EXTERNAL_SERVICE,
        classification=DataClassification.PERSONAL,
        sharing=DataSharingScope.EXTERNAL,
        retention=DataRetention.INDEFINITE,
        purpose=OperationPurpose.PERSISTENCE,
    )
    report = DeterministicContextRuleEngine().run(_set(context))

    assert any(
        finding.rule_id == ContextRuleId.INDEFINITE_EXTERNAL_PERSISTENCE
        for finding in report.risk_findings
    )


def test_unknown_context_is_coverage_not_a_risk_finding() -> None:
    context = _context(
        "operation.unknown",
        target=OperationTarget.UNKNOWN,
        classification=DataClassification.UNKNOWN,
        trigger=OperationTrigger.UNKNOWN,
        purpose=OperationPurpose.UNKNOWN,
        authorization=AuthorizationState.UNKNOWN,
    )
    report = DeterministicContextRuleEngine().run(
        _set(
            context,
            complete=False,
            unknown_dimensions=(
                "operation.unknown.authorization.state",
                "operation.unknown.data_scope.classification",
                "operation.unknown.purpose",
                "operation.unknown.target",
                "operation.unknown.trigger",
            ),
        )
    )

    assert report.risk_findings == ()
    assert len(report.coverage_findings) == 1
    assert report.coverage_findings[0].severity is Severity.NONE
    assert report.coverage_findings[0].rule_id == ContextRuleId.CONTEXT_COVERAGE_GAP


def test_rule_output_and_finding_identity_are_deterministic() -> None:
    context_set = _set(
        _context(
            "operation.send-secret",
            action=OperationAction.SEND,
            target=OperationTarget.EXTERNAL_SERVICE,
            classification=DataClassification.SECRET,
            sharing=DataSharingScope.EXTERNAL,
            authorization=AuthorizationState.APPROVAL_MISSING,
            purpose=OperationPurpose.EXTERNAL_COMMUNICATION,
        )
    )
    first = DeterministicContextRuleEngine().run(context_set)
    second = DeterministicContextRuleEngine().run(context_set)

    assert first == second
    assert encode_context_risk_json(first) == encode_context_risk_json(second)
    assert first.findings[0].finding_id.startswith("context-risk-sha256:")


def test_failed_rule_is_isolated_as_coverage_and_cannot_grant_authority() -> None:
    class BrokenRule:
        metadata = ContextRuleMetadata(
            rule_id="CTX-RISK-999",
            title="Broken test rule",
            description="A test rule that fails closed.",
            category=FindingCategory.OTHER,
        )

        def evaluate(
            self, context_set: OperationContextSet
        ) -> tuple[ContextRuleMatch, ...]:
            raise RuntimeError("test failure")

    report = DeterministicContextRuleEngine(rules=(BrokenRule(),)).run(
        _set(_context("operation.read"))
    )

    assert report.risk_findings == ()
    assert len(report.coverage_findings) == 1
    assert report.coverage_findings[0].rationale_code == "rule_evaluation_failed"
    assert report.report_only is True
    assert report.runtime_verified is False
    assert report.policy_authority is False
    assert report.ci_blocked is False


def test_empty_rule_registry_is_rejected() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        DeterministicContextRuleEngine(rules=())


def test_json_output_is_value_minimized_and_schema_is_exportable(
    tmp_path: Path,
) -> None:
    report = DeterministicContextRuleEngine().run(
        _set(
            _context(
                "operation.send-secret",
                action=OperationAction.SEND,
                target=OperationTarget.EXTERNAL_SERVICE,
                classification=DataClassification.SECRET,
                sharing=DataSharingScope.EXTERNAL,
                authorization=AuthorizationState.APPROVAL_MISSING,
                purpose=OperationPurpose.EXTERNAL_COMMUNICATION,
            )
        )
    )
    payload = json.loads(encode_context_risk_json(report))
    schema_path = export_context_risk_json_schema(tmp_path)

    assert schema_path.name == "context-risk-report.schema.json"
    assert payload["findings"][0]["evidence_ids"]
    encoded = json.dumps(payload)
    assert "source_text" not in encoded
    assert "raw_secret_value" not in encoded
    assert decode_context_risk_json(encode_context_risk_json(report)) == report
    payload["authority"]["ci_blocked"] = True
    with pytest.raises(ValueError, match="authority"):
        decode_context_risk_json(json.dumps(payload))
