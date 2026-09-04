"""Tests for RISK-05 context residual-risk and drift scoring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.domain import EvidenceConfidence, Severity
from agentsec.risk import (
    AuthorizationContext,
    AuthorizationState,
    ContextPosture,
    ContextRiskReport,
    ContextRiskScoreError,
    ContextRiskScoreReport,
    ControlEffectiveness,
    ControlState,
    DataClassification,
    DataRetention,
    DataScope,
    DataSharingScope,
    DeterministicContextRiskScoreEngine,
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
    RiskDriftDirection,
    build_operation_evidence,
    encode_context_risk_score_json,
    export_context_risk_score_json_schema,
)
from agentsec.risk.context_rules import DeterministicContextRuleEngine

_HASH = "a" * 64


def _context(
    operation_id: str,
    *,
    action: OperationAction = OperationAction.READ,
    target: OperationTarget = OperationTarget.PUBLIC_WEB,
    classification: DataClassification = DataClassification.PUBLIC,
    sharing: DataSharingScope = DataSharingScope.NONE,
    retention: DataRetention = DataRetention.EPHEMERAL,
    authorization: AuthorizationState = AuthorizationState.USER_CONFIRMED,
    controls: ControlEffectiveness | None = None,
) -> OperationContext:
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
            classification=classification,
            sharing=sharing,
            retention=retention,
        ),
        trigger=OperationTrigger.USER_CONFIRMED,
        purpose=OperationPurpose.EXTERNAL_COMMUNICATION
        if action is OperationAction.SEND
        else OperationPurpose.SEARCH,
        authorization=auth,
        reversibility=OperationReversibility.REVERSIBLE,
        scope=OperationScope.EXTERNAL
        if target is OperationTarget.EXTERNAL_SERVICE
        else OperationScope.SINGLE_ITEM,
        frequency=Frequency.ONE_TIME,
        controls=controls or ControlEffectiveness(),
        evidence=(evidence,),
        status=OperationContextStatus.COMPLETE,
    )


def _reports(
    context_set: OperationContextSet,
) -> tuple[ContextRiskReport, ContextRiskScoreReport]:
    risk_report = DeterministicContextRuleEngine().run(context_set)
    score_report = DeterministicContextRiskScoreEngine().run(context_set, risk_report)
    return risk_report, score_report


def _set(*contexts: OperationContext, complete: bool = True) -> OperationContextSet:
    return OperationContextSet(
        subject_id="risk-score-test",
        contexts=tuple(sorted(contexts, key=lambda item: item.operation_id)),
        coverage_complete=complete,
        unknown_dimensions=() if complete else ("risk-score-test.coverage",),
    )


def test_public_read_has_zero_context_risk_and_no_current_posture_claim() -> None:
    _, report = _reports(_set(_context("operation.public-read")))

    assert report.potential_impact_score == 0.0
    assert report.residual_risk_score == 0.0
    assert report.residual_risk_level is Severity.NONE
    assert report.current_posture is ContextPosture.NOT_ESTABLISHED
    assert report.current_posture_score is None
    assert report.drift_score is None


def test_residual_score_uses_explicit_controls_without_diluting_potential_impact() -> (
    None
):
    unmitigated = _context(
        "operation.send-secret",
        action=OperationAction.SEND,
        target=OperationTarget.EXTERNAL_SERVICE,
        classification=DataClassification.SECRET,
        sharing=DataSharingScope.EXTERNAL,
        authorization=AuthorizationState.APPROVAL_MISSING,
    )
    _, unmitigated_report = _reports(_set(unmitigated))
    assert unmitigated_report.potential_impact_score == 9.5
    assert unmitigated_report.residual_risk_score == 9.5

    controlled = unmitigated.model_copy(
        update={
            "authorization": AuthorizationContext(
                state=AuthorizationState.USER_CONFIRMED,
                approval_required=True,
                approval_present=True,
            ),
            "controls": ControlEffectiveness(
                approval=ControlState.PRESENT,
                user_consent=ControlState.PRESENT,
                audit=ControlState.PRESENT,
                redaction=ControlState.PRESENT,
                retention=ControlState.PRESENT,
            ),
        }
    )
    _, controlled_report = _reports(_set(controlled))
    assert controlled_report.potential_impact_score == 8.0
    assert controlled_report.residual_risk_score == 5.6
    assert controlled_report.contributions[0].control_coverage.value == "strong"
    assert (
        controlled_report.residual_risk_score < controlled_report.potential_impact_score
    )


def test_incomplete_context_is_provisional_not_automatically_high_risk() -> None:
    context = _context("operation.public-read")
    _, report = _reports(_set(context, complete=False))

    assert report.coverage_complete is False
    assert report.potential_impact_score == 0.0
    assert report.residual_risk_score == 0.0
    assert any("provisional" in item for item in report.limitations)


def test_risk_drift_is_computed_only_against_an_explicit_baseline() -> None:
    baseline_context = _context("operation.baseline")
    current_context = _context(
        "operation.send-secret",
        action=OperationAction.SEND,
        target=OperationTarget.EXTERNAL_SERVICE,
        classification=DataClassification.SECRET,
        sharing=DataSharingScope.EXTERNAL,
        authorization=AuthorizationState.APPROVAL_MISSING,
    )
    baseline_set = _set(baseline_context)
    current_set = _set(current_context)
    baseline_risk, _ = _reports(baseline_set)
    current_risk, current_score = (
        DeterministicContextRiskScoreEngine().run(
            current_set,
            DeterministicContextRuleEngine().run(current_set),
            baseline=(baseline_set, baseline_risk),
        ),
        None,
    )

    assert current_risk.drift is not None
    assert current_risk.drift.direction is RiskDriftDirection.INCREASED
    assert current_risk.drift.drift_score > 0.0
    assert current_risk.drift.added_finding_ids
    assert current_risk.drift.added_context_ids == ("operation.send-secret",)
    assert current_score is None


def test_resolved_context_risk_is_marked_decreased() -> None:
    baseline_context = _context(
        "operation.shared-secret",
        action=OperationAction.SEND,
        target=OperationTarget.EXTERNAL_SERVICE,
        classification=DataClassification.SECRET,
        sharing=DataSharingScope.EXTERNAL,
        authorization=AuthorizationState.APPROVAL_MISSING,
    )
    current_context = _context("operation.shared-secret")
    baseline_set = _set(baseline_context)
    current_set = _set(current_context)
    baseline_risk = DeterministicContextRuleEngine().run(baseline_set)
    current_risk = DeterministicContextRuleEngine().run(current_set)
    report = DeterministicContextRiskScoreEngine().run(
        current_set,
        current_risk,
        baseline=(baseline_set, baseline_risk),
    )

    assert report.drift is not None
    assert report.drift.direction is RiskDriftDirection.DECREASED
    assert report.drift.drift_score == 0.0
    assert report.drift.resolved_finding_ids
    assert report.drift.modified_context_ids == ("operation.shared-secret",)


def test_context_score_binding_and_authority_are_strict() -> None:
    context_set = _set(_context("operation.public-read"))
    risk_report = DeterministicContextRuleEngine().run(context_set)
    changed = context_set.model_copy(update={"subject_id": "another-agent"})

    with pytest.raises(ContextRiskScoreError, match="not bound"):
        DeterministicContextRiskScoreEngine().run(changed, risk_report)

    report = DeterministicContextRiskScoreEngine().run(context_set, risk_report)
    payload = json.loads(encode_context_risk_score_json(report))
    assert payload["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "policy_authority": False,
        "ci_blocked": False,
    }
    assert payload["current_posture_score"] is None


def test_context_score_schema_is_exportable(tmp_path: Path) -> None:
    path = export_context_risk_score_json_schema(tmp_path)
    assert path.name == "context-risk-score.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert schema["properties"]["residual_risk_score"]["maximum"] == 10
