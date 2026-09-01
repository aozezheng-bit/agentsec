"""P3-AG-08 Attack Path Evidence calibration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.attack_graph import (
    ATTACK_PATH_EVIDENCE_ASSOCIATION_LIMITATIONS,
    AttackGraphSourceRef,
    AttackPathAssociationBasis,
    AttackPathAssociationRelation,
    AttackPathCalibrationCase,
    AttackPathCalibrationCaseFamily,
    AttackPathCalibrationClassification,
    AttackPathEvidenceAssociation,
    AttackPathEvidenceAssociationReport,
    AttackPathEvidenceCalibrationRunner,
    AttackPathFindingEvidenceRef,
    AttackPathGraphEvidenceRef,
    AttackPathSemanticEvidenceRef,
    canonical_attack_path_evidence_association_sha256,
    encode_attack_path_calibration_json,
    export_attack_path_calibration_json_schema,
)
from agentsec.domain import EvidenceSource

_HASH = "a" * 64


def _source() -> AttackGraphSourceRef:
    return AttackGraphSourceRef(
        asset_path="AGENTS.md",
        asset_sha256=_HASH,
        start_line=4,
        end_line=4,
    )


def _graph_ref() -> AttackPathGraphEvidenceRef:
    return AttackPathGraphEvidenceRef(source=_source(), roles=("edge",))


def _report() -> AttackPathEvidenceAssociationReport:
    graph_ref = _graph_ref()
    finding_ref = AttackPathFindingEvidenceRef(
        source_type=EvidenceSource.FILE,
        asset_path="AGENTS.md",
        content_sha256=_HASH,
        start_line=4,
        end_line=4,
    )
    semantic_ref = AttackPathSemanticEvidenceRef(
        evidence_id="semantic-evidence-sha256:" + "b" * 64,
        asset_path="AGENTS.md",
        asset_sha256=_HASH,
        start_line=3,
        end_line=5,
    )
    associations = (
        AttackPathEvidenceAssociation(
            path_id="attack-path-sha256:" + "1" * 64,
            target_kind="finding",
            finding_id="finding-001",
            relation=AttackPathAssociationRelation.DUPLICATES,
            basis=(
                AttackPathAssociationBasis.ASSET_PATH,
                AttackPathAssociationBasis.ASSET_SHA256,
                AttackPathAssociationBasis.EXACT_LOCATOR,
                AttackPathAssociationBasis.GRAPH_EDGE_SOURCE,
                AttackPathAssociationBasis.LINE_OVERLAP,
            ),
            evidence_refs=(graph_ref,),
            finding_evidence_refs=(finding_ref,),
        ),
        AttackPathEvidenceAssociation(
            path_id="attack-path-sha256:" + "2" * 64,
            target_kind="finding",
            relation=AttackPathAssociationRelation.UNMATCHED,
            basis=(AttackPathAssociationBasis.GRAPH_SOURCE_UNAVAILABLE,),
            evidence_refs=(),
        ),
        AttackPathEvidenceAssociation(
            path_id="attack-path-sha256:" + "3" * 64,
            target_kind="semantic_candidate",
            semantic_candidate_id="semantic-candidate-sha256:" + "c" * 64,
            relation=AttackPathAssociationRelation.PARTIALLY_SUPPORTS,
            basis=(
                AttackPathAssociationBasis.ASSET_PATH,
                AttackPathAssociationBasis.ASSET_SHA256,
                AttackPathAssociationBasis.GRAPH_EDGE_SOURCE,
                AttackPathAssociationBasis.LINE_OVERLAP,
                AttackPathAssociationBasis.PARTIAL_EVIDENCE_OVERLAP,
            ),
            evidence_refs=(graph_ref,),
            semantic_evidence_refs=(semantic_ref,),
        ),
    )
    return AttackPathEvidenceAssociationReport(
        graph_sha256="d" * 64,
        path_report_sha256="e" * 64,
        findings_sha256="f" * 64,
        path_count=3,
        finding_count=1,
        semantic_candidate_count=1,
        associations=associations,
        association_count=3,
        limitations=ATTACK_PATH_EVIDENCE_ASSOCIATION_LIMITATIONS,
    )


def _cases(
    report: AttackPathEvidenceAssociationReport,
) -> tuple[AttackPathCalibrationCase, ...]:
    digest = canonical_attack_path_evidence_association_sha256(report)
    return (
        AttackPathCalibrationCase(
            case_id="attack-cal-exact",
            association_report_sha256=digest,
            path_id="attack-path-sha256:" + "1" * 64,
            target_kind="finding",
            target_id="finding-001",
            expected_relation=AttackPathAssociationRelation.DUPLICATES,
            family=AttackPathCalibrationCaseFamily.EXACT_MATCH,
            reviewer_id="reviewer-a",
            rationale_code="locator_exact",
        ),
        AttackPathCalibrationCase(
            case_id="attack-cal-no-source",
            association_report_sha256=digest,
            path_id="attack-path-sha256:" + "2" * 64,
            target_kind="finding",
            expected_relation=AttackPathAssociationRelation.UNMATCHED,
            family=AttackPathCalibrationCaseFamily.NO_SOURCE,
            reviewer_id="reviewer-b",
            rationale_code="source_missing",
        ),
        AttackPathCalibrationCase(
            case_id="attack-cal-partial",
            association_report_sha256=digest,
            path_id="attack-path-sha256:" + "3" * 64,
            target_kind="semantic_candidate",
            target_id="semantic-candidate-sha256:" + "c" * 64,
            expected_relation=AttackPathAssociationRelation.PARTIALLY_SUPPORTS,
            family=AttackPathCalibrationCaseFamily.PARTIAL_MATCH,
            reviewer_id="reviewer-a",
            rationale_code="partial_overlap",
        ),
    )


def test_calibration_reports_multiclass_accuracy_and_unreviewed_count() -> None:
    report = _report()
    calibration = AttackPathEvidenceCalibrationRunner().run(report, _cases(report))

    assert calibration.reviewed_case_count == 3
    assert calibration.unreviewed_association_count == 0
    assert calibration.reviewer_count == 2
    assert calibration.metrics.accuracy == 1.0
    assert calibration.metrics.correct_count == 3
    assert calibration.metrics.incorrect_count == 0
    assert calibration.metrics.macro_f1 == 1.0
    assert calibration.report_only is True
    assert calibration.blocks is False
    assert calibration.finding_authority is False
    assert calibration.semantic_authority is False


def test_calibration_exposes_incorrect_label_without_promoting_it() -> None:
    report = _report()
    cases = list(_cases(report))
    cases[0] = cases[0].model_copy(
        update={"expected_relation": AttackPathAssociationRelation.SUPPORTS}
    )
    calibration = AttackPathEvidenceCalibrationRunner().run(report, tuple(cases))

    row = calibration.cases[0]
    assert row.classification is AttackPathCalibrationClassification.INCORRECT
    assert row.observed_relation is AttackPathAssociationRelation.DUPLICATES
    assert calibration.metrics.accuracy == 0.666667
    assert calibration.metrics.incorrect_count == 1


def test_calibration_requires_report_digest_and_unique_case_keys() -> None:
    report = _report()
    cases = _cases(report)
    wrong_digest = cases[0].model_copy(update={"association_report_sha256": "0" * 64})
    with pytest.raises(ValueError, match="different association report"):
        AttackPathEvidenceCalibrationRunner().run(report, (wrong_digest, *cases[1:]))
    with pytest.raises(ValueError, match="sorted and unique"):
        AttackPathEvidenceCalibrationRunner().run(report, (cases[0], cases[0]))


def test_calibration_missing_row_is_incorrect_and_schema_round_trips(
    tmp_path: Path,
) -> None:
    report = _report()
    digest = canonical_attack_path_evidence_association_sha256(report)
    missing = AttackPathCalibrationCase(
        case_id="attack-cal-missing",
        association_report_sha256=digest,
        path_id="attack-path-sha256:" + "4" * 64,
        target_kind="finding",
        target_id="finding-404",
        expected_relation=AttackPathAssociationRelation.DUPLICATES,
        family=AttackPathCalibrationCaseFamily.PATH_MISMATCH,
        reviewer_id="reviewer-a",
        rationale_code="not_in_report",
    )
    calibration = AttackPathEvidenceCalibrationRunner().run(report, (missing,))
    assert calibration.cases[0].observed_relation == "missing"
    assert calibration.metrics.accuracy == 0.0
    payload = json.loads(encode_attack_path_calibration_json(calibration))
    assert calibration.__class__.model_validate(payload) == calibration
    schema_path = export_attack_path_calibration_json_schema(
        tmp_path / "attack-path-calibration.schema.json"
    )
    assert json.loads(schema_path.read_text(encoding="utf-8"))["title"] == (
        "AttackPathEvidenceCalibrationReport"
    )


def test_calibration_contract_rejects_authority_or_bad_targets() -> None:
    report = _report()
    cases = _cases(report)
    payload = cases[0].model_dump(mode="json")
    payload["target_kind"] = "semantic_candidate"
    with pytest.raises(ValidationError):
        AttackPathCalibrationCase.model_validate(payload)
    calibration = AttackPathEvidenceCalibrationRunner().run(report, cases)
    forged = calibration.model_dump(mode="json")
    forged["ci_authority"] = True
    with pytest.raises(ValidationError):
        type(calibration).model_validate(forged)
