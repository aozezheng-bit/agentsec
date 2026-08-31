"""P2-EXIT-06-04/05 final external Homi Pilot workflow tests."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any, cast

import pytest

from agentsec.external_pilot import (
    EXTERNAL_HOMI_PILOT_ID,
    HOMI_PILOT_SCENARIOS,
    HOMI_STANDARD_FILES,
    ExternalPilotWorkflowError,
    deploy_external_homi_bundle,
    export_external_review_submission_schema,
    import_external_review_submission,
    prepare_external_homi_bundle,
    validate_external_human_evidence,
)
from agentsec.pilot import PilotHumanLabels, PilotPlan

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    REPOSITORY_ROOT
    / "pilots"
    / "external-homi-demo"
    / "source"
    / "workspace-files-20260826.zip"
)
BUNDLE = REPOSITORY_ROOT / "pilots" / "external-homi-demo" / "final-pilot"
SCHEMA = (
    REPOSITORY_ROOT
    / "schemas"
    / "pilot"
    / "external-pilot-review-submission.schema.json"
)


def _load(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _complete_submission(tmp_path: Path, pack: Path = BUNDLE / "reviewer-pack") -> Path:
    payload = _load(pack / "submission.template.json")
    by_id = {item.case_id: item for item in HOMI_PILOT_SCENARIOS}
    payload["status"] = "complete"
    payload["reviewer_id"] = "independent-reviewer-test"
    payload["independence_statement"] = (
        "I independently reviewed the blinded static cases without scanner output."
    )
    for row in payload["cases"]:
        scenario = by_id[row["case_id"]]
        row["expected_exit"] = scenario.expected_exit
        row["expected_coverage"] = scenario.expected_coverage
        row["expected_rule_ids"] = list(scenario.expected_rule_ids)
        row["rationale"] = (
            f"Independent static test label for {scenario.case_id}; no runtime claim."
        )
    path = tmp_path / "review-submission.json"
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def test_checked_in_final_collection_closes_machine_scope_honestly() -> None:
    report = _load(BUNDLE / "results" / "pilot-report.json")
    evidence = _load(BUNDLE / "evidence" / "collection-evidence.json")
    waiver = _load(BUNDLE / "evidence" / "waiver-drill-evidence.json")

    assert report["pilot_id"] == EXTERNAL_HOMI_PILOT_ID
    assert report["status"] == "evidence_pending"
    assert report["evidence_mode"] == "external_repository"
    assert report["human_label_source"] == "none"
    assert report["metrics"]["cases"] == 20
    assert report["metrics"]["baseline_scans"] == 10
    assert report["metrics"]["pull_request_scans"] == 10
    assert report["metrics"]["passed_cases"] == 20
    assert report["metrics"]["failed_cases"] == 0
    assert report["metrics"]["scope_complete"] is True
    assert report["metrics"]["human_labels_complete"] is False
    assert report["metrics"]["acceptance_ready"] is False
    assert evidence["policy"]["digest_pin_verified"] is True
    assert evidence["safety"]["target_unchanged"] is True
    assert waiver["waiver_lifecycle"]["passed"] is True
    assert waiver["waiver_lifecycle"] == {
        "active_waived_finding_remained_visible": True,
        "active_waiver_applied": True,
        "expired_waiver_reported": True,
        "expired_waiver_restored_blocking": True,
        "passed": True,
    }


def test_independent_final_replay_is_accepted_and_phase3_ready() -> None:
    root = BUNDLE / "final-results"
    report = _load(root / "pilot-report.json")
    entry = _load(root / "phase3-entry-readiness.json")
    evidence = _load(root / "acceptance-evidence.json")

    assert report["status"] == "complete"
    assert report["human_label_source"] == "independent_reviewer"
    assert report["human_reviewer_ids"] == ["codefuse-agentsec-expert-reviewer"]
    assert report["metrics"]["cases"] == 20
    assert report["metrics"]["passed_cases"] == 20
    assert report["metrics"]["failed_cases"] == 0
    assert report["metrics"]["true_positives"] == 25
    assert report["metrics"]["false_positives"] == 0
    assert report["metrics"]["false_negatives"] == 0
    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert report["metrics"]["scope_complete"] is True
    assert report["metrics"]["human_labels_complete"] is True
    assert report["metrics"]["acceptance_ready"] is True
    assert evidence["rule_pack_version"] == "0.3.1"
    assert entry["state"] == "ready_for_candidate"
    assert entry["blocking_checks"] == []
    assert entry["ready_for_phase3_shadow"] is True
    assert entry["ready_for_release"] is False


def test_human_review_gap_and_rule_patch_history_are_preserved() -> None:
    diagnostic = _load(
        BUNDLE / "review-diagnostics" / "pre-calibration-gap-report.json"
    )
    calibrated = _load(
        BUNDLE.parent
        / "review-history"
        / "rule-pack-0.3.1-engineering-replay"
        / "results"
        / "pilot-report.json"
    )

    assert diagnostic["metrics"]["passed_cases"] == 19
    assert diagnostic["metrics"]["false_negatives"] == 4
    assert diagnostic["metrics"]["recall"] == 0.84
    assert diagnostic["decision"]["preserve_human_labels"] is True
    assert diagnostic["decision"]["automatic_label_rewrite"] is False
    assert diagnostic["differences"][0]["false_negative_rule_ids"] == [
        "MD-EXEC-001",
        "MD-NET-001",
        "MD-SELF-001",
        "MD-TOOL-001",
    ]
    assert calibrated["metrics"]["passed_cases"] == 20
    assert calibrated["metrics"]["false_positives"] == 0
    assert calibrated["metrics"]["false_negatives"] == 0


def test_checked_in_plan_and_snapshots_are_complete_and_bound() -> None:
    plan = PilotPlan.model_validate(
        __import__("yaml").safe_load((BUNDLE / "pilot.yaml").read_text())
    )
    manifest = _load(BUNDLE / "bundle-manifest.json")

    assert plan.pilot_id == EXTERNAL_HOMI_PILOT_ID
    assert len(plan.cases) == 20
    assert sum(item.scan_kind == "pull_request" for item in plan.cases) == 10
    assert set(plan.required_drills) == {
        "incomplete_coverage",
        "risky_change",
        "waiver_lifecycle",
    }
    by_id = {item["case_id"]: item for item in manifest["snapshots"]}
    assert set(by_id) == {item.case_id for item in HOMI_PILOT_SCENARIOS}
    for case_id, item in by_id.items():
        path = BUNDLE / item["path"]
        assert _sha256(path) == item["sha256"], case_id
        with zipfile.ZipFile(path) as archive:
            assert tuple(sorted(archive.namelist())) == HOMI_STANDARD_FILES


def test_reviewer_pack_is_blinded_and_schema_is_frozen() -> None:
    pack = BUNDLE / "reviewer-pack"
    manifest = _load(pack / "manifest.json")
    template = _load(pack / "submission.template.json")
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in sorted(pack.rglob("*"))
        if path.is_file() and path.suffix != ".zip"
    )

    assert manifest["blinding"] == {
        "engineering_expectations_included": False,
        "implementation_report_included": False,
        "scanner_observations_included": False,
        "tp_fp_fn_included": False,
    }
    assert len(manifest["cases"]) == 20
    workflow = (pack / "EXPERT-WORKFLOW.zh.md").read_text(encoding="utf-8")
    rule_reference = (pack / "RULE-REFERENCE.zh.md").read_text(encoding="utf-8")
    assert "单个 Case 的判断顺序" in workflow
    assert "提交前自检" in workflow
    assert "MD-EXEC-001" in rule_reference
    assert "MD-SECRET-001" in rule_reference
    assert "不包含任何 Case 的工程预期" in rule_reference
    assert template["status"] == "draft"
    assert all(item["expected_exit"] is None for item in template["cases"])
    assert "observed_rule_ids" not in text
    assert "true_positive" not in text
    assert "false_positive" not in text
    assert "false_negative" not in text
    assert SCHEMA.read_text(encoding="utf-8") == (
        export_external_review_submission_schema()
    )


def test_bundle_preparation_is_deterministic_and_deploys_separate_roots(
    tmp_path: Path,
) -> None:
    first = prepare_external_homi_bundle(
        source_archive=SOURCE,
        bundle_root=tmp_path / "bundle-a",
        collection_date="2026-08-26",
        owner="test-owner",
    )
    second = prepare_external_homi_bundle(
        source_archive=SOURCE,
        bundle_root=tmp_path / "bundle-b",
        collection_date="2026-08-26",
        owner="test-owner",
    )
    assert first.policy_sha256 == second.policy_sha256
    assert first.snapshot_sha256 == second.snapshot_sha256

    target, trust = deploy_external_homi_bundle(
        bundle_root=first.bundle_root,
        target_root=tmp_path / "external-target",
        trust_root=tmp_path / "protected-trust",
    )
    assert target != trust
    assert (trust / "organization-policy.yaml").is_file()
    assert tuple(sorted(path.name for path in (target / "states").iterdir())) == (
        tuple(item.case_id for item in HOMI_PILOT_SCENARIOS)
    )
    for state in (target / "states").iterdir():
        assert (
            tuple(sorted(path.name for path in state.iterdir())) == HOMI_STANDARD_FILES
        )


def test_complete_review_import_emits_exact_bounded_human_labels(
    tmp_path: Path,
) -> None:
    output = tmp_path / "human-evidence"
    report = import_external_review_submission(
        reviewer_pack_root=BUNDLE / "reviewer-pack",
        submission_path=_complete_submission(tmp_path),
        output_root=output,
    )
    labels = PilotHumanLabels.model_validate_json(
        (output / "human-labels.json").read_text(encoding="utf-8")
    )

    assert report["reviewed_cases"] == 20
    assert report["human_labels_complete"] is True
    assert report["acceptance_ready"] is False
    assert labels.pilot_id == EXTERNAL_HOMI_PILOT_ID
    assert labels.reviewer_id == "independent-reviewer-test"
    assert len(labels.cases) == 20
    assert (output / "human-labels.json").stat().st_mode & 0o777 == 0o600
    validated_path, validated_labels, validated_report = (
        validate_external_human_evidence(
            human_evidence_root=output,
            reviewer_pack_root=BUNDLE / "reviewer-pack",
        )
    )
    assert validated_path == (output / "human-labels.json").resolve()
    assert validated_labels == labels
    assert validated_report["reviewer_id"] == labels.reviewer_id


def test_review_import_rejects_draft_and_stale_binding(tmp_path: Path) -> None:
    with pytest.raises(ExternalPilotWorkflowError, match="not complete"):
        import_external_review_submission(
            reviewer_pack_root=BUNDLE / "reviewer-pack",
            submission_path=BUNDLE / "reviewer-pack" / "submission.template.json",
            output_root=tmp_path / "draft-output",
        )

    submission = _complete_submission(tmp_path)
    payload = _load(submission)
    payload["case_manifest_sha256"] = "0" * 64
    submission.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ExternalPilotWorkflowError, match="binding is stale"):
        import_external_review_submission(
            reviewer_pack_root=BUNDLE / "reviewer-pack",
            submission_path=submission,
            output_root=tmp_path / "stale-output",
        )


def test_final_evidence_validation_rejects_label_tampering(tmp_path: Path) -> None:
    output = tmp_path / "human-evidence"
    import_external_review_submission(
        reviewer_pack_root=BUNDLE / "reviewer-pack",
        submission_path=_complete_submission(tmp_path),
        output_root=output,
    )
    payload = _load(output / "human-labels.json")
    payload["cases"][0]["expected_rule_ids"] = []
    (output / "human-labels.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ExternalPilotWorkflowError, match="digest binding is stale"):
        validate_external_human_evidence(
            human_evidence_root=output,
            reviewer_pack_root=BUNDLE / "reviewer-pack",
        )
