"""P2-EXIT-08A Phase 3 promotion state-machine tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import agentsec.release_review as release_review_module
from agentsec.release_review import (
    PHASE3_CANDIDATE_VERSION,
    PHASE3_ENTRY_REVIEW_FORMAT_VERSION,
    DeterministicPhase3EntryReview,
    Phase3EntryReviewRequest,
    Phase3PromotionState,
    Phase3ReviewLanguage,
    Phase3ReviewStage,
    Phase3ReviewStatus,
    encode_phase3_entry_review_json,
    render_phase3_entry_review_text,
)

ROOT = Path(__file__).resolve().parents[1]
_AUTHORITY_BOUNDARY = {
    "llm_candidate_evidence_only": True,
    "llm_allow_block": False,
    "llm_rule_publication": False,
    "llm_waiver_approval": False,
    "runtime_unverified_authority": False,
    "deterministic_rules_retain_authority": True,
    "ci_blocking_requires_explicit_policy": True,
}


def _write(path: Path, content: str = "evidence\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _control_root(tmp_path: Path) -> Path:
    root = tmp_path / "control-root"
    for index in range(1, 8):
        _write(root / "docs" / "tasks" / f"P2-EXIT-{index:02d}-record.md")
    _write(root / "src" / "agentsec" / "api.py")
    _write(root / "src" / "agentsec" / "py.typed")
    _write(root / "src" / "agentsec" / "exit_codes.py")
    _write(
        root / "docs" / "phase2-exit-hardening-plan.md",
        "LLM output = candidate evidence only\n"
        "deterministic Rules retain authorization authority\n",
    )
    _write(
        root / "src" / "agentsec" / "provenance.py",
        "allow_llm_authority = False\nruntime_unverified_authority = False\n",
    )
    _write(root / "src" / "agentsec" / "policy" / "ci_enforcement.py")
    _write(root / "requirements" / "runtime.lock")
    _write(root / "requirements" / "dev.lock")
    _write(root / "supply-chain" / "sbom.cdx.json", "{}\n")
    _write(root / "supply-chain" / "license-inventory.json", "{}\n")
    _write(root / "supply-chain" / "lockfiles.sha256")
    _write(
        root / "supply-chain" / "build-provenance.json",
        json.dumps(
            {
                "artifact_signature": "not_claimed",
                "slsa_provenance": "not_claimed",
            }
        ),
    )
    return root


def _external_pilot(root: Path) -> Path:
    path = root / "evidence" / "external-pilot.json"
    cases: list[dict[str, object]] = []
    for index in range(20):
        scan_kind = "baseline" if index < 10 else "pull_request"
        drill = None
        expected_exit = 0
        expected_coverage = "complete"
        if index == 10:
            drill = "risky_change"
            expected_exit = 1
        elif index == 11:
            drill = "incomplete_coverage"
            expected_exit = 2
            expected_coverage = "incomplete"
        elif index == 12:
            drill = "waiver_lifecycle"
        cases.append(
            {
                "case_id": f"case-{index + 1:02d}",
                "title": f"Case {index + 1:02d}",
                "expected_exit": expected_exit,
                "observed_exit": expected_exit,
                "expected_coverage": expected_coverage,
                "observed_coverage": expected_coverage,
                "expected_rule_ids": [],
                "observed_rule_ids": [],
                "true_positive_rule_ids": [],
                "false_positive_rule_ids": [],
                "false_negative_rule_ids": [],
                "duration_ms": 1,
                "max_duration_ms": 10000,
                "json_bytes": 1,
                "sarif_bytes": 1,
                "sarif_valid": True,
                "decision_agreement": True,
                "coverage_agreement": True,
                "detection_agreement": True,
                "performance_within_limit": True,
                "passed": True,
                "scan_kind": scan_kind,
                "drill": drill,
            }
        )
    _write(
        path,
        json.dumps(
            {
                "format": "agentsec-pilot-report",
                "format_version": "0.1.0",
                "status": "complete",
                "pilot_id": "external-pilot",
                "project_name": "External Pilot",
                "owner": "project-owner",
                "evidence_mode": "external_repository",
                "plan_sha256": "0" * 64,
                "agentsec_executable": "agentsec",
                "metrics": {
                    "cases": 20,
                    "passed_cases": 20,
                    "failed_cases": 0,
                    "true_positives": 0,
                    "false_positives": 0,
                    "false_negatives": 0,
                    "precision": None,
                    "recall": None,
                    "decision_accuracy": 1.0,
                    "coverage_accuracy": 1.0,
                    "detection_accuracy": 1.0,
                    "total_duration_ms": 20,
                    "mean_duration_ms": 1.0,
                    "p50_duration_ms": 1,
                    "p95_duration_ms": 1,
                    "max_duration_ms": 1,
                    "baseline_scans": 10,
                    "pull_request_scans": 10,
                    "drill_counts": {
                        "risky_change": 1,
                        "incomplete_coverage": 1,
                        "waiver_lifecycle": 1,
                    },
                    "scope_scans_target": 20,
                    "scope_pr_scans_target": 10,
                    "scope_complete": True,
                    "human_labels_complete": True,
                    "acceptance_ready": True,
                },
                "cases": cases,
                "limitations": ["Static report-only evidence."],
                "human_label_source": "independent_reviewer",
                "human_reviewer_ids": ["reviewer-a"],
            }
        ),
    )
    return path


def _approved_entry_report(root: Path) -> Path:
    pilot = _external_pilot(root)
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=root,
            external_pilot_report=pilot,
        )
    )
    path = root / "reviews" / "entry-readiness.json"
    _write(path, encode_phase3_entry_review_json(report))
    return path


def _candidate_artifacts(root: Path, *, valid_checksums: bool = True) -> None:
    release_dir = root / "dist" / PHASE3_CANDIDATE_VERSION
    wheel = release_dir / "agentsec-0.4.0-py3-none-any.whl"
    sdist = release_dir / "agentsec-0.4.0.tar.gz"
    _write(wheel, "wheel bytes\n")
    _write(sdist, "sdist bytes\n")
    wheel_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
    sdist_hash = hashlib.sha256(sdist.read_bytes()).hexdigest()
    if not valid_checksums:
        wheel_hash = "0" * 64
    _write(
        release_dir / "SHA256SUMS",
        f"{wheel_hash}  {wheel.name}\n{sdist_hash}  {sdist.name}\n",
    )


def _candidate_verification(root: Path) -> Path:
    path = root / "reviews" / "candidate-verification.json"
    _write(
        path,
        json.dumps(
            {
                "format": "agentsec-candidate-verification-report",
                "format_version": "0.1.0",
                "candidate_version": "0.4.0",
                "status": "complete",
                "acceptance_ready": True,
                "checks": {
                    "package_hardening": True,
                    "reproducible_build": True,
                    "clean_install": True,
                    "public_api_import": True,
                    "checksums_verified": True,
                },
            }
        ),
    )
    return path


def test_current_entry_readiness_is_honest_no_go_without_external_pilot() -> None:
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(repository_root=ROOT)
    )

    assert report.format_version == PHASE3_ENTRY_REVIEW_FORMAT_VERSION == "0.2.0"
    assert report.review_stage is Phase3ReviewStage.ENTRY_READINESS
    assert report.state is Phase3PromotionState.ENTRY_NO_GO
    assert report.status is Phase3ReviewStatus.NO_GO
    assert report.acceptance_ready is False
    assert {item.check_id for item in report.blocking_checks} == {
        "external_pilot_evidence"
    }
    assert report.ready_for_candidate_promotion is False
    assert report.ready_for_candidate_build is False
    assert report.ready_for_phase3_shadow is False
    assert report.ready_for_release is False
    assert report.authority_boundary == _AUTHORITY_BOUNDARY


def test_current_engineering_pilot_reports_human_evidence_as_only_gap() -> None:
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=ROOT,
            external_pilot_report=(
                ROOT
                / "pilots"
                / "external-homi-demo"
                / "final-pilot"
                / "results"
                / "pilot-report.json"
            ),
        )
    )

    pilot_check = next(
        item for item in report.checks if item.check_id == "external_pilot_evidence"
    )
    assert report.state is Phase3PromotionState.ENTRY_NO_GO
    assert pilot_check.status.value == "pending"
    assert "machine scope is complete" in pilot_check.rationale
    assert "independent human labels" in pilot_check.rationale


def test_entry_readiness_does_not_require_version_or_candidate_artifacts(
    tmp_path: Path,
) -> None:
    root = _control_root(tmp_path)
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=root,
            external_pilot_report=_external_pilot(root),
        )
    )

    assert report.state is Phase3PromotionState.READY_FOR_CANDIDATE
    assert report.status is Phase3ReviewStatus.GO
    assert report.acceptance_ready is True
    assert report.ready_for_candidate_promotion is True
    assert report.ready_for_candidate_build is True
    assert report.ready_for_phase3_shadow is True
    assert report.ready_for_release is False
    assert "candidate_version_promotion" not in {
        item.check_id for item in report.checks
    }
    assert "candidate_artifacts" not in {item.check_id for item in report.checks}


def test_entry_readiness_rejects_unstructured_acceptance_assertion(
    tmp_path: Path,
) -> None:
    root = _control_root(tmp_path)
    path = root / "evidence" / "self-asserted.json"
    _write(
        path,
        json.dumps(
            {
                "status": "complete",
                "metrics": {"acceptance_ready": True},
            }
        ),
    )

    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=root,
            external_pilot_report=path,
        )
    )

    assert report.state is Phase3PromotionState.ENTRY_NO_GO
    pilot_check = next(
        item for item in report.checks if item.check_id == "external_pilot_evidence"
    )
    assert pilot_check.status.value == "fail"


def test_homi_baseline_report_cannot_authorize_entry_readiness() -> None:
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=ROOT,
            external_pilot_report=(
                ROOT
                / "pilots"
                / "external-homi-demo"
                / "results"
                / "baseline-01"
                / "homi-pilot-report.json"
            ),
        )
    )

    assert report.state is Phase3PromotionState.ENTRY_NO_GO
    pilot_check = next(
        item for item in report.checks if item.check_id == "external_pilot_evidence"
    )
    assert pilot_check.status.value == "fail"
    assert report.ready_for_candidate_promotion is False


def test_homi_pr_drift_aggregate_cannot_authorize_entry_readiness() -> None:
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=ROOT,
            external_pilot_report=(
                ROOT
                / "pilots"
                / "external-homi-demo"
                / "pr-change-evidence"
                / "evidence"
                / "pr-change-evidence.json"
            ),
        )
    )

    assert report.state is Phase3PromotionState.ENTRY_NO_GO
    pilot_check = next(
        item for item in report.checks if item.check_id == "external_pilot_evidence"
    )
    assert pilot_check.status.value == "fail"
    assert report.ready_for_candidate_promotion is False


def test_candidate_acceptance_requires_approved_entry_report(tmp_path: Path) -> None:
    root = _control_root(tmp_path)
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=root,
            stage=Phase3ReviewStage.CANDIDATE_ACCEPTANCE,
        )
    )

    assert report.state is Phase3PromotionState.ENTRY_NO_GO
    assert report.status is Phase3ReviewStatus.NO_GO
    assert "entry_readiness_approval" in {
        item.check_id for item in report.blocking_checks
    }
    assert report.ready_for_candidate_promotion is False


def test_approved_entry_moves_candidate_to_under_review(tmp_path: Path) -> None:
    root = _control_root(tmp_path)
    entry_report = _approved_entry_report(root)
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=root,
            stage=Phase3ReviewStage.CANDIDATE_ACCEPTANCE,
            entry_readiness_report=entry_report,
        )
    )

    assert report.state is Phase3PromotionState.CANDIDATE_UNDER_REVIEW
    assert report.status is Phase3ReviewStatus.CONDITIONAL
    assert report.acceptance_ready is False
    assert report.ready_for_candidate_promotion is True
    assert report.ready_for_candidate_build is True
    assert report.ready_for_phase3_shadow is True
    assert report.ready_for_release is False
    assert {item.check_id for item in report.blocking_checks} == {
        "candidate_artifacts",
        "candidate_verification",
    }


def test_candidate_acceptance_go_requires_verified_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _control_root(tmp_path)
    entry_report = _approved_entry_report(root)
    _candidate_artifacts(root)
    verification = _candidate_verification(root)
    monkeypatch.setattr(release_review_module, "__version__", "0.4.0")

    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=root,
            stage=Phase3ReviewStage.CANDIDATE_ACCEPTANCE,
            entry_readiness_report=entry_report,
            candidate_verification_report=verification,
        )
    )

    assert report.state is Phase3PromotionState.CANDIDATE_GO
    assert report.status is Phase3ReviewStatus.GO
    assert report.acceptance_ready is True
    assert report.blocking_checks == ()
    assert report.ready_for_release is True
    signature = next(
        item
        for item in report.checks
        if item.check_id == "release_signature_and_provenance"
    )
    assert signature.required is False
    assert signature.status.value == "pending"


def test_reconciled_candidate_report_drives_candidate_acceptance() -> None:
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=ROOT,
            stage=Phase3ReviewStage.CANDIDATE_ACCEPTANCE,
            entry_readiness_report=(
                ROOT / "docs" / "reviews" / "phase3-entry-readiness-2026-08-26.json"
            ),
            reconciled_candidate_report=(
                ROOT
                / "dist"
                / "candidates"
                / "0.4.0-p3-rel-01"
                / "reconciliation-report.json"
            ),
            release_provenance_bundle=(
                ROOT
                / "dist"
                / "candidates"
                / "0.4.0-p3-rel-01"
                / "provenance-bundle.json"
            ),
        )
    )

    assert report.state is Phase3PromotionState.CANDIDATE_GO
    assert report.acceptance_ready is True
    assert report.blocking_checks == ()
    artifact = next(
        item for item in report.checks if item.check_id == "candidate_artifacts"
    )
    verification = next(
        item for item in report.checks if item.check_id == "candidate_verification"
    )
    assert artifact.status is release_review_module.Phase3CheckStatus.PASS
    assert verification.status is release_review_module.Phase3CheckStatus.PASS
    bundle = next(
        item
        for item in report.checks
        if item.check_id == "release_manifest_and_provenance_bundle"
    )
    assert bundle.status is release_review_module.Phase3CheckStatus.PASS
    assert any("dist/candidates/0.4.0-p3-rel-01" in item for item in artifact.evidence)


def test_reconciled_candidate_report_outside_root_fails_closed() -> None:
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=ROOT,
            stage=Phase3ReviewStage.CANDIDATE_ACCEPTANCE,
            entry_readiness_report=(
                ROOT / "docs" / "reviews" / "phase3-entry-readiness-2026-08-26.json"
            ),
            reconciled_candidate_report=Path("/tmp/reconciliation-report.json"),
        )
    )

    assert report.state is Phase3PromotionState.CANDIDATE_NO_GO
    assert "candidate_artifacts" in {item.check_id for item in report.blocking_checks}


def test_reconciled_candidate_acceptance_rejects_stale_byte_content_contract() -> None:
    report_path = (
        ROOT / "dist" / "candidates" / "0.4.0-p3-rel-01" / "reconciliation-report.json"
    )
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["content_checks"]["wheel_content_match"] = False

    assert (
        release_review_module.DeterministicPhase3EntryReview._reconciliation_payload_is_accepted(  # noqa: SLF001
            ROOT, payload
        )
        is False
    )


def test_tampered_candidate_checksum_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _control_root(tmp_path)
    entry_report = _approved_entry_report(root)
    _candidate_artifacts(root, valid_checksums=False)
    verification = _candidate_verification(root)
    monkeypatch.setattr(release_review_module, "__version__", "0.4.0")

    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(
            repository_root=root,
            stage=Phase3ReviewStage.CANDIDATE_ACCEPTANCE,
            entry_readiness_report=entry_report,
            candidate_verification_report=verification,
        )
    )

    assert report.state is Phase3PromotionState.CANDIDATE_NO_GO
    assert report.status is Phase3ReviewStatus.NO_GO
    assert report.ready_for_candidate_build is True
    assert report.ready_for_release is False
    artifact_check = next(
        item for item in report.checks if item.check_id == "candidate_artifacts"
    )
    assert artifact_check.status.value == "fail"


def test_phase3_review_json_and_bilingual_text_are_value_bounded() -> None:
    report = DeterministicPhase3EntryReview().run(
        Phase3EntryReviewRequest(repository_root=ROOT)
    )
    payload = json.loads(encode_phase3_entry_review_json(report))
    english = render_phase3_entry_review_text(report)
    chinese = render_phase3_entry_review_text(report, language=Phase3ReviewLanguage.ZH)

    assert payload["format"] == "agentsec-phase3-entry-review"
    assert payload["review_stage"] == "entry_readiness"
    assert payload["state"] == "entry_no_go"
    assert payload["status"] == "no_go"
    assert "candidate evidence" in english
    assert "状态机状态" in chinese
    assert str(ROOT) not in json.dumps(payload)


def test_phase3_review_script_defaults_to_entry_readiness(tmp_path: Path) -> None:
    output = tmp_path / "phase3-review.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run-phase3-entry-review.py",
            "--format",
            "json",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["review_stage"] == "entry_readiness"
    assert payload["state"] == "entry_no_go"
    assert payload["blocking_checks"] == ["external_pilot_evidence"]


def test_stage_specific_arguments_are_rejected(tmp_path: Path) -> None:
    root = _control_root(tmp_path)
    with pytest.raises(ValueError, match="does not accept candidate-stage"):
        Phase3EntryReviewRequest(
            repository_root=root,
            candidate_verification_report=root / "candidate.json",
        )
    with pytest.raises(ValueError, match="does not accept candidate-stage"):
        Phase3EntryReviewRequest(
            repository_root=root,
            reconciled_candidate_report=root / "reconciliation.json",
        )
    with pytest.raises(ValueError, match="approved entry-readiness report"):
        Phase3EntryReviewRequest(
            repository_root=root,
            stage=Phase3ReviewStage.CANDIDATE_ACCEPTANCE,
            external_pilot_report=root / "pilot.json",
        )
