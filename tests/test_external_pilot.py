"""P2-EXIT-06 external report-only Pilot contract tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
import yaml

from agentsec.pilot import (
    PilotCase,
    PilotCaseResult,
    PilotError,
    PilotHumanLabelCase,
    PilotHumanLabels,
    PilotPlan,
    PilotRunner,
    load_human_labels,
    load_pilot_plan,
)

ROOT = Path(__file__).resolve().parents[1]
AGENTSEC = ROOT / ".venv" / "bin" / "agentsec"


def _external_plan(case_count: int = 20) -> PilotPlan:
    cases: list[dict[str, object]] = []
    for index in range(1, case_count + 1):
        if index <= 10:
            case_id = f"baseline-{index:02d}"
            scan_kind = "baseline"
            drill = None
            expected_exit = 0
            expected_coverage = "complete"
        elif index == 13:
            case_id = "pr-03"
            scan_kind = "pull_request"
            drill = "risky_change"
            expected_exit = 1
            expected_coverage = "complete"
        elif index == 14:
            case_id = "pr-04"
            scan_kind = "pull_request"
            drill = "incomplete_coverage"
            expected_exit = 2
            expected_coverage = "incomplete"
        elif index == 15:
            case_id = "pr-05"
            scan_kind = "pull_request"
            drill = "waiver_lifecycle"
            expected_exit = 0
            expected_coverage = "complete"
        else:
            case_id = f"pr-{index - 10:02d}"
            scan_kind = "pull_request"
            drill = None
            expected_exit = 0
            expected_coverage = "complete"
        cases.append(
            {
                "case_id": case_id,
                "title": case_id,
                "project_root": "state",
                "policy_path": "organization-policy.yaml",
                "expected_exit": expected_exit,
                "expected_coverage": expected_coverage,
                "expected_rule_ids": [],
                "scan_kind": scan_kind,
                "drill": drill,
            }
        )
    # The generated IDs are lexicographically ordered after construction.
    cases.sort(key=lambda item: str(item["case_id"]))
    return PilotPlan.model_validate(
        {
            "format": "agentsec-pilot-plan",
            "schema_version": "0.1.0",
            "pilot_id": "external-pilot-test",
            "project_name": "External Pilot Test",
            "owner": "project-owner",
            "security_reviewer": "security-reviewer",
            "evidence_mode": "external_repository",
            "minimum_scans": 20,
            "minimum_pr_scans": 10,
            "required_drills": [
                "incomplete_coverage",
                "risky_change",
                "waiver_lifecycle",
            ],
            "cases": cases,
        }
    )


def _write_plan(path: Path, plan: PilotPlan) -> None:
    path.write_text(
        yaml.safe_dump(plan.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )


def _labels(plan: PilotPlan) -> PilotHumanLabels:
    return PilotHumanLabels(
        format="agentsec-pilot-human-labels",
        schema_version="0.1.0",
        pilot_id=plan.pilot_id,
        reviewer_id="independent-reviewer",
        independence_statement=(
            "I reviewed the cases independently of the scanner implementation "
            "and recorded expected deterministic outcomes."
        ),
        cases=tuple(
            PilotHumanLabelCase(
                case_id=item.case_id,
                expected_exit=item.expected_exit,
                expected_coverage=item.expected_coverage,
                expected_rule_ids=item.expected_rule_ids,
            )
            for item in plan.cases
        ),
    )


def test_external_plan_uses_explicit_separate_roots(tmp_path: Path) -> None:
    control = tmp_path / "agentsec-control"
    target = tmp_path / "external-project"
    trust = tmp_path / "protected-policy"
    control.mkdir()
    (target / "state").mkdir(parents=True)
    trust.mkdir()
    (trust / "organization-policy.yaml").write_text("policy: test\n", encoding="utf-8")
    plan_path = control / "pilot.yaml"
    plan = _external_plan()
    _write_plan(plan_path, plan)

    loaded = load_pilot_plan(
        plan_path,
        repository_root=control,
        target_root=target,
        trust_root=trust,
    )

    assert loaded.plan.evidence_mode == "external_repository"
    assert loaded.plan.minimum_scans == 20
    assert sum(item.scan_kind == "pull_request" for item in loaded.plan.cases) == 10


def test_external_plan_requires_explicit_distinct_roots(tmp_path: Path) -> None:
    control = tmp_path / "agentsec-control"
    target = tmp_path / "external-project"
    control.mkdir()
    target.mkdir()
    (target / "state").mkdir()
    (target / "organization-policy.yaml").write_text("policy: test\n", encoding="utf-8")
    plan_path = control / "pilot.yaml"
    _write_plan(plan_path, _external_plan())

    with pytest.raises(PilotError, match="explicit --target-root"):
        load_pilot_plan(plan_path, repository_root=control)
    with pytest.raises(PilotError, match="different"):
        load_pilot_plan(
            plan_path,
            repository_root=control,
            target_root=target,
            trust_root=target,
        )


def test_human_labels_are_bounded_and_independent(tmp_path: Path) -> None:
    plan = _external_plan()
    labels = _labels(plan)
    path = tmp_path / "human-labels.json"
    path.write_text(
        json.dumps(labels.model_dump(mode="json"), ensure_ascii=False),
        encoding="utf-8",
    )

    loaded = load_human_labels(path, repository_root=tmp_path)

    assert loaded.reviewer_id == "independent-reviewer"
    assert len(loaded.cases) == 20


def test_external_runner_stays_evidence_pending_without_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "external-project"
    trust = tmp_path / "protected-policy"
    target.mkdir()
    trust.mkdir()
    (target / "state").mkdir()
    (trust / "organization-policy.yaml").write_text("policy: test\n", encoding="utf-8")
    control = tmp_path / "control"
    control.mkdir()
    plan_path = control / "pilot.yaml"
    plan = _external_plan()
    _write_plan(plan_path, plan)
    loaded = load_pilot_plan(
        plan_path,
        repository_root=control,
        target_root=target,
        trust_root=trust,
    )

    def fake_run_case(case: PilotCase, **kwargs: object) -> PilotCaseResult:
        del kwargs
        return PilotCaseResult(
            case_id=case.case_id,
            title=case.title,
            expected_exit=case.expected_exit,
            observed_exit=case.expected_exit,
            expected_coverage=case.expected_coverage,
            observed_coverage=case.expected_coverage,
            expected_rule_ids=case.expected_rule_ids,
            observed_rule_ids=case.expected_rule_ids,
            true_positive_rule_ids=case.expected_rule_ids,
            false_positive_rule_ids=(),
            false_negative_rule_ids=(),
            duration_ms=1,
            max_duration_ms=case.max_duration_ms,
            json_bytes=1,
            sarif_bytes=1,
            sarif_valid=True,
            decision_agreement=True,
            coverage_agreement=True,
            detection_agreement=True,
            performance_within_limit=True,
            passed=True,
            scan_kind=case.scan_kind,
            drill=case.drill,
        )

    monkeypatch.setattr(PilotRunner, "_run_case", staticmethod(fake_run_case))
    report = PilotRunner().run(
        loaded,
        repository_root=ROOT,
        agentsec_executable=AGENTSEC,
        output_root=tmp_path / "output",
        target_root=target,
        trust_root=trust,
    )

    assert report.status == "evidence_pending"
    assert report.metrics.scope_complete is True
    assert report.metrics.human_labels_complete is False
    assert report.metrics.acceptance_ready is False
    assert "human TP/FP/FN labels" in " ".join(report.limitations)


def test_external_runner_accepts_complete_scope_and_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "external-project"
    trust = tmp_path / "protected-policy"
    target.mkdir()
    trust.mkdir()
    (target / "state").mkdir()
    (trust / "organization-policy.yaml").write_text("policy: test\n", encoding="utf-8")
    control = tmp_path / "control"
    control.mkdir()
    plan_path = control / "pilot.yaml"
    plan = _external_plan()
    _write_plan(plan_path, plan)
    loaded = load_pilot_plan(
        plan_path,
        repository_root=control,
        target_root=target,
        trust_root=trust,
    )

    def fake_run_case(case: PilotCase, **kwargs: object) -> PilotCaseResult:
        expected = cast(PilotHumanLabelCase, kwargs["expected"])
        return PilotCaseResult(
            case_id=case.case_id,
            title=case.title,
            expected_exit=expected.expected_exit,
            observed_exit=expected.expected_exit,
            expected_coverage=expected.expected_coverage,
            observed_coverage=expected.expected_coverage,
            expected_rule_ids=expected.expected_rule_ids,
            observed_rule_ids=expected.expected_rule_ids,
            true_positive_rule_ids=expected.expected_rule_ids,
            false_positive_rule_ids=(),
            false_negative_rule_ids=(),
            duration_ms=1,
            max_duration_ms=case.max_duration_ms,
            json_bytes=1,
            sarif_bytes=1,
            sarif_valid=True,
            decision_agreement=True,
            coverage_agreement=True,
            detection_agreement=True,
            performance_within_limit=True,
            passed=True,
            scan_kind=case.scan_kind,
            drill=case.drill,
        )

    monkeypatch.setattr(PilotRunner, "_run_case", staticmethod(fake_run_case))
    report = PilotRunner().run(
        loaded,
        repository_root=ROOT,
        agentsec_executable=AGENTSEC,
        output_root=tmp_path / "output",
        target_root=target,
        trust_root=trust,
        human_labels=_labels(plan),
    )

    assert report.status == "complete"
    assert report.metrics.acceptance_ready is True
    assert report.metrics.human_labels_complete is True
    assert report.human_label_source == "independent_reviewer"
