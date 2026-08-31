"""P2-CAL-02 deterministic evaluation Runner and reports."""

from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path

from agentsec.calibration import (
    CalibrationJsonRenderer,
    CalibrationObservation,
    CalibrationRuleOutcome,
    CalibrationTextRenderer,
    DeterministicCalibrationRunner,
    DeterministicFactBundleEvaluator,
    export_calibration_report_json_schema,
    load_calibration_corpus,
)
from agentsec.capability_rules import CapabilityCorrelation, CapabilityRuleLanguage
from agentsec.domain import EvidenceConfidence

REPOSITORY_ROOT = Path(__file__).parents[1]
CALIBRATION_ROOT = REPOSITORY_ROOT / "calibration"


def test_seed_runner_produces_deterministic_complete_metrics() -> None:
    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    runner = DeterministicCalibrationRunner()

    first = runner.run(corpus)
    second = runner.run(corpus)

    expected_matches = sum(
        expectation.outcome is CalibrationRuleOutcome.MATCH
        for case in corpus.cases
        for expectation in case.ground_truth.rule_expectations
    )
    expected_no_matches = sum(
        expectation.outcome is CalibrationRuleOutcome.NO_MATCH
        for case in corpus.cases
        for expectation in case.ground_truth.rule_expectations
    )

    assert first == second
    assert first.status == "complete"
    assert first.summary.total_cases == len(corpus.index.case_paths)
    assert first.summary.total_expectations == expected_matches + expected_no_matches
    assert first.summary.evaluated_rules == 29
    assert first.summary.micro.confusion.model_dump() == {
        "true_positive": expected_matches,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": expected_no_matches,
    }
    assert first.summary.micro.precision == 1.0
    assert first.summary.micro.recall == 1.0
    assert first.summary.micro.f1 == 1.0
    assert first.summary.coverage_visibility == 1.0
    assert first.summary.unknown_visibility == 1.0
    assert first.summary.evidence_completeness == 1.0
    assert first.summary.correlation_agreement == 1.0
    assert first.summary.confidence_agreement == 1.0
    assert first.summary.insufficient_sample_rules == sum(
        not item.sufficient_sample_size for item in first.rules
    )
    assert first.policy.ci_blocking_enabled is False
    assert first.policy.hard_gate_eligibility_decided is False


def test_runner_calculates_false_positive_and_false_negative() -> None:
    base = DeterministicFactBundleEvaluator()

    class PerturbingEvaluator:
        evaluator_id = "test-perturbation"
        evaluator_version = "0.1.0"

        def evaluate(self, *, corpus_root, case, expectation):  # type: ignore[no-untyped-def]
            observed = base.evaluate(
                corpus_root=corpus_root,
                case=case,
                expectation=expectation,
            )
            if case.case_id == "cal-positive-approval-001-en":
                return CalibrationObservation(
                    outcome=CalibrationRuleOutcome.NO_MATCH,
                    evidence_complete=True,
                    coverage_visible=True,
                    unknowns_visible=True,
                )
            if case.case_id == "cal-near-miss-approval-001-zh":
                return CalibrationObservation(
                    outcome=CalibrationRuleOutcome.MATCH,
                    correlations=(CapabilityCorrelation.SAME_TARGET,),
                    confidences=(EvidenceConfidence.B,),
                    finding_count=1,
                    evidence_items=1,
                    evidence_complete=True,
                    coverage_visible=True,
                    unknowns_visible=True,
                )
            return observed

    report = DeterministicCalibrationRunner(PerturbingEvaluator()).run(
        load_calibration_corpus(CALIBRATION_ROOT)
    )
    matrix = report.summary.micro.confusion

    corpus = load_calibration_corpus(CALIBRATION_ROOT)
    expected_matches = sum(
        expectation.outcome is CalibrationRuleOutcome.MATCH
        for case in corpus.cases
        for expectation in case.ground_truth.rule_expectations
    )
    expected_no_matches = sum(
        expectation.outcome is CalibrationRuleOutcome.NO_MATCH
        for case in corpus.cases
        for expectation in case.ground_truth.rule_expectations
    )

    assert matrix.true_positive == expected_matches - 1
    assert matrix.false_positive == 1
    assert matrix.false_negative == 1
    assert matrix.true_negative == expected_no_matches - 1
    assert report.summary.micro.precision == round(
        (expected_matches - 1) / expected_matches, 6
    )
    assert report.summary.micro.recall == round(
        (expected_matches - 1) / expected_matches, 6
    )
    assert report.summary.micro.false_positive_rate == round(1 / expected_no_matches, 6)
    approval = next(item for item in report.rules if item.rule_id == "CAP-APPROVAL-001")
    assert approval.confusion.false_positive == 1
    assert approval.confusion.false_negative == 1


def test_runner_isolates_evaluator_failure_without_leaking_exception() -> None:
    marker = "p2-cal-02-secret-must-not-leak"
    base = DeterministicFactBundleEvaluator()

    class FailingEvaluator:
        evaluator_id = "test-failure"
        evaluator_version = "0.1.0"

        def evaluate(self, *, corpus_root, case, expectation):  # type: ignore[no-untyped-def]
            if case.case_id == "cal-conflicting-control-bilingual":
                raise RuntimeError(marker)
            return base.evaluate(
                corpus_root=corpus_root,
                case=case,
                expectation=expectation,
            )

    report = DeterministicCalibrationRunner(FailingEvaluator()).run(
        load_calibration_corpus(CALIBRATION_ROOT)
    )

    assert report.status == "incomplete"
    assert report.summary.failures == 1
    assert marker not in repr(report)
    assert sum(item.failure for item in report.cases) == 1


def test_calibration_reports_are_bilingual_deterministic_and_schema_backed(
    tmp_path: Path,
) -> None:
    report = DeterministicCalibrationRunner().run(
        load_calibration_corpus(CALIBRATION_ROOT)
    )
    json_renderer = CalibrationJsonRenderer()

    first = json_renderer.render(report)
    second = json_renderer.render(report)
    payload = json.loads(first)
    english = CalibrationTextRenderer().render(report)
    chinese = CalibrationTextRenderer(language=CapabilityRuleLanguage.ZH).render(report)
    schema = export_calibration_report_json_schema(tmp_path)

    insufficient = sum(not item.sufficient_sample_size for item in report.rules)

    assert first == second
    assert payload["format"] == "agentsec-capability-calibration-report"
    assert payload["format_version"] == "0.1.0"
    assert payload["policy"]["enforcement_mode"] == "report_only"
    assert "AgentSec Capability Calibration" in english
    assert f"Insufficient-sample Rules: {insufficient}" in english
    assert "AgentSec 能力校准报告" in chinese
    assert f"样本不足规则：{insufficient}" in chinese
    assert "Seed fact-bundle replay" in english
    assert json.loads(schema.read_text())["additionalProperties"] is False


def test_calibration_script_writes_private_json_artifact(tmp_path: Path) -> None:
    output = tmp_path / "calibration.json"
    result = subprocess.run(
        (
            str(REPOSITORY_ROOT / ".venv" / "bin" / "python"),
            str(REPOSITORY_ROOT / "scripts" / "run-calibration.py"),
            "--corpus",
            str(CALIBRATION_ROOT),
            "--format",
            "json",
            "--output",
            str(output),
        ),
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text())["summary"]["evaluated_rules"] == 29
