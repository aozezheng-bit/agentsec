"""P3-AG-09 Attack Path context integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.application import AgenticScoreEngine, AgenticScoreRequest
from agentsec.attack_graph import (
    AttackPathEvidenceAssociationReport,
    AttackPathEvidenceCalibrationReport,
)
from agentsec.cli import app
from agentsec.cli.exit_codes import ExitCode
from agentsec.manifests import AgentManifest
from agentsec.risk import (
    AttackPathScoreContext,
    build_attack_path_score_context,
    encode_attack_path_score_context_json,
    export_attack_path_score_context_json_schema,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BASELINE_MANIFEST = (
    REPOSITORY_ROOT
    / "demos"
    / "capability-drift-agent"
    / "expected"
    / "baseline.manifest.json"
)
RISKY_PROJECT = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / "risky-drift"
runner = CliRunner()


ASSOCIATION_FIXTURE = (
    REPOSITORY_ROOT / "calibration" / "attack-path" / "seed-association-report.json"
)
CALIBRATION_FIXTURE = (
    REPOSITORY_ROOT / "calibration" / "attack-path" / "seed-calibration-report.json"
)


def _association_report() -> AttackPathEvidenceAssociationReport:
    return AttackPathEvidenceAssociationReport.model_validate_json(
        ASSOCIATION_FIXTURE.read_text(encoding="utf-8")
    )


def _calibration_report() -> AttackPathEvidenceCalibrationReport:
    return AttackPathEvidenceCalibrationReport.model_validate_json(
        CALIBRATION_FIXTURE.read_text(encoding="utf-8")
    )


def _score_args(*extra: str) -> list[str]:
    return [
        "score",
        str(RISKY_PROJECT),
        "--agent-id",
        "release-agent",
        "--before",
        str(BASELINE_MANIFEST),
        "--format",
        "json",
        *extra,
    ]


def test_context_counts_are_stable_and_report_only() -> None:
    report = _association_report()
    context = build_attack_path_score_context(report)

    assert context.path_count == 1
    assert context.association_count == 3
    assert context.finding_association_count == 1
    assert context.semantic_association_count == 2
    assert context.relation_counts.duplicates == 1
    assert context.relation_counts.total == 3
    assert context.calibration_qualified is False
    assert context.scoring_mode == "context_only"
    assert context.numeric_score_effect == 0.0
    assert context.report_only is True
    assert context.hard_gate_authority is False
    assert context.runtime_verified is False
    assert "Run a shell command" not in encode_attack_path_score_context_json(context)


def test_calibration_is_bound_but_never_qualified() -> None:
    report = _association_report()
    calibration = _calibration_report()
    context = build_attack_path_score_context(report, calibration)

    assert context.calibration_report_sha256 is not None
    assert context.calibration_accuracy == 1.0
    assert context.calibration_reviewed_case_count == 3
    assert context.calibration_qualified is False

    mismatched = _association_report().model_copy(
        update={"path_report_sha256": "c" * 64}
    )
    with pytest.raises(ValueError, match="bound to a different"):
        build_attack_path_score_context(mismatched, calibration)


def test_attack_path_context_does_not_change_any_score_or_gate() -> None:
    report = _association_report()
    calibration = _calibration_report()
    engine = AgenticScoreEngine()
    base = engine.score(
        AgenticScoreRequest(
            project_root=RISKY_PROJECT, before=_manifest(), agent_id="release-agent"
        )
    )
    enriched = engine.score(
        AgenticScoreRequest(
            project_root=RISKY_PROJECT,
            before=_manifest(),
            agent_id="release-agent",
            attack_path_report=report,
            attack_path_calibration=calibration,
        )
    )

    assert enriched.attack_path is not None
    assert enriched.technical == base.technical
    assert enriched.drift == base.drift
    assert enriched.governance == base.governance
    assert enriched.overall == base.overall
    assert enriched.gate_matches == base.gate_matches


def test_score_cli_emits_attack_path_context_and_text_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "association.json"
    report_path.write_text(
        json.dumps(_association_report().model_dump(mode="json")), encoding="utf-8"
    )
    result = runner.invoke(app, _score_args("--attack-path-report", str(report_path)))

    assert result.exit_code == ExitCode.SUCCESS, result.stderr
    payload = json.loads(result.stdout)
    assert payload["attack_path"]["path_count"] == 1
    assert payload["attack_path"]["scoring_mode"] == "context_only"
    assert payload["attack_path"]["numeric_score_effect"] == 0.0
    assert payload["attack_path"]["calibration_qualified"] is False

    text = runner.invoke(
        app,
        [
            "score",
            str(RISKY_PROJECT),
            "--agent-id",
            "release-agent",
            "--before",
            str(BASELINE_MANIFEST),
            "--format",
            "text",
            "--attack-path-report",
            str(report_path),
        ],
    )
    assert text.exit_code == ExitCode.SUCCESS
    assert "Attack paths: 1" in text.stdout
    assert "numeric score effect=0.0" in text.stdout


def test_score_cli_requires_and_validates_calibration_binding(tmp_path: Path) -> None:
    calibration_path = tmp_path / "calibration.json"
    calibration_path.write_text(
        json.dumps(_calibration_report().model_dump(mode="json")),
        encoding="utf-8",
    )
    missing_report = runner.invoke(
        app, _score_args("--attack-path-calibration", str(calibration_path))
    )
    assert missing_report.exit_code == ExitCode.CONFIGURATION_ERROR

    report_path = tmp_path / "association.json"
    report_path.write_text(
        json.dumps(_association_report().model_dump(mode="json")), encoding="utf-8"
    )
    result = runner.invoke(
        app,
        _score_args(
            "--attack-path-report",
            str(report_path),
            "--attack-path-calibration",
            str(calibration_path),
        ),
    )
    assert result.exit_code == ExitCode.SUCCESS, result.stderr
    assert json.loads(result.stdout)["attack_path"]["calibration_accuracy"] == 1.0


def test_score_cli_rejects_invalid_attack_path_artifact(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"format":"not-an-association-report"}', encoding="utf-8")
    result = runner.invoke(app, _score_args("--attack-path-report", str(invalid)))
    assert result.exit_code == ExitCode.ARTIFACT_ERROR


def test_attack_path_context_schema_matches_export(tmp_path: Path) -> None:
    generated = export_attack_path_score_context_json_schema(tmp_path / "context.json")
    payload = json.loads(generated.read_text(encoding="utf-8"))
    assert payload["title"] == "AttackPathScoreContext"
    assert AttackPathScoreContext.model_json_schema() == payload


def _manifest() -> AgentManifest:
    from agentsec.artifacts import AgentManifestFileReader

    return AgentManifestFileReader().read(BASELINE_MANIFEST).manifest
