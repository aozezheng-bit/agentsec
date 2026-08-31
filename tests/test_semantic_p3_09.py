"""P3-09 trusted input builder and Semantic Analyze CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.cli import app
from agentsec.domain import FindingCategory
from agentsec.frameworks import CodexAdapter, FrameworkInspectionRequest
from agentsec.semantic import (
    SemanticAnalysisInput,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticModelCandidate,
    SemanticModelOutput,
    TrustedSemanticInputBuilder,
)

runner = CliRunner()


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text(
        "# Agent\n\nUse the tool only with human approval.\n", encoding="utf-8"
    )
    return project


def _input_for_project(project: Path) -> SemanticAnalysisInput:
    adapter = CodexAdapter()
    inspection = adapter.inspect(FrameworkInspectionRequest(project_root=project))
    deterministic = AgentAnalysisPipeline(adapter=adapter).analyze(
        AgentAnalysisRequest(project_root=project)
    )
    return TrustedSemanticInputBuilder().build(inspection, deterministic.manifest)


def test_trusted_builder_uses_adapter_records_and_preserves_coverage(
    tmp_path: Path,
) -> None:
    semantic_input = _input_for_project(_project(tmp_path))
    assert semantic_input.analysis_id.startswith("semantic-")
    assert semantic_input.deterministic_context.manifest_sha256 is not None
    assert semantic_input.deterministic_context.coverage_complete is True
    assert semantic_input.evidence
    assert semantic_input.evidence[0].asset_path == "AGENTS.md"
    assert semantic_input.evidence[0].secret_values_included is False
    assert semantic_input.evidence[0].instruction_authority is False


def test_builder_marks_evidence_limit_as_incomplete(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / "SKILL.md").write_text("Use the tool.\n", encoding="utf-8")
    limited = TrustedSemanticInputBuilder(max_evidence_chunks=1)
    adapter = CodexAdapter()
    inspection = adapter.inspect(FrameworkInspectionRequest(project_root=project))
    deterministic = AgentAnalysisPipeline(adapter=adapter).analyze(
        AgentAnalysisRequest(project_root=project)
    )
    result = limited.build(inspection, deterministic.manifest)
    assert len(result.evidence) == 1
    assert result.deterministic_context.coverage_complete is False
    assert "semantic_evidence_limit" in result.deterministic_context.unknown_dimensions


def test_semantic_analyze_cli_runs_offline_and_writes_json(tmp_path: Path) -> None:
    project = _project(tmp_path)
    output = tmp_path / "semantic-report.json"
    result = runner.invoke(
        app,
        [
            "semantic",
            "analyze",
            str(project),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["format"] == "agentsec-semantic-shadow-pipeline-report"
    assert payload["report_only"] is True
    assert payload["ci_authority"] is False
    assert payload["blocks"] is False
    assert payload["runtime_verified"] is False


def test_semantic_analyze_cli_replays_a_bounded_offline_response_fixture(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    semantic_input = _input_for_project(project)
    evidence_id = semantic_input.evidence[0].evidence_id
    response = SemanticModelOutput(
        analysis_id=semantic_input.analysis_id,
        analyzed_evidence_ids=tuple(
            item.evidence_id for item in semantic_input.evidence
        ),
        candidates=(
            SemanticModelCandidate(
                candidate_key="candidate-01",
                kind=SemanticCandidateKind.RISKY_INTENT,
                category=FindingCategory.HUMAN_APPROVAL,
                disposition=SemanticCandidateDisposition.SUPPORTED,
                summary="The asset describes an approval-sensitive action.",
                evidence_ids=(evidence_id,),
            ),
        ),
    )
    response_path = tmp_path / "response.json"
    response_path.write_text(
        json.dumps(response.model_dump(mode="json")), encoding="utf-8"
    )
    output = tmp_path / "semantic-report.json"
    result = runner.invoke(
        app,
        [
            "semantic",
            "analyze",
            str(project),
            "--response",
            str(response_path),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert len(payload["invocation"]["analysis"]["candidates"]) == 1
    assert len(payload["rule_candidates"]["proposals"]) == 1
    assert payload["rule_candidates"]["proposals"][0]["status"] == "review_required"
    assert "Use the tool only with human approval" not in output.read_text(
        encoding="utf-8"
    )


def test_live_provider_requires_explicit_opt_in(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "semantic",
            "analyze",
            str(_project(tmp_path)),
            "--provider",
            "live_https",
        ],
    )
    assert result.exit_code != 0
    assert "configuration/input error" in result.output
