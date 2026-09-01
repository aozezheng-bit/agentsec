"""P3-AG-06 Attack Path Evidence association CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentsec.attack_graph import (
    AttackGraphEdge,
    AttackGraphEdgeKind,
    AttackGraphNode,
    AttackGraphNodeKind,
    AttackGraphNodeProvenance,
    AttackGraphPath,
    AttackGraphSourceRef,
    AttackPathAssociationRelation,
    AttackPathEvidenceAssociationReport,
    CapabilityAttackGraph,
    attack_edge_id,
    attack_node_id,
    attack_path_id,
    encode_attack_graph_json,
)
from agentsec.cli import app
from agentsec.cli.exit_codes import ExitCode
from agentsec.domain import (
    Evidence,
    EvidenceConfidence,
    EvidenceSource,
    Finding,
    FindingCategory,
    ImpactLevel,
    LikelihoodLevel,
    Severity,
)

runner = CliRunner()
_HASH = "a" * 64


def _source(line: int = 4) -> AttackGraphSourceRef:
    return AttackGraphSourceRef(
        asset_path="AGENTS.md",
        asset_sha256=_HASH,
        start_line=line,
        end_line=line,
    )


def _graph() -> CapabilityAttackGraph:
    source = _source()
    agent = AttackGraphNode(
        node_id=attack_node_id(
            node_kind=AttackGraphNodeKind.AGENT,
            label=None,
            node_provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
            manifest_refs=("agent:root",),
            sources=(source,),
        ),
        node_kind=AttackGraphNodeKind.AGENT,
        node_provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
        manifest_refs=("agent:root",),
        sources=(source,),
    )
    tool = AttackGraphNode(
        node_id=attack_node_id(
            node_kind=AttackGraphNodeKind.TOOL,
            label=None,
            node_provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
            manifest_refs=("tool:shell",),
            sources=(),
        ),
        node_kind=AttackGraphNodeKind.TOOL,
        node_provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
        manifest_refs=("tool:shell",),
    )
    edge = AttackGraphEdge(
        edge_id=attack_edge_id(
            edge_kind=AttackGraphEdgeKind.USES_TOOL,
            source_node_id=agent.node_id,
            target_node_id=tool.node_id,
            sources=(source,),
        ),
        edge_kind=AttackGraphEdgeKind.USES_TOOL,
        source_node_id=agent.node_id,
        target_node_id=tool.node_id,
        sources=(source,),
    )
    path = AttackGraphPath(
        path_id=attack_path_id(
            pattern_id="secret-exfiltration",
            node_sequence=(agent.node_id, tool.node_id),
            edge_sequence=(edge.edge_id,),
        ),
        pattern_id="secret-exfiltration",
        node_sequence=(agent.node_id, tool.node_id),
        edge_sequence=(edge.edge_id,),
    )
    return CapabilityAttackGraph(
        manifest_schema_version="0.3.0",
        manifest_sha256="b" * 64,
        nodes=tuple(sorted((agent, tool), key=lambda item: item.node_id)),
        edges=(edge,),
        paths=(path,),
    )


def _finding() -> Finding:
    return Finding(
        finding_id="finding-001",
        rule_id="MD-EXEC-001",
        category=FindingCategory.CODE_EXECUTION,
        title="Shell execution is declared",
        description="The instruction file declares shell execution capability.",
        likelihood=LikelihoodLevel.MODERATE,
        impact=ImpactLevel.HIGH,
        severity=Severity.HIGH,
        score=8.0,
        confidence=EvidenceConfidence.C,
        evidence=(
            Evidence(
                source_type=EvidenceSource.FILE,
                asset_path="AGENTS.md",
                start_line=4,
                end_line=4,
                excerpt="SECRET_SHOULD_NOT_BE_RENDERED",
                content_sha256=_HASH,
            ),
        ),
        recommendations=("Require approval before execution.",),
    )


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_association_cli_emits_report_only_json_and_matches_finding(
    tmp_path: Path,
) -> None:
    graph_path = tmp_path / "graph.json"
    findings_path = tmp_path / "findings.json"
    _write_json(graph_path, json.loads(encode_attack_graph_json(_graph())))
    _write_json(findings_path, [_finding().model_dump(mode="json")])

    result = runner.invoke(
        app,
        [
            "attack-graph-associate",
            "--graph",
            str(graph_path),
            "--findings",
            str(findings_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    report = AttackPathEvidenceAssociationReport.model_validate_json(result.stdout)
    assert report.association_count == 1
    assert (
        report.finding_associations[0].relation
        is AttackPathAssociationRelation.DUPLICATES
    )
    assert report.report_only is True
    assert report.blocks is False
    assert "SECRET_SHOULD_NOT_BE_RENDERED" not in result.stdout


def test_association_cli_supports_project_mode_and_safe_artifact_force(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text(
        "---\nmemory:\n  write: scratch\n---\n# Agent\n", encoding="utf-8"
    )
    output = tmp_path / "association.json"
    first = runner.invoke(
        app,
        [
            "attack-graph-associate",
            "--project",
            str(project),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )
    second = runner.invoke(
        app,
        [
            "attack-graph-associate",
            "--project",
            str(project),
            "--format",
            "json",
            "--output",
            str(output),
            "--force",
        ],
    )

    assert first.exit_code == ExitCode.SUCCESS
    assert second.exit_code == ExitCode.SUCCESS
    report = AttackPathEvidenceAssociationReport.model_validate_json(
        output.read_text(encoding="utf-8")
    )
    assert report.report_only is True


def test_association_cli_rejects_ambiguous_or_incomplete_input_selection(
    tmp_path: Path,
) -> None:
    graph_path = tmp_path / "graph.json"
    _write_json(graph_path, json.loads(encode_attack_graph_json(_graph())))

    neither = runner.invoke(app, ["attack-graph-associate"])
    both = runner.invoke(
        app,
        [
            "attack-graph-associate",
            "--graph",
            str(graph_path),
            "--project",
            str(tmp_path),
        ],
    )
    semantic_only = runner.invoke(
        app,
        [
            "attack-graph-associate",
            "--graph",
            str(graph_path),
            "--semantic-evidence",
            str(graph_path),
        ],
    )

    assert neither.exit_code == ExitCode.CONFIGURATION_ERROR
    assert both.exit_code == ExitCode.CONFIGURATION_ERROR
    assert semantic_only.exit_code == ExitCode.CONFIGURATION_ERROR
    assert "exactly one" in both.stderr
    assert "requires --semantic-result" in semantic_only.stderr


def test_association_cli_fails_closed_on_invalid_graph_artifact(tmp_path: Path) -> None:
    graph_path = tmp_path / "graph.json"
    graph_path.write_text('{"format":"not-a-graph"}', encoding="utf-8")

    result = runner.invoke(
        app,
        ["attack-graph-associate", "--graph", str(graph_path)],
    )

    assert result.exit_code == ExitCode.ARTIFACT_ERROR
    assert "schema validation" in result.stderr
    assert "not-a-graph" not in result.stderr
