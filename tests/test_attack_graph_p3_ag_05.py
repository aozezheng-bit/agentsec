"""P3-AG-05 deterministic Attack Path Evidence association tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.attack_graph import (
    AttackGraphEdge,
    AttackGraphEdgeKind,
    AttackGraphNode,
    AttackGraphNodeKind,
    AttackGraphNodeProvenance,
    AttackGraphPath,
    AttackGraphSourceRef,
    AttackPathAssociationBasis,
    AttackPathAssociationRelation,
    AttackPathEvidenceAssociationReport,
    AttackPathEvidenceAssociator,
    CapabilityAttackGraph,
    attack_edge_id,
    attack_node_id,
    attack_path_id,
    canonical_attack_path_evidence_association_sha256,
    encode_attack_path_evidence_association_json,
    export_attack_path_evidence_association_json_schema,
    render_attack_path_evidence_association_text,
)
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
from agentsec.semantic import (
    SemanticAnalysisContract,
    SemanticAnalysisInput,
    SemanticAnalysisResult,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticDeterministicContext,
    SemanticEvidenceChunk,
    SemanticInvocationProvenance,
    SemanticModelCandidate,
    SemanticModelOutput,
    build_semantic_evidence_chunk,
)

_HASH = "a" * 64


def _source(line: int) -> AttackGraphSourceRef:
    return AttackGraphSourceRef(
        asset_path="AGENTS.md",
        asset_sha256=_HASH,
        start_line=line,
        end_line=line,
    )


def _node(
    kind: AttackGraphNodeKind,
    ref: str,
    sources: tuple[AttackGraphSourceRef, ...] = (),
) -> AttackGraphNode:
    refs = (ref,)
    return AttackGraphNode(
        node_id=attack_node_id(
            node_kind=kind,
            label=None,
            node_provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
            manifest_refs=refs,
            sources=tuple(sources),
        ),
        node_kind=kind,
        node_provenance=AttackGraphNodeProvenance.MANIFEST_DECLARED,
        manifest_refs=refs,
        sources=tuple(sources),
    )


def _graph(*, second_line: int | None = None) -> CapabilityAttackGraph:
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root", (_source(4),))
    tool_sources = () if second_line is None else (_source(second_line),)
    tool = _node(AttackGraphNodeKind.TOOL, "tool:shell", tool_sources)
    edge_source = _source(4) if second_line is None else _source(second_line)
    edge = AttackGraphEdge(
        edge_id=attack_edge_id(
            edge_kind=AttackGraphEdgeKind.USES_TOOL,
            source_node_id=agent.node_id,
            target_node_id=tool.node_id,
            sources=(edge_source,),
        ),
        edge_kind=AttackGraphEdgeKind.USES_TOOL,
        source_node_id=agent.node_id,
        target_node_id=tool.node_id,
        sources=(edge_source,),
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


def _finding(
    *, line: int = 4, source_type: EvidenceSource = EvidenceSource.FILE
) -> Finding:
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
                source_type=source_type,
                asset_path="AGENTS.md",
                start_line=line,
                end_line=line,
                excerpt="Run a shell command.",
                content_sha256=_HASH,
            ),
        ),
        recommendations=("Require approval before execution.",),
    )


def _semantic(line: int = 4) -> tuple[SemanticAnalysisResult, SemanticEvidenceChunk]:
    chunk = build_semantic_evidence_chunk(
        asset_path="AGENTS.md",
        asset_sha256=_HASH,
        start_line=line,
        end_line=line,
        text="Run a shell command.",
    )
    request = SemanticAnalysisInput(
        analysis_id="p3-ag-05-test",
        deterministic_context=SemanticDeterministicContext(coverage_complete=True),
        evidence=(chunk,),
    )
    output = SemanticModelOutput(
        analysis_id=request.analysis_id,
        analyzed_evidence_ids=(chunk.evidence_id,),
        candidates=(
            SemanticModelCandidate(
                candidate_key="shell-execution",
                kind=SemanticCandidateKind.RISKY_INTENT,
                category=FindingCategory.CODE_EXECUTION,
                disposition=SemanticCandidateDisposition.SUPPORTED,
                summary="The asset describes shell execution.",
                evidence_ids=(chunk.evidence_id,),
            ),
        ),
    )
    invocation = SemanticInvocationProvenance(
        provider_id="offline-fixture",
        model_id="fixture-model",
        prompt_version="0.1.0",
        invocation_sha256="c" * 64,
        invocation_mode="offline_fixture",
    )
    return SemanticAnalysisContract().validate(request, output, invocation), chunk


def test_exact_path_finding_and_semantic_associations_are_value_free() -> None:
    graph = _graph()
    result, chunk = _semantic()
    report = AttackPathEvidenceAssociator().associate(
        graph, (_finding(),), result, (chunk,)
    )

    assert report.path_count == 1
    assert len(report.finding_associations) == 1
    assert len(report.semantic_associations) == 1
    assert all(
        item.relation is AttackPathAssociationRelation.DUPLICATES
        for item in report.associations
    )
    assert all(
        AttackPathAssociationBasis.EXACT_LOCATOR in item.basis
        for item in report.associations
    )
    payload = encode_attack_path_evidence_association_json(report)
    assert "Run a shell command" not in payload
    decoded = json.loads(payload)
    assert all("excerpt" not in json.dumps(value) for value in decoded["associations"])
    assert "report_only" in payload
    assert report.blocks is False
    assert report.finding_authority is False
    assert report.semantic_authority is False
    assert report.runtime_verified is False
    text = render_attack_path_evidence_association_text(report)
    assert "report_only=true" in text
    assert "Run a shell command" not in text


def test_partial_overlap_is_reported_without_false_exact_match() -> None:
    graph = _graph(second_line=6)
    report = AttackPathEvidenceAssociator().associate(graph, (_finding(),))

    finding_link = report.finding_associations[0]
    assert finding_link.relation is AttackPathAssociationRelation.PARTIALLY_SUPPORTS
    assert AttackPathAssociationBasis.PARTIAL_EVIDENCE_OVERLAP in finding_link.basis
    assert AttackPathAssociationBasis.EXACT_LOCATOR not in finding_link.basis


def test_hash_path_and_line_are_all_required_for_matching() -> None:
    graph = _graph()
    wrong_hash = _finding().model_copy(
        update={
            "evidence": (
                Evidence(
                    source_type=EvidenceSource.FILE,
                    asset_path="AGENTS.md",
                    start_line=4,
                    end_line=4,
                    excerpt="Run a shell command.",
                    content_sha256="d" * 64,
                ),
            )
        }
    )
    report = AttackPathEvidenceAssociator().associate(graph, (wrong_hash,))
    assert (
        report.finding_associations[0].relation
        is AttackPathAssociationRelation.UNMATCHED
    )
    assert report.finding_associations[0].finding_id is None

    runtime = _finding(source_type=EvidenceSource.RUNTIME)
    report = AttackPathEvidenceAssociator().associate(graph, (runtime,))
    assert (
        report.finding_associations[0].relation
        is AttackPathAssociationRelation.UNMATCHED
    )


def test_semantic_missing_evidence_fails_closed_to_unmatched() -> None:
    graph = _graph()
    result, chunk = _semantic()
    report = AttackPathEvidenceAssociator().associate(graph, (), result, ())
    link = report.semantic_associations[0]
    assert link.relation is AttackPathAssociationRelation.UNMATCHED
    assert (
        AttackPathAssociationBasis.SEMANTIC_EVIDENCE_REFERENCE_UNAVAILABLE in link.basis
    )
    assert link.semantic_evidence_refs == ()
    assert chunk.evidence_id in result.candidates[0].evidence_ids


def test_graph_source_roles_are_deduplicated_and_stable() -> None:
    graph = _graph()
    report = AttackPathEvidenceAssociator().associate(graph, (_finding(),))
    link = report.finding_associations[0]
    assert len(link.evidence_refs) == 1
    assert link.evidence_refs[0].roles == ("edge", "node")
    assert link.evidence_refs[0].source.start_line == 4


def test_no_path_source_is_explicitly_unmatched() -> None:
    agent = _node(AttackGraphNodeKind.AGENT, "agent:root")
    tool = _node(AttackGraphNodeKind.TOOL, "tool:shell")
    edge = AttackGraphEdge(
        edge_id=attack_edge_id(
            edge_kind=AttackGraphEdgeKind.USES_TOOL,
            source_node_id=agent.node_id,
            target_node_id=tool.node_id,
        ),
        edge_kind=AttackGraphEdgeKind.USES_TOOL,
        source_node_id=agent.node_id,
        target_node_id=tool.node_id,
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
    graph = CapabilityAttackGraph(
        manifest_schema_version="0.3.0",
        manifest_sha256="b" * 64,
        nodes=tuple(sorted((agent, tool), key=lambda item: item.node_id)),
        edges=(edge,),
        paths=(path,),
    )
    report = AttackPathEvidenceAssociator().associate(graph, (_finding(),))
    assert (
        report.finding_associations[0].relation
        is AttackPathAssociationRelation.UNMATCHED
    )
    assert report.finding_associations[0].basis == (
        AttackPathAssociationBasis.GRAPH_SOURCE_UNAVAILABLE,
    )


def test_association_is_replayable_and_schema_round_trips(tmp_path: Path) -> None:
    graph = _graph()
    result, chunk = _semantic()
    associator = AttackPathEvidenceAssociator()
    first = associator.associate(graph, (_finding(),), result, (chunk,))
    second = associator.associate(graph, (_finding(),), result, (chunk,))
    assert first == second
    assert canonical_attack_path_evidence_association_sha256(first) == (
        canonical_attack_path_evidence_association_sha256(second)
    )
    payload = json.loads(encode_attack_path_evidence_association_json(first))
    assert AttackPathEvidenceAssociationReport.model_validate(payload) == first
    path = export_attack_path_evidence_association_json_schema(
        tmp_path / "association.schema.json"
    )
    assert json.loads(path.read_text(encoding="utf-8"))["title"] == (
        "AttackPathEvidenceAssociationReport"
    )


def test_input_validation_and_authority_forgery_are_rejected() -> None:
    graph = _graph()
    with pytest.raises(TypeError, match="CapabilityAttackGraph"):
        AttackPathEvidenceAssociator().associate("not-a-graph")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires a SemanticAnalysisResult"):
        AttackPathEvidenceAssociator().associate(graph, (), None, (_semantic()[1],))
    report = AttackPathEvidenceAssociator().associate(graph, (_finding(),))
    payload = report.model_dump(mode="json")
    payload["blocks"] = True
    with pytest.raises(ValidationError):
        AttackPathEvidenceAssociationReport.model_validate(payload)
