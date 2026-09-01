#!/usr/bin/env python3
"""Run the P3-AG-07 Attack Path Story Demo through the production CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from agentsec.application import (
    AgentAnalysisRequest,
    CapabilityAssessmentEngine,
    DeterministicAttackGraphAnalysisEngine,
)
from agentsec.attack_graph import (
    AttackPathEvidenceAssociationReport,
    encode_attack_graph_json,
)
from agentsec.domain import Evidence, EvidenceSource, Finding, FindingCategory
from agentsec.semantic import (
    SemanticAnalysisContract,
    SemanticAnalysisInput,
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticDeterministicContext,
    SemanticInvocationProvenance,
    SemanticModelCandidate,
    SemanticModelOutput,
    build_semantic_evidence_chunk,
    encode_semantic_analysis_result_json,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = REPOSITORY_ROOT / "demos" / "attack-path-story-agent"
DEFAULT_OUTPUT_PREFIX = "agentsec-attack-path-story."


def main() -> int:
    output_root = _resolve_output_root()
    request = AgentAnalysisRequest(
        project_root=DEMO_ROOT,
        agent_id="homi-release-agent",
    )
    assessment = CapabilityAssessmentEngine().assess(request)
    graph_result = DeterministicAttackGraphAnalysisEngine().analyze(request)
    if not assessment.complete or not graph_result.analysis.complete:
        print("Attack Path Story Demo input analysis was incomplete.", file=sys.stderr)
        return 2
    if not graph_result.graph.paths:
        print("Attack Path Story Demo produced no static paths.", file=sys.stderr)
        return 1

    findings = _domain_findings(assessment)
    story_graph = graph_result.graph.model_copy(
        update={"paths": (graph_result.graph.paths[0],)}
    )
    selected_finding = _select_story_finding(findings, story_graph)
    story_findings = (selected_finding,)
    semantic_result, semantic_chunks = _semantic_fixture(story_graph, selected_finding)
    graph_path = _write_json(
        output_root / "graph.json",
        json.loads(encode_attack_graph_json(story_graph)),
    )
    findings_path = _write_json(
        output_root / "findings.json",
        [item.model_dump(mode="json") for item in story_findings],
    )
    semantic_result_path = _write_json(
        output_root / "semantic-result.json",
        json.loads(encode_semantic_analysis_result_json(semantic_result)),
    )
    semantic_evidence_path = _write_json(
        output_root / "semantic-evidence.json",
        [item.model_dump(mode="json") for item in semantic_chunks],
    )

    association_json_path = output_root / "association-report.json"
    _run_cli(
        [
            "attack-graph-associate",
            "--graph",
            str(graph_path),
            "--findings",
            str(findings_path),
            "--semantic-result",
            str(semantic_result_path),
            "--semantic-evidence",
            str(semantic_evidence_path),
            "--format",
            "json",
            "--output",
            str(association_json_path),
        ]
    )

    association_text_path = output_root / "association-report.txt"
    _run_cli(
        [
            "attack-graph-associate",
            "--graph",
            str(graph_path),
            "--findings",
            str(findings_path),
            "--semantic-result",
            str(semantic_result_path),
            "--semantic-evidence",
            str(semantic_evidence_path),
            "--format",
            "text",
            "--output",
            str(association_text_path),
        ]
    )

    report = AttackPathEvidenceAssociationReport.model_validate_json(
        association_json_path.read_text(encoding="utf-8")
    )
    text = association_text_path.read_text(encoding="utf-8")
    _validate_demo_output(report, text)
    summary_path = _write_json(
        output_root / "story-summary.json", _story_summary(report)
    )

    print("Attack Path Story Demo")
    print("=" * 22)
    print("[1] Homi-like workspace: inert AGENTS/SOUL/TOOLS/HEARTBEAT assets")
    print(
        f"[2] Static graph story slice: {len(story_graph.nodes)} nodes, "
        f"{len(story_graph.edges)} edges, {len(story_graph.paths)} path"
    )
    print(f"[3] Deterministic Finding: {selected_finding.rule_id}")
    print(f"[4] Semantic Candidate: {len(semantic_result.candidates)} (shadow-only)")
    print(f"[5] Evidence associations: {report.association_count}")
    print(f"[6] Output: {summary_path.parent}")
    print(
        "[7] Conclusion: report-only; no runtime reachability or "
        "exploitability is claimed."
    )
    return 0


def _resolve_output_root() -> Path:
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] in {"-h", "--help"}):
        if len(sys.argv) == 2 and sys.argv[1] in {"-h", "--help"}:
            print(f"Usage: {Path(sys.argv[0]).name} [OUTPUT_DIR]")
            raise SystemExit(0)
        print("Usage: run-attack-path-demo.py [OUTPUT_DIR]", file=sys.stderr)
        raise SystemExit(2)
    output_root = (
        Path(sys.argv[1]).expanduser()
        if len(sys.argv) == 2
        else Path(os.environ.get("TMPDIR", "/tmp"))
        / f"{DEFAULT_OUTPUT_PREFIX}{os.getpid()}"
    )
    if output_root.exists():
        if not output_root.is_dir() or any(output_root.iterdir()):
            print("Output directory must be new or empty.", file=sys.stderr)
            raise SystemExit(2)
    else:
        output_root.mkdir(mode=0o700, parents=True)
    output_root.chmod(0o700)
    return output_root


def _domain_findings(assessment: Any) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for item in assessment.rules.findings:
        english = next(text for text in item.texts if text.language.value == "en")
        evidence = tuple(
            Evidence(
                source_type=EvidenceSource.FILE,
                asset_path=reference.path,
                start_line=reference.start_line,
                end_line=reference.end_line,
                field=reference.field_path,
                content_sha256=reference.content_sha256,
            )
            for reference in item.evidence
        )
        findings.append(
            Finding(
                finding_id=item.finding_id,
                rule_id=item.rule_id,
                category=item.category,
                title=english.title,
                description=english.description,
                likelihood=item.likelihood,
                impact=item.impact,
                severity=item.severity,
                score=item.score,
                confidence=item.confidence,
                hard_gate=False,
                evidence=evidence,
                recommendations=english.recommendations,
            )
        )
    return tuple(sorted(findings, key=lambda item: item.finding_id))


def _select_story_finding(findings: tuple[Finding, ...], graph: Any) -> Finding:
    source_keys = {
        source.sort_key()
        for path in graph.paths
        for source in _story_graph_sources(graph, path)
    }
    for finding in findings:
        if finding.category is FindingCategory.SCAN_COVERAGE:
            continue
        if any(
            evidence.asset_path is not None
            and evidence.content_sha256 is not None
            and evidence.start_line is not None
            and evidence.end_line is not None
            and (
                evidence.asset_path,
                evidence.content_sha256,
                evidence.start_line,
                evidence.end_line,
            )
            in source_keys
            for evidence in finding.evidence
        ):
            return finding
    raise RuntimeError("demo requires a Finding overlapping the story path")


def _story_graph_sources(graph: Any, path: Any) -> tuple[Any, ...]:
    nodes = {item.node_id: item for item in graph.nodes}
    edges = {item.edge_id: item for item in graph.edges}
    sources = {
        source.sort_key(): source
        for node_id in path.node_sequence
        for source in nodes[node_id].sources
    }
    sources.update(
        {
            source.sort_key(): source
            for edge_id in path.edge_sequence
            for source in edges[edge_id].sources
        }
    )
    return tuple(sources[key] for key in sorted(sources))


def _semantic_fixture(graph: Any, finding: Finding) -> tuple[Any, tuple[Any, ...]]:
    story_path = graph.paths[0]
    sources = _story_graph_sources(graph, story_path)
    chunks = tuple(
        build_semantic_evidence_chunk(
            asset_path=source.asset_path,
            asset_sha256=source.asset_sha256,
            start_line=source.start_line,
            end_line=source.end_line,
            text="A reviewed static capability declaration is present.",
        )
        for source in sources
    )
    unmatched_chunk = build_semantic_evidence_chunk(
        asset_path="unrelated.md",
        asset_sha256="d" * 64,
        start_line=1,
        end_line=1,
        text="This evidence belongs to another asset.",
    )
    all_chunks = tuple(
        sorted((*chunks, unmatched_chunk), key=lambda item: item.sort_key())
    )
    request = SemanticAnalysisInput(
        analysis_id="p3-ag-07-story",
        deterministic_context=SemanticDeterministicContext(
            coverage_complete=True,
            finding_ids=(finding.finding_id,),
        ),
        evidence=all_chunks,
    )
    category = finding.category
    output = SemanticModelOutput(
        analysis_id=request.analysis_id,
        analyzed_evidence_ids=tuple(sorted(item.evidence_id for item in all_chunks)),
        candidates=(
            SemanticModelCandidate(
                candidate_key="static-capability-chain",
                kind=SemanticCandidateKind.CROSS_FILE_CHAIN,
                category=category,
                disposition=SemanticCandidateDisposition.SUPPORTED,
                summary="The static declarations form a reviewable capability chain.",
                evidence_ids=tuple(sorted(item.evidence_id for item in chunks)),
            ),
            SemanticModelCandidate(
                candidate_key="unrelated-evidence-check",
                kind=SemanticCandidateKind.AMBIGUITY,
                category=category,
                disposition=SemanticCandidateDisposition.UNCERTAIN,
                summary="The unrelated evidence cannot support this path.",
                evidence_ids=(unmatched_chunk.evidence_id,),
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
    result = SemanticAnalysisContract().validate(request, output, invocation)
    return result, all_chunks


def _run_cli(arguments: list[str]) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    result = subprocess.run(
        [sys.executable, "-m", "agentsec", *arguments],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print("Attack Path Story Demo CLI execution failed.", file=sys.stderr)
        if result.stderr:
            print(result.stderr.strip(), file=sys.stderr)
        raise SystemExit(1)


def _validate_demo_output(
    report: AttackPathEvidenceAssociationReport,
    text: str,
) -> None:
    if report.association_count == 0 or report.path_count == 0:
        raise SystemExit("Attack Path Story Demo produced no association evidence.")
    if not report.report_only or report.blocks or report.runtime_verified:
        raise SystemExit("Attack Path Story Demo authority boundary failed.")
    if "AgentSec Attack Path Evidence Association Report" not in text:
        raise SystemExit("Attack Path Story Demo text report title is invalid.")
    forbidden = ("LOCAL_REVIEW_TOKEN", "synthetic-demo-token", "example.invalid")
    for value in forbidden:
        if value in text:
            raise SystemExit("Attack Path Story Demo output leaked a forbidden value.")


def _story_summary(report: AttackPathEvidenceAssociationReport) -> dict[str, object]:
    relations = Counter(item.relation.value for item in report.associations)
    return {
        "format": "agentsec-attack-path-story-demo",
        "schema_version": "0.1.0",
        "story": [
            "Homi-like configuration is collected as inert text.",
            "Static capability paths are matched deterministically.",
            (
                "Existing Findings and Shadow Semantic Candidates are associated "
                "by Evidence."
            ),
            "The result is report-only and does not prove runtime behavior.",
        ],
        "paths": report.path_count,
        "associations": report.association_count,
        "relations": dict(sorted(relations.items())),
        "report_only": report.report_only,
        "blocks": report.blocks,
        "runtime_verified": report.runtime_verified,
        "authority": {
            "finding": report.finding_authority,
            "semantic": report.semantic_authority,
            "policy": report.policy_authority,
            "ci": report.ci_authority,
            "hard_gate": report.hard_gate_authority,
            "release": report.release_authority,
        },
    }


def _write_json(path: Path, payload: object) -> Path:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


if __name__ == "__main__":
    raise SystemExit(main())
