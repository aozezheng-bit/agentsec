"""CLI delivery for the report-only Capability Attack Graph workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from agentsec.application import (
    AgentAnalysisRequest,
    AttackGraphAnalysisEngine,
    AttackGraphAnalysisResult,
)
from agentsec.artifacts import (
    AssociationInputReadError,
    AttackPathAssociationInputReader,
    ReportArtifactKind,
    ReportArtifactWriter,
)
from agentsec.attack_graph import (
    AttackGraphBuildError,
    AttackPathEvidenceAssociator,
    AttackPathMatchError,
    encode_attack_path_evidence_association_json,
    encode_attack_path_report_json,
    render_attack_path_evidence_association_text,
    render_attack_path_report_text,
)
from agentsec.cli.exit_codes import ExitCode, exit_code_for_agent_analysis
from agentsec.cli.manifest import (
    AgentIdOption,
    CodexHomeOption,
    ManifestProjectArgument,
    ReportForceOption,
    ReportOutputOption,
    UserHomeOption,
    WorkingDirectoryOption,
    _emit_or_write,
    _require_output_for_force,
)
from agentsec.config import OutputFormat

AttackGraphFormatOption = Annotated[
    OutputFormat,
    typer.Option(
        "--format",
        help="Attack Path report format: text or json.",
        case_sensitive=False,
    ),
]


class AttackGraphCliError(RuntimeError):
    """Safe Attack Graph CLI failure without scanned-content diagnostics."""


def register_attack_graph_command(
    application: typer.Typer,
    engine: AttackGraphAnalysisEngine,
    writer: ReportArtifactWriter,
) -> None:
    """Register the top-level ``agentsec attack-graph`` command."""

    @application.command("attack-graph")
    def attack_graph_command(
        project_root: ManifestProjectArgument = Path("."),
        working_directory: WorkingDirectoryOption = None,
        user_home: UserHomeOption = None,
        codex_home: CodexHomeOption = None,
        agent_id: AgentIdOption = None,
        output_format: AttackGraphFormatOption = OutputFormat.TEXT,
        output_path: ReportOutputOption = None,
        force: ReportForceOption = False,
    ) -> None:
        """Build a report-only static Attack Path report for an Agent project."""

        _require_output_for_force(output_path, force)
        request = AgentAnalysisRequest(
            project_root=project_root,
            working_directory=working_directory,
            user_home=user_home,
            codex_home=codex_home,
            agent_id=agent_id,
        )
        try:
            result = engine.analyze(request)
            rendered = _render_report(result, output_format)
        except (AttackGraphBuildError, AttackPathMatchError) as error:
            typer.echo("Attack Graph analysis failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        except AttackGraphCliError as error:
            typer.echo(str(error), err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        except Exception as error:
            typer.echo("Attack Graph analysis failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

        _emit_or_write(
            rendered,
            output_path=output_path,
            force=force,
            output_format=output_format,
            kind=ReportArtifactKind.ATTACK_PATH_REPORT,
            writer=writer,
        )
        exit_code = exit_code_for_agent_analysis(result.analysis)
        if exit_code is not ExitCode.SUCCESS:
            raise typer.Exit(code=exit_code)


def register_attack_graph_association_command(
    application: typer.Typer,
    attack_graph_engine: AttackGraphAnalysisEngine,
    writer: ReportArtifactWriter,
    *,
    reader: AttackPathAssociationInputReader | None = None,
    associator: AttackPathEvidenceAssociator | None = None,
) -> None:
    """Register the report-only Attack Path Evidence association command."""

    effective_reader = reader or AttackPathAssociationInputReader()
    effective_associator = associator or AttackPathEvidenceAssociator()

    @application.command("attack-graph-associate")
    def attack_graph_associate_command(
        project_root: Annotated[
            Path | None,
            typer.Option(
                "--project", help="Project root to analyze instead of --graph."
            ),
        ] = None,
        graph_path: Annotated[
            Path | None,
            typer.Option(
                "--graph", help="Validated Capability Attack Graph JSON artifact."
            ),
        ] = None,
        findings_path: Annotated[
            Path | None,
            typer.Option(
                "--findings", help="Finding JSON array or assessment JSON artifact."
            ),
        ] = None,
        semantic_result_path: Annotated[
            Path | None,
            typer.Option(
                "--semantic-result",
                help="Validated Shadow Semantic Result JSON artifact.",
            ),
        ] = None,
        semantic_evidence_path: Annotated[
            Path | None,
            typer.Option(
                "--semantic-evidence",
                help="Trusted Semantic Evidence array or input-envelope JSON artifact.",
            ),
        ] = None,
        output_format: AttackGraphFormatOption = OutputFormat.TEXT,
        output_path: ReportOutputOption = None,
        force: ReportForceOption = False,
    ) -> None:
        """Associate static Attack Paths with existing Finding/Semantic Evidence."""

        _require_output_for_force(output_path, force)
        if (project_root is None) == (graph_path is None):
            typer.echo(
                "Option error: provide exactly one of --project or --graph.",
                err=True,
            )
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)
        if semantic_evidence_path is not None and semantic_result_path is None:
            typer.echo(
                "Option error: --semantic-evidence requires --semantic-result.",
                err=True,
            )
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)

        try:
            if graph_path is not None:
                graph = effective_reader.read_graph(graph_path)
                analysis_complete = True
            else:
                assert project_root is not None
                analysis = attack_graph_engine.analyze(
                    AgentAnalysisRequest(project_root=project_root)
                )
                graph = analysis.graph
                analysis_complete = analysis.analysis.complete
            findings = (
                ()
                if findings_path is None
                else effective_reader.read_findings(findings_path)
            )
            semantic_result = (
                None
                if semantic_result_path is None
                else effective_reader.read_semantic_result(semantic_result_path)
            )
            semantic_evidence = (
                ()
                if semantic_evidence_path is None
                else effective_reader.read_semantic_evidence(semantic_evidence_path)
            )
            report = effective_associator.associate(
                graph, findings, semantic_result, semantic_evidence
            )
            rendered = (
                encode_attack_path_evidence_association_json(report)
                if output_format is OutputFormat.JSON
                else render_attack_path_evidence_association_text(report)
            )
        except AssociationInputReadError as error:
            typer.echo(f"Association input error: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Attack Path Evidence association failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

        _emit_or_write(
            rendered,
            output_path=output_path,
            force=force,
            output_format=output_format,
            kind=ReportArtifactKind.ATTACK_PATH_EVIDENCE_ASSOCIATION,
            writer=writer,
        )
        if not analysis_complete:
            raise typer.Exit(code=ExitCode.SCAN_INCOMPLETE)


def _render_report(
    result: AttackGraphAnalysisResult,
    output_format: OutputFormat,
) -> str:
    """Render only the validated value-free Attack Path report."""

    if not isinstance(result, AttackGraphAnalysisResult):
        raise AttackGraphCliError("Attack Graph engine returned an invalid result")
    if output_format is OutputFormat.JSON:
        return encode_attack_path_report_json(result.report)
    return render_attack_path_report_text(result.report)


__all__ = [
    "AttackGraphCliError",
    "register_attack_graph_association_command",
    "register_attack_graph_command",
]
