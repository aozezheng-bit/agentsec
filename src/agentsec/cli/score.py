"""CLI delivery for the Integrated Agentic Score (P2-EXIT-03)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from agentsec.application import (
    AgentAnalysisError,
    AgenticScoreEngine,
    AgenticScoreError,
    AgenticScoreRequest,
)
from agentsec.artifacts import (
    AgentManifestFileReader,
    AgentManifestReadError,
    ReportArtifactFormat,
    ReportArtifactKind,
    ReportArtifactWriter,
)
from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.cli.capability import (
    CapabilityAssessmentFormatOption,
    CapabilityAssessmentOutputFormat,
)
from agentsec.cli.exit_codes import ExitCode
from agentsec.cli.manifest import (
    AgentIdOption,
    CapabilityLanguageOption,
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
from agentsec.manifests import CapabilityDiffError
from agentsec.reporting import (
    AgenticAssessmentJsonRenderer,
    AgenticAssessmentSarifRenderer,
    AgenticAssessmentTextRenderer,
)
from agentsec.risk.cvss import CvssAdapterError
from agentsec.score_context import ScoreContextError, load_score_context

BeforeManifestOption = Annotated[
    Path,
    typer.Option(
        "--before",
        help=(
            "Validated before-state Agent Manifest JSON used for the Drift comparison."
        ),
    ),
]

ScoreContextOption = Annotated[
    Path | None,
    typer.Option(
        "--context",
        help=(
            "Optional bounded agentsec-score-context JSON supplying reviewed "
            "Drift, Governance, CVSS, and accepted Gate-match context. Missing "
            "values remain conservative unknowns; they are never fabricated."
        ),
    ),
]


def register_score_command(
    application: typer.Typer,
    score_engine: AgenticScoreEngine,
    manifest_reader: AgentManifestFileReader,
    writer: ReportArtifactWriter,
    *,
    json_renderer: AgenticAssessmentJsonRenderer | None = None,
    text_renderer_factory: type[AgenticAssessmentTextRenderer] | None = None,
    sarif_renderer: AgenticAssessmentSarifRenderer | None = None,
) -> None:
    """Register the report-only `score` command."""

    effective_json_renderer = json_renderer or AgenticAssessmentJsonRenderer()
    effective_text_renderer_factory = (
        text_renderer_factory or AgenticAssessmentTextRenderer
    )
    effective_sarif_renderer = sarif_renderer or AgenticAssessmentSarifRenderer()

    @application.command("score")
    def score_command(
        before_path: BeforeManifestOption,
        project_root: ManifestProjectArgument = Path("."),
        working_directory: WorkingDirectoryOption = None,
        user_home: UserHomeOption = None,
        codex_home: CodexHomeOption = None,
        agent_id: AgentIdOption = None,
        context_path: ScoreContextOption = None,
        output_format: CapabilityAssessmentFormatOption = (
            CapabilityAssessmentOutputFormat.TEXT
        ),
        language: CapabilityLanguageOption = CapabilityRuleLanguage.EN,
        output_path: ReportOutputOption = None,
        force: ReportForceOption = False,
    ) -> None:
        """Run the complete deterministic Agentic Score chain (report-only)."""
        _require_output_for_force(output_path, force)
        try:
            before = manifest_reader.read(before_path)
        except AgentManifestReadError as error:
            typer.echo(f"Agentic Score input error: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        loaded_context = None
        if context_path is not None:
            try:
                loaded_context = load_score_context(context_path)
            except (ScoreContextError, OSError) as error:
                typer.echo(f"Agentic Score context error: {error}", err=True)
                raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        request = AgenticScoreRequest(
            project_root=project_root,
            before=before.manifest,
            agent_id=agent_id,
            working_directory=working_directory,
            user_home=user_home,
            codex_home=codex_home,
            context=loaded_context,
        )
        try:
            result = score_engine.score(request)
        except CvssAdapterError as error:
            typer.echo(f"Agentic Score context error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        except CapabilityDiffError as error:
            typer.echo(f"Agentic Score compatibility error: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except (AgentAnalysisError, AgenticScoreError) as error:
            typer.echo(f"Agentic Score analysis failed: {error}", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        except Exception:
            typer.echo("Agentic Score analysis failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from None

        if output_format is CapabilityAssessmentOutputFormat.JSON:
            rendered = effective_json_renderer.render(result)
        elif output_format is CapabilityAssessmentOutputFormat.SARIF:
            rendered = effective_sarif_renderer.render(result)
        else:
            rendered = effective_text_renderer_factory(language=language.value).render(
                result
            )
        _emit_or_write(
            rendered,
            output_path=output_path,
            force=force,
            output_format=(
                OutputFormat.JSON
                if output_format is not CapabilityAssessmentOutputFormat.TEXT
                else OutputFormat.TEXT
            ),
            artifact_format=(
                ReportArtifactFormat.SARIF
                if output_format is CapabilityAssessmentOutputFormat.SARIF
                else None
            ),
            kind=ReportArtifactKind.AGENTIC_ASSESSMENT,
            writer=writer,
        )
        if not result.complete:
            raise typer.Exit(code=ExitCode.SCAN_INCOMPLETE)


__all__ = ["register_score_command"]
