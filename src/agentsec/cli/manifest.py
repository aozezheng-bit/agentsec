"""CLI delivery for final Agent Manifest analysis and reporting."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from agentsec.application import (
    AgentAnalysisEngine,
    AgentAnalysisError,
    AgentAnalysisRequest,
)
from agentsec.artifacts import (
    ReportArtifactFormat,
    ReportArtifactKind,
    ReportArtifactWriteError,
    ReportArtifactWriter,
)
from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.cli.exit_codes import ExitCode, exit_code_for_agent_analysis
from agentsec.config import OutputFormat
from agentsec.reporting import ManifestJsonRenderer, ManifestTextRenderer

ManifestProjectArgument = Annotated[
    Path,
    typer.Argument(
        help="Project root containing inert Agent control assets.",
        show_default=True,
    ),
]
WorkingDirectoryOption = Annotated[
    Path | None,
    typer.Option(
        "--working-directory",
        help="Explicit working directory inside the project root.",
    ),
]
UserHomeOption = Annotated[
    Path | None,
    typer.Option(
        "--user-home",
        help="Explicit user-home root to inspect; never inferred from the process.",
    ),
]
CodexHomeOption = Annotated[
    Path | None,
    typer.Option(
        "--codex-home",
        help="Explicit Codex-home root to inspect; never inferred from the process.",
    ),
]
AgentIdOption = Annotated[
    str | None,
    typer.Option(
        "--agent-id",
        help="Stable Agent identifier used in the generated Manifest.",
    ),
]
CapabilityFormatOption = Annotated[
    OutputFormat,
    typer.Option(
        "--format",
        help="Report output format: text or json.",
        case_sensitive=False,
    ),
]
CapabilityLanguageOption = Annotated[
    CapabilityRuleLanguage,
    typer.Option(
        "--language",
        "-l",
        help="Text report language: en or zh. JSON retains canonical languages.",
        case_sensitive=False,
    ),
]
ReportOutputOption = Annotated[
    Path | None,
    typer.Option(
        "--output",
        "-o",
        help="Write to a new .txt or .json artifact.",
    ),
]
ReportForceOption = Annotated[
    bool,
    typer.Option(
        "--force",
        help="Replace only an existing valid artifact of the same report kind.",
    ),
]


def register_manifest_command(
    application: typer.Typer,
    engine: AgentAnalysisEngine,
    writer: ReportArtifactWriter,
    *,
    json_renderer: ManifestJsonRenderer | None = None,
) -> None:
    """Register the top-level `agentsec manifest` command."""

    effective_json_renderer = json_renderer or ManifestJsonRenderer()

    @application.command("manifest")
    def manifest_command(
        project_root: ManifestProjectArgument = Path("."),
        working_directory: WorkingDirectoryOption = None,
        user_home: UserHomeOption = None,
        codex_home: CodexHomeOption = None,
        agent_id: AgentIdOption = None,
        output_format: CapabilityFormatOption = OutputFormat.TEXT,
        language: CapabilityLanguageOption = CapabilityRuleLanguage.EN,
        output_path: ReportOutputOption = None,
        force: ReportForceOption = False,
    ) -> None:
        """Build a static Agent Manifest; runtime capability is not verified."""

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
        except AgentAnalysisError as error:
            typer.echo(f"Manifest analysis failed: {error}", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        except Exception as error:
            typer.echo("Manifest analysis failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

        rendered = (
            effective_json_renderer.render(result.manifest)
            if output_format is OutputFormat.JSON
            else ManifestTextRenderer(language=language).render(result)
        )
        _emit_or_write(
            rendered,
            output_path=output_path,
            force=force,
            output_format=output_format,
            kind=ReportArtifactKind.AGENT_MANIFEST,
            writer=writer,
        )
        exit_code = exit_code_for_agent_analysis(result)
        if exit_code is not ExitCode.SUCCESS:
            raise typer.Exit(code=exit_code)


def _require_output_for_force(output_path: Path | None, force: bool) -> None:
    if force and output_path is None:
        typer.echo("Option error: --force requires --output.", err=True)
        raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)


def _emit_or_write(
    rendered: str,
    *,
    output_path: Path | None,
    force: bool,
    output_format: OutputFormat,
    kind: ReportArtifactKind,
    writer: ReportArtifactWriter,
    protected_paths: tuple[Path, ...] = (),
    artifact_format: ReportArtifactFormat | None = None,
) -> None:
    if output_path is None:
        typer.echo(rendered, nl=False)
        return
    try:
        writer.write(
            rendered,
            output_path,
            kind=kind,
            output_format=(
                artifact_format
                or (
                    ReportArtifactFormat.JSON
                    if output_format is OutputFormat.JSON
                    else ReportArtifactFormat.TEXT
                )
            ),
            force=force,
            protected_paths=protected_paths,
        )
    except ReportArtifactWriteError as error:
        typer.echo(f"Artifact output error: {error}", err=True)
        raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
