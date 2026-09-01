"""CLI registration and stable outcome mapping for project Diff."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from agentsec.application import (
    ProjectDiffEngine,
    ProjectDiffError,
    ProjectDiffExecutionCode,
    ProjectDiffRequest,
    ProjectDiffResult,
)
from agentsec.baselines import DEFAULT_BASELINE_RELATIVE_PATH
from agentsec.cli.exit_codes import ExitCode, exit_code_for_project_diff
from agentsec.cli.scan import ConfigOption, ProjectRootArgument
from agentsec.config import ConfigurationError, OutputFormat, load_project_config
from agentsec.reporting import DiffErrorView, DiffJsonRenderer, DiffTextRenderer

BaselineOption = Annotated[
    Path | None,
    typer.Option(
        "--baseline",
        "-b",
        help=(
            "Baseline JSON path. Defaults to <project-root>/.agentsec/baseline.json."
        ),
    ),
]
FormatOption = Annotated[
    OutputFormat | None,
    typer.Option(
        "--format",
        help="Override configured Diff output format: text or json.",
        case_sensitive=False,
    ),
]


def register_diff_command(
    application: typer.Typer,
    engine: ProjectDiffEngine,
    *,
    text_renderer: DiffTextRenderer | None = None,
    json_renderer: DiffJsonRenderer | None = None,
) -> None:
    """Register `agentsec diff` against deterministic application services."""

    effective_text_renderer = (
        text_renderer if text_renderer is not None else DiffTextRenderer()
    )
    effective_json_renderer = (
        json_renderer if json_renderer is not None else DiffJsonRenderer()
    )

    @application.command("diff")
    def diff_command(
        project_root: ProjectRootArgument = Path("."),
        baseline_path: BaselineOption = None,
        config_path: ConfigOption = None,
        output_format: FormatOption = None,
    ) -> None:
        """Compare current Agent assets with a validated Baseline."""

        try:
            loaded_config = load_project_config(
                project_root,
                config_path=config_path,
            )
        except ConfigurationError as error:
            selected_format = output_format or OutputFormat.TEXT
            view = DiffErrorView(
                code="configuration_error",
                message="project configuration could not be loaded safely",
                exit_code=int(ExitCode.CONFIGURATION_ERROR),
            )
            _emit_error(
                view,
                output_format=selected_format,
                text_renderer=effective_text_renderer,
                json_renderer=effective_json_renderer,
            )
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error

        selected_format = output_format or loaded_config.config.output.format
        selected_baseline = (
            baseline_path
            if baseline_path is not None
            else project_root / DEFAULT_BASELINE_RELATIVE_PATH
        )
        request = ProjectDiffRequest(
            project_root=project_root,
            config=loaded_config.config,
            config_path=loaded_config.path,
            baseline_path=selected_baseline,
        )
        try:
            result = engine.compare(request)
        except ProjectDiffError as error:
            exit_code = _exit_code_for_error(error.code)
            view = DiffErrorView(
                code=error.code.value,
                message=str(error),
                exit_code=int(exit_code),
                coverage=error.coverage,
            )
            _emit_error(
                view,
                output_format=selected_format,
                text_renderer=effective_text_renderer,
                json_renderer=effective_json_renderer,
            )
            raise typer.Exit(code=exit_code) from error

        rendered = _render_result(
            result,
            output_format=selected_format,
            text_renderer=effective_text_renderer,
            json_renderer=effective_json_renderer,
        )
        typer.echo(rendered, nl=False)
        exit_code = exit_code_for_project_diff(result)
        if exit_code is not ExitCode.SUCCESS:
            raise typer.Exit(code=exit_code)


def _render_result(
    result: ProjectDiffResult,
    *,
    output_format: OutputFormat,
    text_renderer: DiffTextRenderer,
    json_renderer: DiffJsonRenderer,
) -> str:
    if output_format is OutputFormat.JSON:
        return json_renderer.render(result)
    return text_renderer.render(result)


def _emit_error(
    error: DiffErrorView,
    *,
    output_format: OutputFormat,
    text_renderer: DiffTextRenderer,
    json_renderer: DiffJsonRenderer,
) -> None:
    if output_format is OutputFormat.JSON:
        typer.echo(json_renderer.render_error(error), nl=False)
    else:
        typer.echo(text_renderer.render_error(error), err=True, nl=False)


def _exit_code_for_error(code: ProjectDiffExecutionCode) -> ExitCode:
    if code is ProjectDiffExecutionCode.BASELINE_FAILED:
        return ExitCode.BASELINE_ERROR
    if code is ProjectDiffExecutionCode.INCOMPLETE_CURRENT_COVERAGE:
        return ExitCode.SCAN_INCOMPLETE
    return ExitCode.REQUIRED_ANALYSIS_FAILED
