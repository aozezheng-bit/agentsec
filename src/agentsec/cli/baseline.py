"""CLI registration for explicit, safe baseline creation."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from agentsec.application import (
    BaselineCreationError,
    BaselineCreationRequest,
    BaselineCreator,
)
from agentsec.baselines import BaselineFileWriter, BaselineWriteError
from agentsec.baselines.storage import DEFAULT_BASELINE_RELATIVE_PATH
from agentsec.cli.exit_codes import ExitCode
from agentsec.cli.scan import ConfigOption, ProjectRootArgument
from agentsec.config import ConfigurationError, load_project_config

OutputOption = Annotated[
    Path | None,
    typer.Option(
        "--output",
        "-o",
        help=(
            "Baseline JSON path. Defaults to <project-root>/.agentsec/baseline.json."
        ),
    ),
]
ForceOption = Annotated[
    bool,
    typer.Option(
        "--force",
        help="Replace an existing file only when it is a valid AgentSec baseline.",
    ),
]


def register_baseline_commands(
    application: typer.Typer,
    creator: BaselineCreator,
    writer: BaselineFileWriter,
) -> None:
    """Register the `baseline create` command group."""

    baseline_application = typer.Typer(
        help="Create and manage trusted Agent asset baselines.",
        add_completion=False,
        no_args_is_help=True,
        rich_markup_mode="rich",
        context_settings={"help_option_names": ["-h", "--help"]},
    )

    @baseline_application.command("create")
    def create_baseline(
        project_root: ProjectRootArgument = Path("."),
        config_path: ConfigOption = None,
        output_path: OutputOption = None,
        force: ForceOption = False,
    ) -> None:
        """Create a validated baseline from complete Markdown scan coverage."""

        try:
            loaded_config = load_project_config(
                project_root,
                config_path=config_path,
            )
        except ConfigurationError as error:
            typer.echo(f"Configuration error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error

        selected_output = (
            output_path
            if output_path is not None
            else project_root / DEFAULT_BASELINE_RELATIVE_PATH
        )
        request = BaselineCreationRequest(
            project_root=project_root,
            config=loaded_config.config,
            config_path=loaded_config.path,
            output_path=selected_output,
        )
        try:
            baseline = creator.create(request)
            result = writer.write(
                baseline,
                selected_output,
                project_root=project_root,
                config_path=loaded_config.path,
                force=force,
            )
        except (BaselineCreationError, BaselineWriteError) as error:
            typer.echo(f"Baseline error: {error}", err=True)
            raise typer.Exit(code=ExitCode.BASELINE_ERROR) from error

        action = "replaced" if result.replaced else "created"
        typer.echo(
            f"Baseline {action}: "
            f"{len(baseline.assets)} asset(s), "
            f"{result.size_bytes} byte(s), "
            f"output {str(result.path)!r}."
        )

    application.add_typer(baseline_application, name="baseline")
