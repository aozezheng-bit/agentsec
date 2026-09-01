"""CLI packaging for the Homi report-only Pilot (P2-HOMI-07)."""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from agentsec.cli.exit_codes import ExitCode
from agentsec.frameworks.homi_diff import (
    HomiCapabilityDiffError,
    compare_homi_reports,
    encode_homi_capability_diff_json,
    render_homi_capability_diff_html,
    render_homi_capability_diff_text,
)
from agentsec.frameworks.homi_pilot import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotError,
    HomiPilotLanguage,
    HomiPilotReport,
    HomiPilotRequest,
    encode_homi_pilot_json,
    render_homi_pilot_html,
    render_homi_pilot_text,
)
from agentsec.frameworks.homi_simulation import (
    HomiSafeSimulationRequest,
    HomiSimulationLanguage,
    HomiSimulationScenarioId,
    encode_homi_safe_simulation_json,
    render_homi_safe_simulation_text,
)

_HOMI_MAX_OUTPUT_BYTES = 67_108_864


class HomiCliFormat(StrEnum):
    """Homi scan and simulation output formats."""

    TEXT = "text"
    JSON = "json"


class HomiDiffFormat(StrEnum):
    """Homi Capability Diff output formats."""

    TEXT = "text"
    JSON = "json"
    HTML = "html"


HomiWorkspaceArgument = Annotated[
    Path,
    typer.Argument(
        help="Explicit Homi workspace root; source files are treated as untrusted.",
        show_default=True,
    ),
]
HomiFormatOption = Annotated[
    HomiCliFormat,
    typer.Option(
        "--format",
        help="Output format: text or json.",
        case_sensitive=False,
    ),
]
HomiLanguageOption = Annotated[
    HomiPilotLanguage,
    typer.Option(
        "--language",
        "-l",
        help="Text language: en or zh.",
        case_sensitive=False,
    ),
]
HomiPilotIdOption = Annotated[
    str,
    typer.Option("--pilot-id", help="Stable report-only Pilot identifier."),
]
HomiProjectNameOption = Annotated[
    str | None,
    typer.Option("--project-name", help="Human-readable project name."),
]
HomiOwnerOption = Annotated[
    str,
    typer.Option("--owner", help="Project or security owner label."),
]
HomiReviewerOption = Annotated[
    str | None,
    typer.Option(
        "--reviewer-id",
        help="Comma-separated reviewer IDs; this does not attest review completion.",
    ),
]
HomiOutputOption = Annotated[
    Path | None,
    typer.Option("--output", "-o", help="Write one JSON/Text report artifact."),
]
HomiOutputDirOption = Annotated[
    Path | None,
    typer.Option(
        "--output-dir",
        help="Controlled directory for paired JSON and Markdown report artifacts.",
    ),
]
HomiForceOption = Annotated[
    bool,
    typer.Option("--force", help="Replace an existing regular output artifact."),
]
HomiHtmlOption = Annotated[
    bool,
    typer.Option(
        "--html/--no-html",
        help="Write a self-contained HTML report for direct browser display.",
    ),
]
HomiScenarioOption = Annotated[
    str | None,
    typer.Option(
        "--scenario",
        help="Optional comma-separated HOMI-SIM-001..005 selection for simulation.",
    ),
]


def register_homi_commands(
    application: typer.Typer,
    pilot: DeterministicHomiReportOnlyPilot | None = None,
) -> None:
    """Register `agentsec homi scan|report|simulate` commands."""

    homi_application = typer.Typer(
        help=(
            "Analyze an explicit Homi workspace in report-only mode; runtime "
            "actions are never executed."
        ),
        add_completion=False,
        no_args_is_help=True,
        rich_markup_mode="rich",
        context_settings={"help_option_names": ["-h", "--help"]},
    )
    effective_pilot = pilot or DeterministicHomiReportOnlyPilot()

    @homi_application.command("scan")
    def scan_command(
        workspace: HomiWorkspaceArgument = Path("."),
        output_format: HomiFormatOption = HomiCliFormat.TEXT,
        language: HomiLanguageOption = HomiPilotLanguage.EN,
        pilot_id: HomiPilotIdOption = "homi-cli-pilot",
        project_name: HomiProjectNameOption = None,
        owner: HomiOwnerOption = "cli-user",
        reviewer_id: HomiReviewerOption = None,
        output_path: HomiOutputOption = None,
        force: HomiForceOption = False,
        scenario_selection: HomiScenarioOption = None,
    ) -> None:
        """Run the complete Homi Pilot and emit one report-only artifact."""

        _require_force_output(output_path, force)
        request = _request_or_exit(
            workspace=workspace,
            output_anchor=output_path.parent if output_path is not None else None,
            pilot_id=pilot_id,
            project_name=project_name,
            owner=owner,
            reviewer_id=reviewer_id,
            scenario_selection=scenario_selection,
        )
        try:
            report = effective_pilot.run(request)
            rendered = _render_report(report, output_format, language)
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                _write_output(
                    rendered,
                    output_path,
                    workspace=workspace,
                    force=force,
                )
        except HomiPilotError as error:
            typer.echo(f"Homi Pilot configuration error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        except OSError as error:
            typer.echo("Homi Pilot artifact output failed safely.", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Homi Pilot scan failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        _exit_for_report(report)

    @homi_application.command("report")
    def report_command(
        workspace: HomiWorkspaceArgument = Path("."),
        output_dir: HomiOutputDirOption = None,
        language: HomiLanguageOption = HomiPilotLanguage.EN,
        html_output: HomiHtmlOption = True,
        pilot_id: HomiPilotIdOption = "homi-cli-pilot",
        project_name: HomiProjectNameOption = None,
        owner: HomiOwnerOption = "cli-user",
        reviewer_id: HomiReviewerOption = None,
        force: HomiForceOption = False,
        scenario_selection: HomiScenarioOption = None,
    ) -> None:
        """Write JSON, Markdown, and HTML Homi Pilot reports."""

        effective_output_dir = output_dir or _default_output_dir(workspace)
        request = _request_or_exit(
            workspace=workspace,
            output_anchor=effective_output_dir,
            pilot_id=pilot_id,
            project_name=project_name,
            owner=owner,
            reviewer_id=reviewer_id,
            scenario_selection=scenario_selection,
        )
        try:
            report = effective_pilot.run(request)
            output_root = _prepare_output_dir(effective_output_dir, workspace)
            _write_output(
                encode_homi_pilot_json(report),
                output_root / "homi-pilot-report.json",
                workspace=workspace,
                force=force,
            )
            _write_output(
                render_homi_pilot_text(report, language=language),
                output_root / "homi-pilot-report.md",
                workspace=workspace,
                force=force,
            )
            if html_output:
                _write_output(
                    render_homi_pilot_html(report, language=language),
                    output_root / "homi-pilot-report.html",
                    workspace=workspace,
                    force=force,
                )
            typer.echo(f"Homi Pilot reports written to {output_root}")
        except HomiPilotError as error:
            typer.echo(f"Homi Pilot configuration error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        except OSError as error:
            typer.echo("Homi Pilot artifact output failed safely.", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Homi Pilot report failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        _exit_for_report(report)

    @homi_application.command("diff")
    def diff_command(
        before_path: Annotated[
            Path,
            typer.Option("--before", help="Before-state Homi Pilot JSON report."),
        ],
        after_path: Annotated[
            Path,
            typer.Option("--after", help="After-state Homi Pilot JSON report."),
        ],
        output_format: Annotated[
            HomiDiffFormat,
            typer.Option(
                "--format",
                help="Output format: text, json, or html.",
                case_sensitive=False,
            ),
        ] = HomiDiffFormat.TEXT,
        language: HomiLanguageOption = HomiPilotLanguage.ZH,
        output_path: HomiOutputOption = None,
        force: HomiForceOption = False,
    ) -> None:
        """Compare two Homi Pilot reports and emit Capability/Finding Delta."""

        _require_force_output(output_path, force)
        try:
            diff = compare_homi_reports(before_path, after_path)
            if output_format is HomiDiffFormat.JSON:
                rendered = encode_homi_capability_diff_json(diff)
            elif output_format is HomiDiffFormat.HTML:
                rendered = render_homi_capability_diff_html(
                    diff,
                    language=language,
                )
            else:
                rendered = render_homi_capability_diff_text(diff)
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                _write_diff_output(
                    rendered,
                    output_path,
                    force=force,
                    protected_paths=(before_path, after_path),
                )
        except HomiCapabilityDiffError as error:
            typer.echo(f"Homi Capability Diff input error: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except OSError as error:
            typer.echo("Homi Capability Diff artifact output failed safely.", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error

    @homi_application.command("simulate")
    def simulate_command(
        workspace: HomiWorkspaceArgument = Path("."),
        output_format: HomiFormatOption = HomiCliFormat.TEXT,
        language: Annotated[
            HomiSimulationLanguage,
            typer.Option(
                "--language",
                "-l",
                help="Simulation Text language: en or zh.",
                case_sensitive=False,
            ),
        ] = HomiSimulationLanguage.EN,
        pilot_id: HomiPilotIdOption = "homi-cli-pilot",
        project_name: HomiProjectNameOption = None,
        owner: HomiOwnerOption = "cli-user",
        reviewer_id: HomiReviewerOption = None,
        output_path: HomiOutputOption = None,
        force: HomiForceOption = False,
        scenario_selection: HomiScenarioOption = None,
    ) -> None:
        """Emit only the non-executing Homi Safe Simulation report."""

        _require_force_output(output_path, force)
        request = _request_or_exit(
            workspace=workspace,
            output_anchor=output_path.parent if output_path is not None else None,
            pilot_id=pilot_id,
            project_name=project_name,
            owner=owner,
            reviewer_id=reviewer_id,
            scenario_selection=scenario_selection,
        )
        try:
            report = effective_pilot.run(request)
            rendered = (
                encode_homi_safe_simulation_json(report.simulation_result)
                if output_format is HomiCliFormat.JSON
                else render_homi_safe_simulation_text(
                    report.simulation_result,
                    language=language,
                )
            )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                _write_output(
                    rendered,
                    output_path,
                    workspace=workspace,
                    force=force,
                )
        except HomiPilotError as error:
            typer.echo(f"Homi Pilot configuration error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        except OSError as error:
            typer.echo("Homi Simulation artifact output failed safely.", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Homi Simulation failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        _exit_for_report(report)

    application.add_typer(homi_application, name="homi")


def _request_or_exit(
    *,
    workspace: Path,
    output_anchor: Path | None,
    pilot_id: str,
    project_name: str | None,
    owner: str,
    reviewer_id: str | None,
    scenario_selection: str | None,
) -> HomiPilotRequest:
    try:
        return _build_request(
            workspace=workspace,
            output_anchor=output_anchor,
            pilot_id=pilot_id,
            project_name=project_name,
            owner=owner,
            reviewer_id=reviewer_id,
            scenario_selection=scenario_selection,
        )
    except (HomiPilotError, OSError, RuntimeError, ValueError) as error:
        typer.echo(f"Homi Pilot configuration error: {error}", err=True)
        raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error


def _build_request(
    *,
    workspace: Path,
    output_anchor: Path | None,
    pilot_id: str,
    project_name: str | None,
    owner: str,
    reviewer_id: str | None,
    scenario_selection: str | None,
) -> HomiPilotRequest:
    if not isinstance(workspace, Path):
        raise HomiPilotError("workspace must be a Path")
    target = workspace.resolve(strict=True)
    anchor = output_anchor or _default_output_dir(target)
    reviewers = tuple(
        sorted(
            set(item.strip() for item in (reviewer_id or "").split(",") if item.strip())
        )
    )
    return HomiPilotRequest(
        pilot_id=pilot_id,
        project_name=project_name or target.name or "Homi Workspace",
        owner=owner,
        target_root=target,
        output_root=anchor,
        reviewer_ids=reviewers,
        simulation_request=_parse_scenarios(scenario_selection),
    )


def _parse_scenarios(value: str | None) -> HomiSafeSimulationRequest:
    if value is None or not value.strip():
        return HomiSafeSimulationRequest()
    raw_values = tuple(item.strip() for item in value.split(",") if item.strip())
    try:
        scenarios = tuple(
            sorted(
                {HomiSimulationScenarioId(item) for item in raw_values},
                key=lambda item: item.value,
            )
        )
        return HomiSafeSimulationRequest(scenarios=scenarios)
    except (TypeError, ValueError) as error:
        raise HomiPilotError(
            "--scenario must contain comma-separated HOMI-SIM-001..005 IDs"
        ) from error


def _render_report(
    report: HomiPilotReport,
    output_format: HomiCliFormat,
    language: HomiPilotLanguage,
) -> str:
    return (
        encode_homi_pilot_json(report)
        if output_format is HomiCliFormat.JSON
        else render_homi_pilot_text(report, language=language)
    )


def _exit_for_report(report: HomiPilotReport) -> None:
    if report.status.value == "partial":
        raise typer.Exit(code=ExitCode.SCAN_INCOMPLETE)


def _require_force_output(output_path: Path | None, force: bool) -> None:
    if force and output_path is None:
        typer.echo("Option error: --force requires --output.", err=True)
        raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)


def _default_output_dir(workspace: Path) -> Path:
    target = workspace.resolve(strict=True)
    return target.parent / f".{target.name or 'homi'}-agentsec-output"


def _prepare_output_dir(path: Path, workspace: Path) -> Path:
    target = workspace.resolve(strict=True)
    if path.exists() and path.is_symlink():
        raise HomiPilotError("Homi CLI output directory cannot be a symbolic link")
    candidate = path.resolve(strict=False)
    if _overlaps(target, candidate):
        raise HomiPilotError("Homi CLI output directory must be outside the workspace")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise HomiPilotError("Homi CLI output directory must be a directory")
    return path.resolve(strict=True)


def _write_output(
    content: str,
    output_path: Path,
    *,
    workspace: Path,
    force: bool,
) -> None:
    if len(content.encode("utf-8")) > _HOMI_MAX_OUTPUT_BYTES:
        raise OSError("Homi CLI output exceeds the hard size limit")
    target_root = workspace.resolve(strict=True)
    if output_path.is_symlink():
        raise HomiPilotError("Homi CLI output path cannot be a symbolic link")
    if output_path.parent.exists() and output_path.parent.is_symlink():
        raise HomiPilotError("Homi CLI output directory cannot be a symbolic link")
    target = output_path.resolve(strict=False)
    if _overlaps(target_root, target):
        raise HomiPilotError("Homi CLI output path must be outside the workspace")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    parent = output_path.parent.resolve(strict=True)
    if output_path.exists() and not force:
        raise OSError("Homi CLI output already exists; use --force to replace it")
    if output_path.exists() and not output_path.is_file():
        raise OSError("Homi CLI output path must be a regular file")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        dir=parent,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output_path)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary)
        raise


def _write_diff_output(
    content: str,
    output_path: Path,
    *,
    force: bool,
    protected_paths: tuple[Path, ...],
) -> None:
    """Write a diff artifact without allowing input reports to be overwritten."""

    if len(content.encode("utf-8")) > _HOMI_MAX_OUTPUT_BYTES:
        raise OSError("Homi Capability Diff output exceeds the hard size limit")
    if output_path.is_symlink() or output_path.parent.is_symlink():
        raise HomiCapabilityDiffError("Homi Capability Diff output cannot be a symlink")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    target = output_path.resolve(strict=False)
    protected = {path.resolve(strict=True) for path in protected_paths}
    if target in protected:
        raise HomiCapabilityDiffError("Homi Capability Diff cannot overwrite an input")
    if target.exists() and not force:
        raise OSError("Homi Capability Diff output already exists; use --force")
    if target.exists() and not target.is_file():
        raise OSError("Homi Capability Diff output must be a regular file")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        dir=output_path.parent.resolve(strict=True),
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output_path)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary)
        raise


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


__all__ = ["HomiCliFormat", "HomiDiffFormat", "register_homi_commands"]
