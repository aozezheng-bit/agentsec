"""Typer application defining the stable AgentSec CLI root."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import Annotated, NoReturn

import typer
from typer.main import get_command

from agentsec import __version__
from agentsec.application import (
    AgentAnalysisEngine,
    AgentAnalysisPipeline,
    AgenticScoreEngine,
    AssessmentEngine,
    AttackGraphAnalysisEngine,
    BaselineCreator,
    CapabilityAssessmentEngine,
    CollectionAssessmentEngine,
    CollectionBaselineCreator,
    CollectionProjectDiffEngine,
    DeterministicAttackGraphAnalysisEngine,
    DeterministicManifestCapabilityChangeImpactEngine,
    DeterministicManifestCapabilityDiffEngine,
    ManifestCapabilityChangeImpactEngine,
    ManifestCapabilityDiffEngine,
    ProjectDiffEngine,
)
from agentsec.artifacts import AgentManifestFileReader, ReportArtifactWriter
from agentsec.baselines import BaselineFileWriter
from agentsec.cli.attack_graph import (
    register_attack_graph_association_command,
    register_attack_graph_command,
)
from agentsec.cli.baseline import register_baseline_commands
from agentsec.cli.capability import register_capability_commands
from agentsec.cli.diff import register_diff_command
from agentsec.cli.exit_codes import ExitCode
from agentsec.cli.homi import register_homi_commands
from agentsec.cli.manifest import register_manifest_command
from agentsec.cli.rules import register_rules_commands
from agentsec.cli.scan import register_scan_command
from agentsec.cli.score import register_score_command
from agentsec.cli.semantic import register_semantic_commands
from agentsec.collectors import MarkdownAssetCollector
from agentsec.frameworks.homi_pilot import DeterministicHomiReportOnlyPilot
from agentsec.reporting import (
    AssessmentJsonRenderer,
    AssessmentSarifRenderer,
    AssessmentTextRenderer,
    CapabilityAssessmentSarifRenderer,
)
from agentsec.risk import CvssHardGateEngine
from agentsec.vulnerabilities import (
    VulnerabilityAutoAssociator,
    VulnerabilityInputAssociator,
    VulnerabilityInputFileReader,
    VulnerabilitySourceFileReader,
)

APP_HELP = "Evidence-backed security diagnostics for Agent assets."
VERSION_HELP = "Print the AgentSec package version and exit."


def _version_callback(value: bool) -> None:
    """Implement the eager global ``--version`` option."""

    if value:
        typer.echo(f"agentsec {__version__}")
        raise typer.Exit()


VersionOption = Annotated[
    bool,
    typer.Option(
        "--version",
        callback=_version_callback,
        is_eager=True,
        help=VERSION_HELP,
    ),
]


def create_app(
    assessment_engine: AssessmentEngine | None = None,
    baseline_creator: BaselineCreator | None = None,
    baseline_writer: BaselineFileWriter | None = None,
    diff_engine: ProjectDiffEngine | None = None,
    *,
    agent_analysis_engine: AgentAnalysisEngine | None = None,
    capability_assessment_engine: CapabilityAssessmentEngine | None = None,
    capability_diff_engine: ManifestCapabilityDiffEngine | None = None,
    capability_impact_engine: ManifestCapabilityChangeImpactEngine | None = None,
    attack_graph_engine: AttackGraphAnalysisEngine | None = None,
    manifest_reader: AgentManifestFileReader | None = None,
    report_writer: ReportArtifactWriter | None = None,
    assessment_text_renderer: AssessmentTextRenderer | None = None,
    assessment_json_renderer: AssessmentJsonRenderer | None = None,
    assessment_sarif_renderer: AssessmentSarifRenderer | None = None,
    capability_sarif_renderer: CapabilityAssessmentSarifRenderer | None = None,
    vulnerability_input_reader: VulnerabilityInputFileReader | None = None,
    vulnerability_input_associator: VulnerabilityInputAssociator | None = None,
    vulnerability_source_reader: VulnerabilitySourceFileReader | None = None,
    vulnerability_auto_associator: VulnerabilityAutoAssociator | None = None,
    cvss_hard_gate_engine: CvssHardGateEngine | None = None,
    homi_pilot: DeterministicHomiReportOnlyPilot | None = None,
) -> typer.Typer:
    """Create the CLI with explicit application-layer dependencies."""

    application = typer.Typer(
        name="agentsec",
        help=APP_HELP,
        add_completion=False,
        invoke_without_command=True,
        no_args_is_help=False,
        rich_markup_mode="rich",
        context_settings={"help_option_names": ["-h", "--help"]},
    )

    @application.callback()
    def root(
        context: typer.Context,
        version: VersionOption = False,
    ) -> None:
        """Display help when no command is given."""

        del version
        if context.invoked_subcommand is None:
            typer.echo(context.get_help())

    @application.command("version")
    def version_command() -> None:
        """Print the AgentSec package version."""

        typer.echo(f"agentsec {__version__}")

    engine = assessment_engine
    if engine is None:
        engine = CollectionAssessmentEngine(MarkdownAssetCollector())
    creator = baseline_creator
    if creator is None:
        creator = CollectionBaselineCreator(MarkdownAssetCollector())
    writer = baseline_writer if baseline_writer is not None else BaselineFileWriter()
    project_diff_engine = diff_engine
    if project_diff_engine is None:
        project_diff_engine = CollectionProjectDiffEngine(MarkdownAssetCollector())

    register_scan_command(
        application,
        engine,
        text_renderer=assessment_text_renderer,
        json_renderer=assessment_json_renderer,
        sarif_renderer=assessment_sarif_renderer,
        vulnerability_input_reader=vulnerability_input_reader,
        vulnerability_input_associator=vulnerability_input_associator,
        vulnerability_source_reader=vulnerability_source_reader,
        vulnerability_auto_associator=vulnerability_auto_associator,
        cvss_hard_gate_engine=cvss_hard_gate_engine,
    )
    register_baseline_commands(application, creator, writer)
    register_diff_command(application, project_diff_engine)
    register_rules_commands(application)

    manifest_engine = agent_analysis_engine or AgentAnalysisPipeline()
    capability_engine = capability_assessment_engine or CapabilityAssessmentEngine(
        analysis_engine=manifest_engine
    )
    score_engine = AgenticScoreEngine(analysis_engine=manifest_engine)
    manifest_diff_engine = (
        capability_diff_engine or DeterministicManifestCapabilityDiffEngine()
    )
    manifest_impact_engine = (
        capability_impact_engine or DeterministicManifestCapabilityChangeImpactEngine()
    )
    effective_attack_graph_engine = (
        attack_graph_engine
        or DeterministicAttackGraphAnalysisEngine(analysis_engine=manifest_engine)
    )
    effective_manifest_reader = manifest_reader or AgentManifestFileReader()
    effective_report_writer = report_writer or ReportArtifactWriter()
    register_manifest_command(
        application,
        manifest_engine,
        effective_report_writer,
    )
    register_attack_graph_command(
        application,
        effective_attack_graph_engine,
        effective_report_writer,
    )
    register_attack_graph_association_command(
        application,
        effective_attack_graph_engine,
        effective_report_writer,
    )
    register_capability_commands(
        application,
        capability_engine,
        manifest_diff_engine,
        manifest_impact_engine,
        effective_manifest_reader,
        effective_report_writer,
        assessment_sarif_renderer=capability_sarif_renderer,
    )
    register_score_command(
        application,
        score_engine,
        effective_manifest_reader,
        effective_report_writer,
    )
    register_semantic_commands(application)
    register_homi_commands(application, homi_pilot)
    return application


app = create_app()


def run_cli(argv: Sequence[str] | None = None) -> int:
    """Run the root command and translate framework errors to stable codes."""

    command = get_command(app)
    arguments = list(argv) if argv is not None else None

    try:
        result = command.main(
            args=arguments,
            prog_name="agentsec",
            standalone_mode=False,
        )
    except Exception as error:
        translated_exit_code = _translate_framework_exception(error)
        if translated_exit_code is None:
            raise
        return translated_exit_code

    if isinstance(result, int):
        return result
    return int(ExitCode.SUCCESS)


def _translate_framework_exception(error: Exception) -> int | None:
    """Translate public or vendored Click/Typer exceptions without coupling.

    Recent Typer releases may vendor Click while older supported releases use
    the external package. Both expose `exit_code`, and displayable usage errors
    expose `show`. Unknown application exceptions remain unhandled.
    """

    raw_exit_code = getattr(error, "exit_code", None)
    show = getattr(error, "show", None)

    if callable(show):
        show(file=sys.stderr)
        return int(ExitCode.USAGE_ERROR)
    if isinstance(raw_exit_code, int):
        return raw_exit_code
    return None


def main() -> NoReturn:
    """Run AgentSec as an installed console or Python module entry point."""

    raise SystemExit(run_cli())
