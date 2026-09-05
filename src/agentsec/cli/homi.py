"""CLI packaging for the Homi report-only Pilot (P2-HOMI-07)."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from agentsec.cli.exit_codes import ExitCode
from agentsec.frameworks.homi_bundle import (
    HomiCombinedReportError,
    build_homi_combined_report,
    encode_homi_combined_report_json,
    render_homi_combined_report_html,
    render_homi_combined_report_text,
)
from agentsec.frameworks.homi_calibration import (
    build_homi_calibration_report,
    encode_homi_calibration_json,
)
from agentsec.frameworks.homi_diff import (
    HomiCapabilityDiffError,
    compare_homi_reports,
    encode_homi_capability_diff_json,
    render_homi_capability_diff_html,
    render_homi_capability_diff_text,
)
from agentsec.frameworks.homi_drift import (
    HomiDriftReport,
    build_homi_drift_report,
    encode_homi_drift_report_json,
)
from agentsec.frameworks.homi_operation_context import (
    HOMI_OPERATION_CONTEXT_FORMAT,
    HOMI_OPERATION_CONTEXT_FORMAT_VERSION,
    HomiOperationContextReport,
    build_homi_operation_context_report_from_workspace,
    encode_homi_operation_context_json,
)
from agentsec.frameworks.homi_operationality import (
    build_homi_operationality_report,
    encode_homi_operationality_json,
)
from agentsec.frameworks.homi_pilot import (
    HOMI_PILOT_FORMAT_VERSION,
    DeterministicHomiReportOnlyPilot,
    HomiPilotError,
    HomiPilotLanguage,
    HomiPilotReport,
    HomiPilotRequest,
    encode_homi_pilot_json,
    render_homi_pilot_html,
    render_homi_pilot_text,
)
from agentsec.frameworks.homi_posture import (
    build_homi_posture_report,
    encode_homi_posture_json,
)
from agentsec.frameworks.homi_provenance import (
    build_homi_build_provenance,
    encode_homi_build_provenance_json,
    render_homi_build_provenance_text,
)
from agentsec.frameworks.homi_risk import (
    HomiRiskReport,
    build_homi_risk_report,
    encode_homi_risk_report_json,
)
from agentsec.frameworks.homi_risk_state import (
    build_homi_risk_state_report,
    encode_homi_risk_state_json,
)
from agentsec.frameworks.homi_simulation import (
    HomiSafeSimulationRequest,
    HomiSimulationLanguage,
    HomiSimulationScenarioId,
    encode_homi_safe_simulation_json,
    render_homi_safe_simulation_text,
)
from agentsec.frameworks.homi_snapshot import (
    HomiSnapshot,
    HomiSnapshotVerification,
    build_homi_snapshot,
    decode_homi_snapshot_json,
    encode_homi_snapshot_json,
    encode_homi_snapshot_verification_json,
    verify_homi_snapshot,
)
from agentsec.risk.context import (
    OperationContextSet,
    canonical_operation_context_sha256,
)
from agentsec.risk.context_rules import (
    ContextRiskReport,
    DeterministicContextRuleEngine,
    decode_context_risk_json,
    encode_context_risk_json,
)
from agentsec.risk.context_score import (
    DeterministicContextRiskScoreEngine,
    encode_context_risk_score_json,
)
from agentsec.risk.runtime_attestation import (
    DeterministicRuntimeEvidenceReconciler,
    RuntimeAttestation,
    RuntimeAttestationError,
    decode_runtime_attestation_json,
    encode_evidence_reconciliation_json,
)
from agentsec.risk.runtime_trust import (
    DeterministicRuntimeTrustVerifier,
    RuntimeReplayStore,
    RuntimeTrustRegistry,
    decode_runtime_trust_registry_json,
    encode_runtime_trust_verification_json,
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


class HomiCombinedFormat(StrEnum):
    """Combined Homi report output formats."""

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
HomiSubjectIdOption = Annotated[
    str,
    typer.Option(
        "--subject-id",
        help=(
            "Stable platform-owned Agent identifier; never derived from mutable "
            "workspace files or project name."
        ),
    ),
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
HomiBaselineDirOption = Annotated[
    Path | None,
    typer.Option(
        "--baseline-dir",
        help=(
            "Optional prior Homi report directory containing Operation Context "
            "and Context Risk JSON for drift scoring."
        ),
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

    _register_snapshot_commands(homi_application, effective_pilot)

    @homi_application.command("drift")
    def drift_command(
        baseline_path: Annotated[
            Path,
            typer.Option(
                "--baseline", help="Baseline Homi Agent Snapshot JSON artifact."
            ),
        ],
        subject_id: HomiSubjectIdOption,
        workspace: HomiWorkspaceArgument = Path("."),
        output_format: HomiFormatOption = HomiCliFormat.JSON,
        output_path: HomiOutputOption = None,
        pilot_id: HomiPilotIdOption = "homi-drift-cli",
        project_name: HomiProjectNameOption = None,
        owner: HomiOwnerOption = "cli-user",
        force: HomiForceOption = False,
    ) -> None:
        """Emit the layered report-only Drift report against a Snapshot."""

        _require_force_output(output_path, force)
        try:
            baseline = decode_homi_snapshot_json(
                baseline_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as error:
            typer.echo(f"Homi drift baseline is invalid: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        request = _request_or_exit(
            workspace=workspace,
            output_anchor=output_path,
            pilot_id=pilot_id,
            project_name=project_name,
            owner=owner,
            reviewer_id=None,
            scenario_selection=None,
        )
        try:
            pilot_report = effective_pilot.run(request)
            operation_context = build_homi_operation_context_report_from_workspace(
                request.target_root,
                pilot_report,
                limits=request.limits,
            )
            current = build_homi_snapshot(
                pilot_report,
                subject_id=subject_id,
                operation_context=operation_context,
            )
            drift = build_homi_drift_report(baseline, current)
            rendered = (
                encode_homi_drift_report_json(drift)
                if output_format is HomiCliFormat.JSON
                else _render_homi_drift_text(drift)
            )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                _write_diff_output(
                    rendered,
                    output_path,
                    force=force,
                    protected_paths=(baseline_path,),
                )
        except (HomiPilotError, ValueError, OSError) as error:
            typer.echo(f"Homi drift report failed safely: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error

    @homi_application.command("risk")
    def risk_command(
        subject_id: HomiSubjectIdOption,
        workspace: HomiWorkspaceArgument = Path("."),
        baseline_path: Annotated[
            Path | None,
            typer.Option(
                "--baseline",
                help="Optional baseline Homi Agent Snapshot for drift risk.",
            ),
        ] = None,
        baseline_context_path: Annotated[
            Path | None,
            typer.Option(
                "--baseline-context",
                help=(
                    "Optional baseline homi-operation-context.json bound to "
                    "--baseline; required for numeric context-risk drift."
                ),
            ),
        ] = None,
        output_format: HomiFormatOption = HomiCliFormat.JSON,
        output_path: HomiOutputOption = None,
        pilot_id: HomiPilotIdOption = "homi-risk-cli",
        project_name: HomiProjectNameOption = None,
        owner: HomiOwnerOption = "cli-user",
        force: HomiForceOption = False,
    ) -> None:
        """Emit the unified report-only Homi Risk report."""

        _require_force_output(output_path, force)
        baseline = None
        baseline_operation_context = None
        if baseline_path is not None:
            try:
                baseline = decode_homi_snapshot_json(
                    baseline_path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as error:
                typer.echo(f"Homi risk baseline is invalid: {error}", err=True)
                raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        if baseline_context_path is not None:
            if baseline is None:
                typer.echo(
                    "Homi risk --baseline-context requires --baseline.", err=True
                )
                raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)
            try:
                baseline_operation_context = _load_homi_operation_context_report(
                    baseline_context_path
                )
            except (HomiPilotError, OSError, ValueError) as error:
                typer.echo(f"Homi risk context baseline is invalid: {error}", err=True)
                raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        request = _request_or_exit(
            workspace=workspace,
            output_anchor=output_path,
            pilot_id=pilot_id,
            project_name=project_name,
            owner=owner,
            reviewer_id=None,
            scenario_selection=None,
        )
        try:
            pilot_report = effective_pilot.run(request)
            operation_context = build_homi_operation_context_report_from_workspace(
                request.target_root,
                pilot_report,
                limits=request.limits,
            )
            risk = build_homi_risk_report(
                pilot_report,
                subject_id=subject_id,
                operation_context=operation_context,
                baseline=baseline,
                baseline_operation_context=baseline_operation_context,
            )
            rendered = (
                encode_homi_risk_report_json(risk)
                if output_format is HomiCliFormat.JSON
                else _render_homi_risk_text(risk)
            )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                _write_diff_output(
                    rendered,
                    output_path,
                    force=force,
                    protected_paths=(
                        tuple(
                            path
                            for path in (baseline_path, baseline_context_path)
                            if path is not None
                        )
                    ),
                )
        except (HomiPilotError, ValueError, OSError) as error:
            typer.echo(f"Homi risk report failed safely: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error

    @homi_application.command("fingerprint")
    def fingerprint_command(
        output_format: HomiFormatOption = HomiCliFormat.JSON,
        output_path: HomiOutputOption = None,
        force: HomiForceOption = False,
    ) -> None:
        """Print the running AgentSec Homi package/build fingerprint."""

        _require_force_output(output_path, force)
        try:
            provenance = build_homi_build_provenance(
                pilot_format_version=HOMI_PILOT_FORMAT_VERSION
            )
            rendered = (
                encode_homi_build_provenance_json(provenance)
                if output_format is HomiCliFormat.JSON
                else render_homi_build_provenance_text(provenance)
            )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                _write_diff_output(
                    rendered, output_path, force=force, protected_paths=()
                )
        except (OSError, RuntimeError, ValueError) as error:
            typer.echo(f"Homi fingerprint failed safely: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error

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
        baseline_dir: HomiBaselineDirOption = None,
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
            _write_output(
                encode_homi_build_provenance_json(
                    build_homi_build_provenance(
                        pilot_format_version=HOMI_PILOT_FORMAT_VERSION
                    )
                ),
                output_root / "homi-build-fingerprint.json",
                workspace=workspace,
                force=force,
            )
            _write_output(
                encode_homi_operationality_json(
                    build_homi_operationality_report(report)
                ),
                output_root / "homi-operationality.json",
                workspace=workspace,
                force=force,
            )
            _write_output(
                encode_homi_posture_json(build_homi_posture_report(report)),
                output_root / "homi-posture.json",
                workspace=workspace,
                force=force,
            )
            _write_output(
                encode_homi_calibration_json(build_homi_calibration_report(report)),
                output_root / "homi-calibration.json",
                workspace=workspace,
                force=force,
            )
            _write_output(
                encode_homi_risk_state_json(build_homi_risk_state_report(report)),
                output_root / "homi-risk-state.json",
                workspace=workspace,
                force=force,
            )
            _write_output(
                encode_homi_operation_context_json(
                    operation_context_report := (
                        build_homi_operation_context_report_from_workspace(
                            request.target_root,
                            report,
                            limits=request.limits,
                        )
                    )
                ),
                output_root / "homi-operation-context.json",
                workspace=workspace,
                force=force,
            )
            context_risk_report = DeterministicContextRuleEngine().run(
                operation_context_report.context_set
            )
            baseline = (
                _load_context_risk_baseline(baseline_dir)
                if baseline_dir is not None
                else None
            )
            _write_output(
                encode_context_risk_json(context_risk_report),
                output_root / "homi-context-risk.json",
                workspace=workspace,
                force=force,
            )
            _write_output(
                encode_context_risk_score_json(
                    DeterministicContextRiskScoreEngine().run(
                        operation_context_report.context_set,
                        context_risk_report,
                        baseline=baseline,
                    )
                ),
                output_root / "homi-risk-score.json",
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

    @homi_application.command("reconcile-runtime")
    def reconcile_runtime_command(
        report_dir: Annotated[
            Path,
            typer.Option(
                "--report-dir",
                help=(
                    "Directory containing homi-pilot-report.json, "
                    "homi-operation-context.json, and homi-context-risk.json."
                ),
            ),
        ],
        attestation_path: Annotated[
            Path,
            typer.Option(
                "--attestation",
                help="External sanitized Runtime Attestation JSON.",
            ),
        ],
        trust_registry_path: Annotated[
            Path | None,
            typer.Option(
                "--trust-registry",
                help="Optional trusted issuer/key registry JSON.",
            ),
        ] = None,
        replay_store_path: Annotated[
            Path | None,
            typer.Option(
                "--replay-store",
                help=(
                    "Replay store JSON; defaults to "
                    "<report-dir>/homi-runtime-replay-store.json."
                ),
            ),
        ] = None,
        output_path: Annotated[
            Path | None,
            typer.Option(
                "--output",
                "-o",
                help=(
                    "Output reconciliation JSON; defaults to "
                    "<report-dir>/homi-runtime-reconciliation.json."
                ),
            ),
        ] = None,
        force: HomiForceOption = False,
    ) -> None:
        """Reconcile external Runtime Attestation with sanitized Homi reports."""

        effective_output = output_path or (
            report_dir / "homi-runtime-reconciliation.json"
        )
        effective_trust_output = report_dir / "homi-runtime-trust-verification.json"
        effective_replay_store = replay_store_path or (
            report_dir / "homi-runtime-replay-store.json"
        )
        try:
            pilot_digest, context_set, risk_report, attestation = (
                _load_runtime_reconciliation_inputs(report_dir, attestation_path)
            )
            registry = (
                _load_runtime_trust_registry(trust_registry_path)
                if trust_registry_path is not None
                else None
            )
            _validate_runtime_binding_preflight(
                pilot_digest,
                context_set,
                risk_report,
                attestation,
            )
            trust_decision = DeterministicRuntimeTrustVerifier().verify(
                attestation,
                registry,
                replay_store=RuntimeReplayStore(effective_replay_store),
            )
            reconciliation = DeterministicRuntimeEvidenceReconciler().reconcile(
                context_set,
                risk_report,
                attestation,
                expected_agent_snapshot_sha256=pilot_digest,
                trust_decision=trust_decision,
            )
            _write_diff_output(
                encode_runtime_trust_verification_json(trust_decision),
                effective_trust_output,
                force=force,
                protected_paths=(attestation_path, trust_registry_path)
                if trust_registry_path is not None
                else (attestation_path,),
            )
            _write_diff_output(
                encode_evidence_reconciliation_json(reconciliation),
                effective_output,
                force=force,
                protected_paths=(
                    report_dir / "homi-pilot-report.json",
                    report_dir / "homi-operation-context.json",
                    report_dir / "homi-context-risk.json",
                    attestation_path,
                    effective_trust_output,
                ),
            )
            typer.echo(
                "Runtime trust verification and evidence reconciliation written to "
                f"{report_dir}"
            )
        except (
            HomiPilotError,
            HomiCapabilityDiffError,
            RuntimeAttestationError,
            ValueError,
        ) as error:
            typer.echo(
                f"Runtime evidence reconciliation input error: {error}", err=True
            )
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except OSError as error:
            typer.echo(
                "Runtime evidence reconciliation artifact output failed safely.",
                err=True,
            )
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error

    @homi_application.command("bundle")
    def bundle_command(
        pilot_path: Annotated[
            Path,
            typer.Option(
                "--pilot",
                help="Sanitized Homi Pilot JSON report for the current snapshot.",
            ),
        ],
        diff_path: Annotated[
            Path | None,
            typer.Option(
                "--diff",
                help="Optional sanitized Homi Capability Diff JSON report.",
            ),
        ] = None,
        score_path: Annotated[
            Path | None,
            typer.Option(
                "--score",
                help="Optional deterministic Agentic Score JSON report.",
            ),
        ] = None,
        output_format: Annotated[
            HomiCombinedFormat,
            typer.Option(
                "--format",
                help="Combined report output format: text, json, or html.",
                case_sensitive=False,
            ),
        ] = HomiCombinedFormat.HTML,
        language: HomiLanguageOption = HomiPilotLanguage.ZH,
        output_path: HomiOutputOption = None,
        force: HomiForceOption = False,
    ) -> None:
        """Combine a Homi snapshot, capability drift, and advisory actions."""

        _require_force_output(output_path, force)
        try:
            combined = build_homi_combined_report(pilot_path, diff_path, score_path)
            if output_format is HomiCombinedFormat.JSON:
                rendered = encode_homi_combined_report_json(combined)
            elif output_format is HomiCombinedFormat.HTML:
                rendered = render_homi_combined_report_html(
                    combined, language=language.value
                )
            else:
                rendered = render_homi_combined_report_text(
                    combined, language=language.value
                )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                _write_diff_output(
                    rendered,
                    output_path,
                    force=force,
                    protected_paths=tuple(
                        path
                        for path in (pilot_path, diff_path, score_path)
                        if path is not None
                    ),
                )
        except HomiCombinedReportError as error:
            typer.echo(f"Homi combined report input error: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except OSError as error:
            typer.echo("Homi combined report output failed safely.", err=True)
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


def _load_context_risk_baseline(
    directory: Path,
) -> tuple[OperationContextSet, ContextRiskReport]:
    """Load a prior, sanitized Homi context/risk pair for Drift scoring."""

    if not isinstance(directory, Path):
        raise HomiPilotError("--baseline-dir must be a directory path")
    if directory.is_symlink() or not directory.is_dir():
        raise HomiPilotError("--baseline-dir must be a regular directory")
    context_path = directory / "homi-operation-context.json"
    risk_path = directory / "homi-context-risk.json"
    if any(path.is_symlink() for path in (context_path, risk_path)):
        raise HomiPilotError("baseline report files cannot be symbolic links")
    try:
        context_payload = json.loads(context_path.read_text(encoding="utf-8"))
        risk_payload = risk_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HomiPilotError(
            "baseline directory must contain readable Operation Context and "
            "Context Risk JSON"
        ) from error
    if not isinstance(context_payload, dict):
        raise HomiPilotError("baseline Operation Context JSON must be an object")
    if context_payload.get("format") != "agentsec-homi-operation-context-extraction":
        raise HomiPilotError("baseline Operation Context format is invalid")
    authority = context_payload.get("authority")
    if (
        not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("runtime_verified") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise HomiPilotError("baseline Operation Context authority is invalid")
    try:
        context_set = OperationContextSet.model_validate(
            context_payload.get("context_set")
        )
        risk_report = decode_context_risk_json(risk_payload)
    except (TypeError, ValueError) as error:
        raise HomiPilotError("baseline context risk reports are invalid") from error
    if risk_report.source_context_sha256 != canonical_operation_context_sha256(
        context_set
    ):
        raise HomiPilotError("baseline Context Risk is not bound to its Context Set")
    return context_set, risk_report


def _load_homi_operation_context_report(path: Path) -> HomiOperationContextReport:
    """Load one sanitized, Pilot-bound Operation Context artifact."""

    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise HomiPilotError("baseline Operation Context must be a regular file")
    if path.stat().st_size > _HOMI_MAX_OUTPUT_BYTES:
        raise HomiPilotError("baseline Operation Context exceeds size limit")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HomiPilotError(
            "baseline Operation Context is not readable JSON"
        ) from error
    if not isinstance(payload, dict):
        raise HomiPilotError("baseline Operation Context JSON must be an object")
    authority = payload.get("authority")
    if (
        payload.get("format") != HOMI_OPERATION_CONTEXT_FORMAT
        or payload.get("format_version") != HOMI_OPERATION_CONTEXT_FORMAT_VERSION
        or payload.get("report_only") is not True
        or payload.get("runtime_verified") is not False
        or payload.get("ci_blocked") is not False
        or not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("runtime_verified") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise HomiPilotError("baseline Operation Context contract is invalid")
    try:
        context_set = OperationContextSet.model_validate(payload.get("context_set"))
        return HomiOperationContextReport(
            format=HOMI_OPERATION_CONTEXT_FORMAT,
            format_version=HOMI_OPERATION_CONTEXT_FORMAT_VERSION,
            source_report_sha256=str(payload.get("source_report_sha256", "")),
            source_report_format=str(payload.get("source_report_format", "")),
            context_set=context_set,
        )
    except (TypeError, ValueError) as error:
        raise HomiPilotError(
            "baseline Operation Context contract is invalid"
        ) from error


def _load_runtime_reconciliation_inputs(
    report_dir: Path,
    attestation_path: Path,
) -> tuple[str, OperationContextSet, ContextRiskReport, RuntimeAttestation]:
    """Load only sanitized Homi reports and external runtime evidence."""

    if not isinstance(report_dir, Path) or report_dir.is_symlink():
        raise HomiPilotError("--report-dir must be a regular directory")
    if not report_dir.is_dir():
        raise HomiPilotError("--report-dir must be a regular directory")
    report_root = report_dir.resolve(strict=True)
    pilot_path = report_root / "homi-pilot-report.json"
    context_path = report_root / "homi-operation-context.json"
    risk_path = report_root / "homi-context-risk.json"
    for path in (pilot_path, context_path, risk_path, attestation_path):
        if path.is_symlink() or not path.is_file():
            raise HomiPilotError(
                f"runtime reconciliation input is not a regular file: {path}"
            )
        if path.stat().st_size > _HOMI_MAX_OUTPUT_BYTES:
            raise HomiPilotError("runtime reconciliation input exceeds size limit")
    try:
        pilot_bytes = pilot_path.read_bytes()
        pilot_payload = json.loads(pilot_bytes.decode("utf-8"))
        context_payload = json.loads(context_path.read_text(encoding="utf-8"))
        risk_payload = risk_path.read_text(encoding="utf-8")
        attestation_payload = attestation_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HomiPilotError(
            "runtime reconciliation inputs are not readable JSON"
        ) from error
    if (
        not isinstance(pilot_payload, dict)
        or pilot_payload.get("format") != "agentsec-homi-report-only-pilot"
    ):
        raise HomiPilotError("runtime reconciliation Pilot report is invalid")
    if (
        pilot_payload.get("report_only") is not True
        or pilot_payload.get("runtime_verified") is not False
        or pilot_payload.get("ci_blocked") is not False
    ):
        raise HomiPilotError("runtime reconciliation Pilot authority is invalid")
    if (
        not isinstance(context_payload, dict)
        or context_payload.get("format") != "agentsec-homi-operation-context-extraction"
    ):
        raise HomiPilotError(
            "runtime reconciliation Operation Context report is invalid"
        )
    context_authority = context_payload.get("authority")
    if (
        not isinstance(context_authority, dict)
        or context_authority.get("report_only") is not True
        or context_authority.get("runtime_verified") is not False
        or context_authority.get("ci_blocked") is not False
    ):
        raise HomiPilotError(
            "runtime reconciliation Operation Context authority is invalid"
        )
    pilot_digest = hashlib.sha256(pilot_bytes).hexdigest()
    if context_payload.get("source_report_sha256") != pilot_digest:
        raise HomiPilotError(
            "Operation Context report is not bound to the Pilot report"
        )
    try:
        context_set = OperationContextSet.model_validate(
            context_payload.get("context_set")
        )
        risk_report = decode_context_risk_json(risk_payload)
        attestation = decode_runtime_attestation_json(attestation_payload)
    except (TypeError, ValueError) as error:
        raise HomiPilotError("runtime reconciliation reports are invalid") from error
    return pilot_digest, context_set, risk_report, attestation


def _load_runtime_trust_registry(path: Path) -> RuntimeTrustRegistry:
    if path.is_symlink() or not path.is_file():
        raise HomiPilotError("--trust-registry must be a regular file")
    if path.stat().st_size > _HOMI_MAX_OUTPUT_BYTES:
        raise HomiPilotError("--trust-registry exceeds size limit")
    try:
        return decode_runtime_trust_registry_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise HomiPilotError("--trust-registry is invalid") from error


def _validate_runtime_binding_preflight(
    pilot_digest: str,
    context_set: OperationContextSet,
    risk_report: ContextRiskReport,
    attestation: RuntimeAttestation,
) -> None:
    """Validate source bindings before replay state can be consumed."""

    context_digest = canonical_operation_context_sha256(context_set)
    if attestation.agent_snapshot_sha256 != pilot_digest:
        raise RuntimeAttestationError(
            "runtime attestation is not bound to the expected Agent Snapshot"
        )
    if risk_report.source_context_sha256 != context_digest:
        raise RuntimeAttestationError(
            "RISK-04 report is not bound to Operation Context"
        )
    if attestation.context_sha256 != context_digest:
        raise RuntimeAttestationError(
            "runtime attestation is not bound to Operation Context"
        )


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


def _register_snapshot_commands(
    parent: typer.Typer, pilot: DeterministicHomiReportOnlyPilot
) -> None:
    """Register `snapshot create|verify` under one parent command group."""

    snapshot_application = typer.Typer(
        help="Create or verify deterministic, report-only Homi Agent Snapshots.",
        add_completion=False,
        no_args_is_help=True,
        rich_markup_mode="rich",
        context_settings={"help_option_names": ["-h", "--help"]},
    )
    parent.add_typer(snapshot_application, name="snapshot")

    @snapshot_application.command("create")
    def snapshot_create_command(
        subject_id: HomiSubjectIdOption,
        workspace: HomiWorkspaceArgument = Path("."),
        output_format: HomiFormatOption = HomiCliFormat.JSON,
        output_path: HomiOutputOption = None,
        pilot_id: HomiPilotIdOption = "homi-snapshot-cli",
        project_name: HomiProjectNameOption = None,
        owner: HomiOwnerOption = "cli-user",
        force: HomiForceOption = False,
    ) -> None:
        """Write a deterministic Homi Agent Snapshot for one workspace."""

        _require_force_output(output_path, force)
        request = _request_or_exit(
            workspace=workspace,
            output_anchor=output_path,
            pilot_id=pilot_id,
            project_name=project_name,
            owner=owner,
            reviewer_id=None,
            scenario_selection=None,
        )
        try:
            pilot_report = pilot.run(request)
            operation_context = build_homi_operation_context_report_from_workspace(
                request.target_root,
                pilot_report,
                limits=request.limits,
            )
            snapshot = build_homi_snapshot(
                pilot_report,
                subject_id=subject_id,
                operation_context=operation_context,
            )
            rendered = (
                encode_homi_snapshot_json(snapshot)
                if output_format is HomiCliFormat.JSON
                else _render_homi_snapshot_text(snapshot)
            )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                _write_diff_output(
                    rendered, output_path, force=force, protected_paths=()
                )
        except (HomiPilotError, ValueError, OSError) as error:
            typer.echo(f"Homi snapshot creation failed safely: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error

    @snapshot_application.command("verify")
    def snapshot_verify_command(
        baseline_path: Annotated[
            Path,
            typer.Option(
                "--baseline", help="Baseline Homi Agent Snapshot JSON artifact."
            ),
        ],
        subject_id: HomiSubjectIdOption,
        workspace: HomiWorkspaceArgument = Path("."),
        output_format: HomiFormatOption = HomiCliFormat.JSON,
        output_path: HomiOutputOption = None,
        pilot_id: HomiPilotIdOption = "homi-snapshot-cli",
        project_name: HomiProjectNameOption = None,
        owner: HomiOwnerOption = "cli-user",
        force: HomiForceOption = False,
    ) -> None:
        """Verify one workspace against a baseline Snapshot (report-only)."""

        _require_force_output(output_path, force)
        try:
            baseline = decode_homi_snapshot_json(
                baseline_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as error:
            typer.echo(f"Homi snapshot baseline is invalid: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        request = _request_or_exit(
            workspace=workspace,
            output_anchor=output_path,
            pilot_id=pilot_id,
            project_name=project_name,
            owner=owner,
            reviewer_id=None,
            scenario_selection=None,
        )
        try:
            pilot_report = pilot.run(request)
            operation_context = build_homi_operation_context_report_from_workspace(
                request.target_root,
                pilot_report,
                limits=request.limits,
            )
            current = build_homi_snapshot(
                pilot_report,
                subject_id=subject_id,
                operation_context=operation_context,
            )
            verification = verify_homi_snapshot(baseline, current)
            rendered = (
                encode_homi_snapshot_verification_json(verification)
                if output_format is HomiCliFormat.JSON
                else _render_homi_snapshot_verification_text(verification)
            )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                _write_diff_output(
                    rendered,
                    output_path,
                    force=force,
                    protected_paths=(baseline_path,),
                )
        except (HomiPilotError, ValueError, OSError) as error:
            typer.echo(f"Homi snapshot verification failed safely: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error


def register_snapshot_commands(
    application: typer.Typer,
    pilot: DeterministicHomiReportOnlyPilot | None = None,
) -> None:
    """Register top-level `agentsec snapshot create|verify` commands."""

    _register_snapshot_commands(
        application, pilot or DeterministicHomiReportOnlyPilot()
    )


def _render_homi_snapshot_text(snapshot: HomiSnapshot) -> str:
    lines = [
        "AgentSec Homi Agent Snapshot",
        f"Subject ID: {snapshot.subject_id}",
        f"Project: {snapshot.project_name}",
        f"Snapshot digest: {snapshot.snapshot_digest}",
        f"Workspace fingerprint: {snapshot.workspace_fingerprint}",
        (
            f"Files: {len(snapshot.files)}  "
            f"Capabilities: {len(snapshot.capabilities)}  "
            f"Findings: {len(snapshot.findings)}  "
            f"Operations: {len(snapshot.operation_contexts)}  "
            f"Context Findings: {len(snapshot.context_findings)}"
        ),
        (
            "Context score: "
            f"potential={snapshot.context_score.potential_impact_score:.2f} "
            f"residual={snapshot.context_score.residual_risk_score:.2f} "
            f"posture={snapshot.context_score.current_posture}"
        ),
        "Authority: report_only=true; runtime_verified=false; ci_blocked=false",
    ]
    return "\n".join(lines) + "\n"


def _render_homi_risk_text(risk: HomiRiskReport) -> str:
    drift_score = (
        "not established"
        if risk.drift_risk_score is None
        else f"{risk.drift_risk_score:.2f} ({risk.drift_risk_level})"
    )
    lines = [
        "AgentSec Homi Unified Risk Report",
        f"Subject ID: {risk.subject_id}",
        f"Risk: {risk.risk_score:.2f} ({risk.risk_level})",
        f"Basis: {risk.risk_basis}",
        f"Reasons: {', '.join(risk.risk_reasons) or 'none'}",
        (
            f"Potential impact: {risk.potential_impact_score:.2f} "
            f"({risk.potential_impact_level})"
        ),
        f"Residual risk: {risk.residual_risk_score:.2f} ({risk.residual_risk_level})",
        f"Current posture: {risk.current_posture} (score={risk.current_posture_score})",
        f"Evidence confidence: {risk.evidence_confidence or 'not applicable'}",
        (
            f"Context: operations={risk.context_count} "
            f"risk_findings={risk.context_risk_finding_count} "
            f"coverage_findings={risk.context_coverage_finding_count} "
            f"coverage_complete={str(risk.context_coverage_complete).lower()}"
        ),
        (
            f"Declaration signals: {risk.declaration_signal_score:.2f} "
            f"({risk.declaration_signal_level}); non-authoritative"
        ),
        (
            f"Drift: {risk.drift_status}; risk={drift_score}; "
            f"direction={risk.drift_direction}"
        ),
        f"Drift basis: {risk.drift_risk_basis}",
        f"Drift reasons: {', '.join(risk.drift_reasons) or 'none'}",
        (
            f"Directional Findings: increased={len(risk.increased_finding_ids)} "
            f"decreased={len(risk.decreased_finding_ids)} "
            f"resolved={len(risk.resolved_finding_ids)}"
        ),
        (
            f"Control transitions: weakened={risk.control_weakening_count} "
            f"strengthened={risk.control_strengthening_count}"
        ),
        f"Limitations: {' | '.join(risk.limitations)}",
        (
            f"Layers: files={risk.file_change_count} "
            f"capabilities={risk.capability_change_count} "
            f"persona={risk.persona_change_count} "
            f"findings={risk.finding_delta_count} "
            f"suppressed={risk.suppressed_finding_count}"
        ),
        (
            "Authority: report_only=true; runtime_verified=false; "
            "policy_authority=false; ci_blocked=false"
        ),
        "Static report-only evidence; not runtime verification.",
    ]
    return "\n".join(lines) + "\n"


def _drift_score_number(value: object) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError("Homi drift score delta value is invalid")
    return float(value)


def _render_homi_drift_text(drift: HomiDriftReport) -> str:
    status = drift.status
    file_changes = drift.file_changes
    capability_changes = drift.capability_changes
    finding_deltas = drift.finding_deltas
    score_delta = drift.score_delta
    lines = [
        "AgentSec Homi Layered Drift Report",
        f"Subject: {drift.baseline_subject_id} -> {drift.current_subject_id}",
        f"Status: {status.value}",
        f"File changes: {len(file_changes)}",
        f"Capability changes: {len(capability_changes)}",
        f"Operation Context changes: {len(drift.operation_context_changes)}",
        f"Context Finding changes: {len(drift.context_finding_changes)}",
        f"Context Score changed: {str(drift.context_score_changed).lower()}",
        f"Risk direction: {drift.risk_direction}",
        (
            f"Directional Findings: increased={len(drift.increased_finding_ids)} "
            f"decreased={len(drift.decreased_finding_ids)} "
            f"resolved={len(drift.resolved_finding_ids)}"
        ),
        (
            f"Control transitions: weakened={drift.control_weakening_count} "
            f"strengthened={drift.control_strengthening_count}"
        ),
        (
            "Finding deltas: "
            + (
                ", ".join(
                    f"{item.rule_id}/{item.finding_id} ({item.delta_type.value})"
                    for item in finding_deltas
                    if item.delta_type.value != "unchanged"
                )
                or "none"
            )
        ),
        (
            "Presentation-only score: {before} -> {after} ({delta:+.2f})".format(
                before=_drift_score_number(score_delta["before_total"]),
                after=_drift_score_number(score_delta["after_total"]),
                delta=_drift_score_number(score_delta["delta"]),
            )
        ),
        "Authority: report_only=true; runtime_verified=false; ci_blocked=false",
        "Static drift evidence only; not runtime verification.",
    ]
    return "\n".join(lines) + "\n"


def _render_homi_snapshot_verification_text(
    verification: HomiSnapshotVerification,
) -> str:
    lines = [
        "AgentSec Homi Agent Snapshot Verification",
        f"Status: {verification.status.value}",
        (
            f"Subject: {verification.baseline_subject_id} -> "
            f"{verification.current_subject_id}"
        ),
        f"Baseline digest: {verification.baseline_snapshot_digest}",
        f"Current digest: {verification.current_snapshot_digest}",
        f"File changes: {', '.join(verification.file_changes) or 'none'}",
        f"Findings added: {', '.join(verification.findings_added) or 'none'}",
        f"Findings removed: {', '.join(verification.findings_removed) or 'none'}",
        (
            "Operation Context changes: "
            f"{', '.join(verification.operation_context_changes) or 'none'}"
        ),
        (
            "Context Findings added: "
            f"{', '.join(verification.context_findings_added) or 'none'}"
        ),
        (
            "Context Findings removed: "
            f"{', '.join(verification.context_findings_removed) or 'none'}"
        ),
        f"Context Score changed: {str(verification.context_score_changed).lower()}",
        "Authority: report_only=true; runtime_verified=false; ci_blocked=false",
    ]
    return "\n".join(lines) + "\n"


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


__all__ = [
    "HomiCliFormat",
    "HomiCombinedFormat",
    "HomiDiffFormat",
    "register_homi_commands",
    "register_snapshot_commands",
]
