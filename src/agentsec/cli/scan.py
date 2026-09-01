"""Registration and safe final-report delivery for the scan command."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from agentsec.application import (
    AssessmentAnalysisError,
    AssessmentEngine,
    AssessmentEngineUnavailable,
    AssessmentRequest,
)
from agentsec.cli.exit_codes import ExitCode, exit_code_for_assessment
from agentsec.config import ConfigurationError, load_project_config
from agentsec.fail_on import FailOnThreshold, evaluate_assessment_fail_on
from agentsec.organization_policy import (
    OrganizationPolicyError,
    evaluate_organization_scan_policy,
    load_organization_policy,
)
from agentsec.reporting import (
    AssessmentFailOnJsonRenderer,
    AssessmentFailOnTextRenderer,
    AssessmentJsonRenderer,
    AssessmentSarifRenderer,
    AssessmentTextRenderer,
    OrganizationAssessmentJsonRenderer,
    OrganizationAssessmentTextRenderer,
    OrganizationTrustProvenance,
)
from agentsec.risk import (
    CvssHardGateEngine,
    DeterministicCvssHardGateEngine,
)
from agentsec.trust import (
    TRUST_MODE_REPOSITORY_LOCAL,
    TrustError,
    resolve_trust_policy_path,
    validate_expected_sha256_option,
    verify_expected_sha256,
)
from agentsec.vulnerabilities import (
    VulnerabilityAutoAssociator,
    VulnerabilityInputAssociator,
    VulnerabilityInputError,
    VulnerabilityInputFileReader,
    VulnerabilitySourceError,
    VulnerabilitySourceFileReader,
)

ProjectRootArgument = Annotated[
    Path,
    typer.Argument(
        help="Project root containing Agent control assets.",
        show_default=True,
    ),
]

ConfigOption = Annotated[
    Path | None,
    typer.Option(
        "--config",
        help=(
            "Explicit configuration file. Defaults to "
            "<project-root>/.agentsec/config.yaml when present."
        ),
    ),
]


class ScanOutputFormat(StrEnum):
    """CLI-only scan output formats; config schema remains text/json."""

    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


ScanFormatOption = Annotated[
    ScanOutputFormat | None,
    typer.Option(
        "--format",
        help="Override Assessment output format: text, json, or sarif.",
        case_sensitive=False,
    ),
]

FailOnOption = Annotated[
    FailOnThreshold | None,
    typer.Option(
        "--fail-on",
        help=(
            "Explicit local AgentSec Severity threshold: high or critical. "
            "Incomplete Coverage still returns exit 2."
        ),
        case_sensitive=False,
    ),
]

OrganizationPolicyOption = Annotated[
    Path | None,
    typer.Option(
        "--policy",
        help=(
            "Explicit organization-level .yaml/.yml Policy. Mutually exclusive "
            "with --fail-on."
        ),
    ),
]

ScanTrustRootOption = Annotated[
    Path | None,
    typer.Option(
        "--trust-root",
        help=(
            "Protected trust-artifact directory for the --policy file; the "
            "relative Policy path is resolved inside it and must not escape."
        ),
    ),
]

ScanExpectPolicySha256Option = Annotated[
    str | None,
    typer.Option(
        "--expect-policy-sha256",
        help=(
            "Protected SHA-256 pin for the loaded Policy; mismatches fail "
            "closed with exit 3."
        ),
    ),
]

VulnerabilityInputOption = Annotated[
    Path | None,
    typer.Option(
        "--vulnerability-input",
        help=(
            "Optional bounded JSON file containing explicit Finding-to-CVE/CWE "
            "and CVSS associations."
        ),
    ),
]


VulnerabilitySourceOption = Annotated[
    Path | None,
    typer.Option(
        "--vulnerability-source",
        help=(
            "Optional local bounded JSON vulnerability source. Supports AgentSec "
            "catalog 0.1.0 and NVD CVE JSON 2.0; exact CVE evidence matching "
            "is report-only and offline."
        ),
    ),
]


def register_scan_command(
    application: typer.Typer,
    assessment_engine: AssessmentEngine,
    *,
    text_renderer: AssessmentTextRenderer | None = None,
    json_renderer: AssessmentJsonRenderer | None = None,
    sarif_renderer: AssessmentSarifRenderer | None = None,
    vulnerability_input_reader: VulnerabilityInputFileReader | None = None,
    vulnerability_input_associator: VulnerabilityInputAssociator | None = None,
    vulnerability_source_reader: VulnerabilitySourceFileReader | None = None,
    vulnerability_auto_associator: VulnerabilityAutoAssociator | None = None,
    cvss_hard_gate_engine: CvssHardGateEngine | None = None,
) -> None:
    """Register the Phase 1 scan command and final report adapters."""

    effective_text_renderer = (
        text_renderer if text_renderer is not None else AssessmentTextRenderer()
    )
    effective_json_renderer = (
        json_renderer if json_renderer is not None else AssessmentJsonRenderer()
    )
    effective_sarif_renderer = sarif_renderer or AssessmentSarifRenderer()
    effective_fail_on_text_renderer = AssessmentFailOnTextRenderer(
        assessment_renderer=effective_text_renderer
    )
    effective_fail_on_json_renderer = AssessmentFailOnJsonRenderer(
        assessment_renderer=effective_json_renderer
    )
    effective_org_text_renderer = OrganizationAssessmentTextRenderer(
        assessment_renderer=effective_text_renderer
    )
    effective_org_json_renderer = OrganizationAssessmentJsonRenderer(
        assessment_renderer=effective_json_renderer
    )
    effective_vulnerability_reader = (
        vulnerability_input_reader
        if vulnerability_input_reader is not None
        else VulnerabilityInputFileReader()
    )
    effective_vulnerability_associator = (
        vulnerability_input_associator
        if vulnerability_input_associator is not None
        else VulnerabilityInputAssociator()
    )
    effective_vulnerability_source_reader = (
        vulnerability_source_reader
        if vulnerability_source_reader is not None
        else VulnerabilitySourceFileReader()
    )
    effective_vulnerability_auto_associator = (
        vulnerability_auto_associator
        if vulnerability_auto_associator is not None
        else VulnerabilityAutoAssociator()
    )
    effective_cvss_hard_gate_engine = (
        cvss_hard_gate_engine
        if cvss_hard_gate_engine is not None
        else DeterministicCvssHardGateEngine()
    )

    @application.command("scan")
    def scan(
        project_root: ProjectRootArgument = Path("."),
        config_path: ConfigOption = None,
        output_format: ScanFormatOption = None,
        fail_on: FailOnOption = None,
        organization_policy_path: OrganizationPolicyOption = None,
        trust_root: ScanTrustRootOption = None,
        expect_policy_sha256: ScanExpectPolicySha256Option = None,
        vulnerability_input_path: VulnerabilityInputOption = None,
        vulnerability_source_path: VulnerabilitySourceOption = None,
    ) -> None:
        """Scan a project for Agent security findings."""

        try:
            loaded_config = load_project_config(
                project_root,
                config_path=config_path,
            )
        except ConfigurationError as error:
            typer.echo(f"Configuration error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error

        if fail_on is not None and organization_policy_path is not None:
            typer.echo(
                "Policy error: --fail-on and --policy are mutually exclusive.",
                err=True,
            )
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)
        if (
            trust_root is not None or expect_policy_sha256 is not None
        ) and organization_policy_path is None:
            typer.echo(
                "Policy error: trust options require an explicit --policy.",
                err=True,
            )
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)
        try:
            if expect_policy_sha256 is not None:
                validate_expected_sha256_option(expect_policy_sha256, label="policy")
        except TrustError as error:
            typer.echo(f"Organization Policy error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        trust_mode = TRUST_MODE_REPOSITORY_LOCAL
        effective_policy_path = organization_policy_path
        try:
            if organization_policy_path is not None:
                effective_policy_path, trust_mode = resolve_trust_policy_path(
                    organization_policy_path, trust_root
                )
        except TrustError as error:
            typer.echo(f"Organization Policy error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        try:
            loaded_organization_policy = (
                load_organization_policy(effective_policy_path)
                if effective_policy_path is not None
                else None
            )
        except OrganizationPolicyError as error:
            typer.echo(f"Organization Policy error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        organization_trust = OrganizationTrustProvenance(trust_mode=trust_mode)
        if loaded_organization_policy is not None and expect_policy_sha256 is not None:
            try:
                verify_expected_sha256(
                    loaded_organization_policy.sha256,
                    expect_policy_sha256,
                    label="policy",
                )
            except TrustError as error:
                typer.echo(f"Organization Policy error: {error}", err=True)
                raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
            organization_trust = OrganizationTrustProvenance(
                trust_mode=trust_mode,
                policy_digest_pinned=True,
                policy_digest_verified=True,
                expected_policy_sha256=expect_policy_sha256,
            )

        request = AssessmentRequest(
            project_root=project_root,
            config=loaded_config.config,
            config_path=loaded_config.path,
        )

        try:
            assessment = assessment_engine.assess(request)
        except AssessmentEngineUnavailable as error:
            typer.echo(f"Scan unavailable: {error}", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        except AssessmentAnalysisError as error:
            typer.echo(f"Scan analysis failed: {error}", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

        if vulnerability_input_path is not None:
            try:
                input_result = effective_vulnerability_reader.read(
                    vulnerability_input_path
                )
                assessment = effective_vulnerability_associator.apply(
                    assessment, input_result.document
                )
            except VulnerabilityInputError as error:
                typer.echo(f"Vulnerability input error: {error}", err=True)
                raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error

        if vulnerability_source_path is not None:
            try:
                source_result = effective_vulnerability_source_reader.read(
                    vulnerability_source_path
                )
                association_result = effective_vulnerability_auto_associator.apply(
                    assessment, source_result.catalog
                )
                assessment = association_result.assessment
            except VulnerabilitySourceError as error:
                typer.echo(f"Vulnerability source error: {error}", err=True)
                raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error

        # CVSS Hard Gate evaluation is deliberately report-only. It runs after
        # all explicit and source-backed CVSS enrichment and never changes the
        # Assessment exit code or the generic AgentSec risk fields.
        assessment = effective_cvss_hard_gate_engine.apply(assessment)

        fail_on_decision = (
            evaluate_assessment_fail_on(assessment, fail_on)
            if fail_on is not None
            else None
        )
        organization_decision = (
            evaluate_organization_scan_policy(
                assessment, loaded_organization_policy.evidence
            )
            if loaded_organization_policy is not None
            else None
        )
        selected_format = output_format or ScanOutputFormat(
            loaded_config.config.output.format.value
        )
        if selected_format is ScanOutputFormat.JSON:
            if (
                loaded_organization_policy is not None
                and organization_decision is not None
            ):
                rendered = effective_org_json_renderer.render(
                    assessment,
                    loaded_organization_policy.evidence,
                    organization_decision,
                    trust=organization_trust,
                )
            elif fail_on_decision is not None:
                rendered = effective_fail_on_json_renderer.render(
                    assessment, fail_on_decision
                )
            else:
                rendered = effective_json_renderer.render(assessment)
        elif selected_format is ScanOutputFormat.SARIF:
            if (
                loaded_organization_policy is not None
                and organization_decision is not None
            ):
                rendered = effective_sarif_renderer.render(
                    assessment,
                    None,
                    loaded_organization_policy.evidence,
                    organization_decision,
                )
            elif fail_on_decision is not None:
                rendered = effective_sarif_renderer.render(assessment, fail_on_decision)
            else:
                rendered = effective_sarif_renderer.render(assessment)
        else:
            if (
                loaded_organization_policy is not None
                and organization_decision is not None
            ):
                rendered = effective_org_text_renderer.render(
                    assessment,
                    loaded_organization_policy.evidence,
                    organization_decision,
                    trust=organization_trust,
                )
            elif fail_on_decision is not None:
                rendered = effective_fail_on_text_renderer.render(
                    assessment, fail_on_decision
                )
            else:
                rendered = effective_text_renderer.render(assessment)
        typer.echo(rendered, nl=False)

        if organization_decision is not None:
            exit_code = ExitCode(organization_decision.exit_code)
        elif fail_on_decision is not None:
            exit_code = ExitCode(fail_on_decision.exit_code)
        else:
            exit_code = exit_code_for_assessment(assessment)
        if exit_code is not ExitCode.SUCCESS:
            raise typer.Exit(code=exit_code)
