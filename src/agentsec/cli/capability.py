"""CLI delivery for deterministic Capability assessment, Diff, and Rule inventory."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from agentsec.application import (
    AgentAnalysisError,
    AgentAnalysisRequest,
    CapabilityAssessmentEngine,
    CapabilityAssessmentError,
    ManifestCapabilityChangeImpactEngine,
    ManifestCapabilityDiffEngine,
)
from agentsec.artifacts import (
    AgentManifestFileReader,
    AgentManifestReadError,
    ReportArtifactFormat,
    ReportArtifactKind,
    ReportArtifactWriter,
)
from agentsec.capability_rules import (
    CapabilityRuleLanguage,
    builtin_capability_rules,
)
from agentsec.change_impact import CapabilityChangeImpactError
from agentsec.cli.exit_codes import (
    ExitCode,
    exit_code_for_capability_assessment,
    exit_code_for_capability_change_impact,
    exit_code_for_capability_diff,
)
from agentsec.cli.manifest import (
    AgentIdOption,
    CapabilityFormatOption,
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
from agentsec.organization_policy import (
    OrganizationPolicyError,
    load_organization_policy,
    organization_gate_waivers,
)
from agentsec.policy import (
    POLICY_SCHEMA_VERSION,
    CapabilityCiPolicy,
    PolicyError,
    enforce_capability_assessment,
    load_policy,
    load_qualification_registry,
)
from agentsec.reporting import (
    CapabilityAssessmentJsonRenderer,
    CapabilityAssessmentSarifRenderer,
    CapabilityAssessmentTextRenderer,
    CapabilityChangeImpactJsonRenderer,
    CapabilityChangeImpactTextRenderer,
    CapabilityDiffJsonRenderer,
    CapabilityDiffTextRenderer,
)
from agentsec.trust import (
    TRUST_MODE_EXTERNAL_TRUST_ROOT,
    TrustError,
    resolve_trust_policy_path,
    safe_file_sha256,
    validate_expected_sha256_option,
    verify_expected_sha256,
)
from agentsec.versioning import CAPABILITY_RULE_PACK_VERSION

BeforeManifestOption = Annotated[
    Path,
    typer.Option(
        "--before",
        help="Validated before-state Agent Manifest JSON file.",
    ),
]
AfterManifestOption = Annotated[
    Path,
    typer.Option(
        "--after",
        help="Validated after-state Agent Manifest JSON file.",
    ),
]
PolicyOption = Annotated[
    Path,
    typer.Option(
        "--policy",
        help=(
            "Explicit Capability JSON or organization-level YAML Policy; "
            "enforcement is never implicit."
        ),
    ),
]
TrustRootOption = Annotated[
    Path | None,
    typer.Option(
        "--trust-root",
        help=(
            "Protected trust-artifact directory. The relative --policy path "
            "is resolved inside it and must not escape it."
        ),
    ),
]
ExpectPolicySha256Option = Annotated[
    str | None,
    typer.Option(
        "--expect-policy-sha256",
        help=(
            "Protected SHA-256 pin for the loaded Policy; mismatches fail "
            "closed with exit 3."
        ),
    ),
]
ExpectRegistrySha256Option = Annotated[
    str | None,
    typer.Option(
        "--expect-registry-sha256",
        help=(
            "Protected SHA-256 pin for the qualification registry; mismatches "
            "fail closed with exit 3."
        ),
    ),
]


class CapabilityAssessmentOutputFormat(StrEnum):
    """Output formats supported by `capability assess`."""

    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


CapabilityAssessmentFormatOption = Annotated[
    CapabilityAssessmentOutputFormat,
    typer.Option(
        "--format",
        help="Capability Assessment output format: text, json, or sarif.",
        case_sensitive=False,
    ),
]


CapabilityAssessmentOutputOption = Annotated[
    Path | None,
    typer.Option(
        "--output",
        "-o",
        help="Write Capability Assessment to a new .txt, .json, or .sarif artifact.",
    ),
]


def register_capability_commands(
    application: typer.Typer,
    assessment_engine: CapabilityAssessmentEngine,
    diff_engine: ManifestCapabilityDiffEngine,
    impact_engine: ManifestCapabilityChangeImpactEngine,
    manifest_reader: AgentManifestFileReader,
    writer: ReportArtifactWriter,
    *,
    assessment_json_renderer: CapabilityAssessmentJsonRenderer | None = None,
    assessment_sarif_renderer: CapabilityAssessmentSarifRenderer | None = None,
    diff_json_renderer: CapabilityDiffJsonRenderer | None = None,
    impact_json_renderer: CapabilityChangeImpactJsonRenderer | None = None,
) -> None:
    """Register `agentsec capability assess|enforce|diff|rules list`."""

    capability_application = typer.Typer(
        help=(
            "Assess static Agent capabilities and drift; runtime reachability is "
            "not verified."
        ),
        add_completion=False,
        no_args_is_help=True,
        rich_markup_mode="rich",
        context_settings={"help_option_names": ["-h", "--help"]},
    )
    effective_assessment_json = (
        assessment_json_renderer or CapabilityAssessmentJsonRenderer()
    )
    effective_assessment_sarif = (
        assessment_sarif_renderer or CapabilityAssessmentSarifRenderer()
    )
    effective_diff_json = diff_json_renderer or CapabilityDiffJsonRenderer()
    effective_impact_json = impact_json_renderer or CapabilityChangeImpactJsonRenderer()

    @capability_application.command("assess")
    def assess_command(
        project_root: ManifestProjectArgument = Path("."),
        working_directory: WorkingDirectoryOption = None,
        user_home: UserHomeOption = None,
        codex_home: CodexHomeOption = None,
        agent_id: AgentIdOption = None,
        output_format: CapabilityAssessmentFormatOption = (
            CapabilityAssessmentOutputFormat.TEXT
        ),
        language: CapabilityLanguageOption = CapabilityRuleLanguage.EN,
        output_path: CapabilityAssessmentOutputOption = None,
        force: ReportForceOption = False,
    ) -> None:
        """Run report-only deterministic Rules over the final static Manifest."""

        _require_output_for_force(output_path, force)
        request = AgentAnalysisRequest(
            project_root=project_root,
            working_directory=working_directory,
            user_home=user_home,
            codex_home=codex_home,
            agent_id=agent_id,
        )
        try:
            result = assessment_engine.assess(request)
        except (AgentAnalysisError, CapabilityAssessmentError) as error:
            typer.echo(f"Capability assessment failed: {error}", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        except Exception as error:
            typer.echo("Capability assessment failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

        if output_format is CapabilityAssessmentOutputFormat.JSON:
            rendered = effective_assessment_json.render(result)
        elif output_format is CapabilityAssessmentOutputFormat.SARIF:
            rendered = effective_assessment_sarif.render(result)
        else:
            rendered = CapabilityAssessmentTextRenderer(language=language).render(
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
            kind=ReportArtifactKind.CAPABILITY_ASSESSMENT,
            writer=writer,
        )
        exit_code = exit_code_for_capability_assessment(result)
        if exit_code is not ExitCode.SUCCESS:
            raise typer.Exit(code=exit_code)

    @capability_application.command("enforce")
    def enforce_command(
        project_root: ManifestProjectArgument = Path("."),
        working_directory: WorkingDirectoryOption = None,
        user_home: UserHomeOption = None,
        codex_home: CodexHomeOption = None,
        agent_id: AgentIdOption = None,
        policy_path: PolicyOption = Path("policies/capability-ci-policy.json"),
        trust_root: TrustRootOption = None,
        expect_policy_sha256: ExpectPolicySha256Option = None,
        expect_registry_sha256: ExpectRegistrySha256Option = None,
        output_format: CapabilityFormatOption = OutputFormat.TEXT,
        language: CapabilityLanguageOption = CapabilityRuleLanguage.EN,
        output_path: ReportOutputOption = None,
        force: ReportForceOption = False,
    ) -> None:
        """Evaluate an explicit deterministic CI policy over Capability findings."""
        _require_output_for_force(output_path, force)
        try:
            if expect_policy_sha256 is not None:
                validate_expected_sha256_option(expect_policy_sha256, label="policy")
            if expect_registry_sha256 is not None:
                validate_expected_sha256_option(
                    expect_registry_sha256, label="qualification registry"
                )
            effective_policy_path, trust_mode = resolve_trust_policy_path(
                policy_path, trust_root
            )
        except TrustError as error:
            typer.echo(f"Capability CI policy error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        loaded_organization_policy = None
        try:
            if effective_policy_path.suffix.lower() in {".yaml", ".yml"}:
                loaded_organization_policy = load_organization_policy(
                    effective_policy_path
                )
                organization = loaded_organization_policy.policy
                organization_qualification = organization.capability.qualification
                policy = CapabilityCiPolicy.model_validate(
                    {
                        "format": "agentsec-capability-ci-policy",
                        "schema_version": "0.2.0",
                        "policy_id": organization.policy_id,
                        "policy_version": organization.policy_version,
                        "enabled": organization.enabled,
                        "enforcement_mode": organization.enforcement_mode,
                        "fail_on": {
                            "qualified_gates": list(
                                organization.capability.qualified_gates
                            )
                        },
                        "qualification": (
                            None
                            if organization_qualification is None
                            else {
                                "registry_path": (
                                    organization_qualification.registry_path
                                ),
                                "registry_sha256": (
                                    organization_qualification.registry_sha256
                                ),
                            }
                        ),
                        "coverage": {
                            "require_complete": True,
                            "require_unknown_free": (
                                organization.coverage.require_unknown_free
                            ),
                        },
                        "safety": {
                            "allow_llm_authority": False,
                            "allow_runtime_unverified_authority": False,
                        },
                    }
                )
            else:
                policy = load_policy(effective_policy_path)
        except (OrganizationPolicyError, PolicyError, OSError, ValueError) as error:
            typer.echo(f"Capability CI policy error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        try:
            policy_source_sha256 = (
                loaded_organization_policy.sha256
                if loaded_organization_policy is not None
                else safe_file_sha256(effective_policy_path)
            )
            if expect_policy_sha256 is not None:
                verify_expected_sha256(
                    policy_source_sha256,
                    expect_policy_sha256,
                    label="policy",
                )
        except TrustError as error:
            typer.echo(f"Capability CI policy error: {error}", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        qualification_registry = None
        if policy.qualification is not None:
            try:
                registry_candidate = (
                    effective_policy_path.parent / policy.qualification.registry_path
                )
                if trust_mode == TRUST_MODE_EXTERNAL_TRUST_ROOT:
                    if trust_root is None:
                        raise PolicyError("external trust root is missing")
                    # A trust-root policy may only load a registry that
                    # resolves inside the same trust root.
                    registry_resolved = registry_candidate.resolve(strict=True)
                    trust_base = trust_root.resolve(strict=True)
                    if not registry_resolved.is_relative_to(trust_base):
                        raise PolicyError(
                            "qualification registry escapes the trust root"
                        )
                candidate = load_qualification_registry(registry_candidate)
                verify_expected_sha256(
                    candidate.sha256,
                    policy.qualification.registry_sha256,
                    label="qualification registry",
                )
                if expect_registry_sha256 is not None:
                    verify_expected_sha256(
                        candidate.sha256,
                        expect_registry_sha256,
                        label="qualification registry",
                    )
            except (PolicyError, TrustError, OSError, ValueError) as error:
                typer.echo(f"Capability CI policy error: {error}", err=True)
                raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
            qualification_registry = candidate
        if loaded_organization_policy is not None:
            gate_waivers, expired_waivers, policy_date = organization_gate_waivers(
                loaded_organization_policy.policy
            )
        else:
            gate_waivers, expired_waivers, policy_date = {}, (), None
        request = AgentAnalysisRequest(
            project_root=project_root,
            working_directory=working_directory,
            user_home=user_home,
            codex_home=codex_home,
            agent_id=agent_id,
        )
        try:
            result = assessment_engine.assess(request)
            decision = enforce_capability_assessment(
                result,
                policy,
                policy_path=effective_policy_path,
                policy_source_format=(
                    loaded_organization_policy.policy.format
                    if loaded_organization_policy is not None
                    else "agentsec-capability-ci-policy"
                ),
                policy_source_schema_version=(
                    loaded_organization_policy.policy.schema_version
                    if loaded_organization_policy is not None
                    else POLICY_SCHEMA_VERSION
                ),
                policy_source_sha256=policy_source_sha256,
                qualification_registry=qualification_registry,
                trust_mode=trust_mode,
                expected_policy_sha256=expect_policy_sha256,
                policy_digest_verified=expect_policy_sha256 is not None,
                expected_registry_sha256=expect_registry_sha256,
                registry_digest_verified=expect_registry_sha256 is not None,
                gate_waivers=gate_waivers,
                evaluated_on=policy_date,
                expired_waiver_ids=expired_waivers,
            )
        except (AgentAnalysisError, CapabilityAssessmentError) as error:
            typer.echo(f"Capability CI assessment failed: {error}", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        except Exception as error:
            typer.echo("Capability CI assessment failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error
        rendered = (
            decision.render_json()
            if output_format is OutputFormat.JSON
            else decision.render_text(language=language.value)
        )
        _emit_or_write(
            rendered,
            output_path=output_path,
            force=force,
            output_format=output_format,
            kind=ReportArtifactKind.CAPABILITY_CI_ENFORCEMENT,
            writer=writer,
        )
        if decision.exit_code is not ExitCode.SUCCESS:
            raise typer.Exit(code=decision.exit_code)

    @capability_application.command("diff")
    def diff_command(
        before_path: BeforeManifestOption,
        after_path: AfterManifestOption,
        output_format: CapabilityFormatOption = OutputFormat.TEXT,
        language: CapabilityLanguageOption = CapabilityRuleLanguage.EN,
        output_path: ReportOutputOption = None,
        force: ReportForceOption = False,
    ) -> None:
        """Compare two validated Manifests without exposing raw before/after values."""

        _require_output_for_force(output_path, force)
        try:
            before = manifest_reader.read(before_path)
            after = manifest_reader.read(after_path)
        except AgentManifestReadError as error:
            typer.echo(f"Capability Diff input error: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        try:
            result = diff_engine.compare(
                before=before.manifest,
                after=after.manifest,
            )
        except CapabilityDiffError as error:
            typer.echo(f"Capability Diff compatibility error: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Capability Diff failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

        rendered = (
            effective_diff_json.render(result)
            if output_format is OutputFormat.JSON
            else CapabilityDiffTextRenderer(language=language).render(result)
        )
        _emit_or_write(
            rendered,
            output_path=output_path,
            force=force,
            output_format=output_format,
            kind=ReportArtifactKind.CAPABILITY_DIFF,
            writer=writer,
            protected_paths=(before.path, after.path),
        )
        exit_code = exit_code_for_capability_diff(result)
        if exit_code is not ExitCode.SUCCESS:
            raise typer.Exit(code=exit_code)

    @capability_application.command("impact")
    def impact_command(
        before_path: BeforeManifestOption,
        after_path: AfterManifestOption,
        output_format: CapabilityFormatOption = OutputFormat.TEXT,
        language: CapabilityLanguageOption = CapabilityRuleLanguage.EN,
        output_path: ReportOutputOption = None,
        force: ReportForceOption = False,
    ) -> None:
        """Compare semantic before/after state and deterministic Finding Delta."""

        _require_output_for_force(output_path, force)
        try:
            before = manifest_reader.read(before_path)
            after = manifest_reader.read(after_path)
        except AgentManifestReadError as error:
            typer.echo(f"Capability Impact input error: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        try:
            result = impact_engine.compare(
                before=before.manifest,
                after=after.manifest,
            )
        except (CapabilityDiffError, CapabilityChangeImpactError) as error:
            typer.echo(f"Capability Impact error: {error}", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Capability Impact failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

        rendered = (
            effective_impact_json.render(result)
            if output_format is OutputFormat.JSON
            else CapabilityChangeImpactTextRenderer(language=language).render(result)
        )
        _emit_or_write(
            rendered,
            output_path=output_path,
            force=force,
            output_format=output_format,
            kind=ReportArtifactKind.CAPABILITY_CHANGE_IMPACT,
            writer=writer,
            protected_paths=(before.path, after.path),
        )
        exit_code = exit_code_for_capability_change_impact(result)
        if exit_code is not ExitCode.SUCCESS:
            raise typer.Exit(code=exit_code)

    rules_application = typer.Typer(
        help="Inspect the deterministic structured Capability Rule Pack.",
        add_completion=False,
        no_args_is_help=True,
        rich_markup_mode="rich",
        context_settings={"help_option_names": ["-h", "--help"]},
    )

    @rules_application.command("list")
    def rules_list_command(
        language: CapabilityLanguageOption = CapabilityRuleLanguage.EN,
    ) -> None:
        """List stable Capability Rule IDs and reviewed localized titles."""

        rules = builtin_capability_rules()
        if language is CapabilityRuleLanguage.ZH:
            typer.echo(
                f"能力规则包 {CAPABILITY_RULE_PACK_VERSION}："
                f"{len(rules)} 条确定性结构化规则"
            )
            typer.echo("规则ID\t风险类别\t中文标题")
        else:
            typer.echo(
                f"Capability Rule Pack {CAPABILITY_RULE_PACK_VERSION}: "
                f"{len(rules)} deterministic structured rules"
            )
            typer.echo("RULE_ID\tCATEGORY\tTITLE")
        for rule in rules:
            metadata = rule.metadata
            text = metadata.text_for(language)
            typer.echo(f"{metadata.rule_id}\t{metadata.category.value}\t{text.title}")

    capability_application.add_typer(rules_application, name="rules")
    application.add_typer(capability_application, name="capability")
