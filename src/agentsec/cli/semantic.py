"""P3-04 semantic Shadow trial and evaluation CLI."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Annotated, cast

import typer
from pydantic import ValidationError

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.artifacts import (
    ReportArtifactFormat,
    ReportArtifactKind,
    ReportArtifactWriter,
)
from agentsec.cli.exit_codes import ExitCode
from agentsec.frameworks import CodexAdapter, FrameworkInspectionRequest
from agentsec.semantic import (
    LiveSemanticProvider,
    LiveSemanticProviderConfig,
    OfflineFixtureSemanticProvider,
    ProviderPromotionReport,
    SemanticAnalysisInput,
    SemanticGateCandidate,
    SemanticGateEvaluationImport,
    SemanticGateEvidenceConfidence,
    SemanticGatePilotConfig,
    SemanticGatePilotRunner,
    SemanticGatePilotStatus,
    SemanticInputBuildError,
    SemanticModelOutput,
    SemanticReportLanguage,
    SemanticShadowInvocationAdapter,
    SemanticShadowPipeline,
    SemanticTrialConfig,
    SemanticTrialError,
    TrustedSemanticInputBuilder,
    encode_semantic_evaluation_json,
    encode_semantic_gate_pilot_json,
    encode_semantic_gate_promotion_json,
    encode_semantic_gate_qualification_json,
    encode_semantic_shadow_pipeline_report_json,
    load_semantic_gate_human_corpus,
    load_semantic_trial_cases,
    load_semantic_trial_config,
    load_semantic_trial_responses,
    promote_report_only,
    qualify_semantic_gate_evaluation,
    render_semantic_evaluation_text,
    render_semantic_gate_pilot_text,
    render_semantic_gate_qualification_text,
    render_semantic_shadow_pipeline_text,
    run_semantic_trial,
)


class SemanticTrialFormat(str):
    TEXT = "text"
    JSON = "json"


CasesOption = Annotated[
    Path | None,
    typer.Option("--cases", help="Bounded semantic trial case-set JSON path."),
]
ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", help="Protected semantic trial config JSON path."),
]
ResponsesOption = Annotated[
    Path | None,
    typer.Option("--responses", help="Offline response-set JSON path."),
]
ProviderOption = Annotated[
    str,
    typer.Option("--provider", help="Provider: offline_fixture or live_https."),
]
EndpointOption = Annotated[
    str | None,
    typer.Option("--endpoint", help="Explicit HTTPS endpoint for live_https."),
]
CredentialEnvOption = Annotated[
    str | None,
    typer.Option(
        "--credential-env", help="Environment variable containing the credential."
    ),
]
ProviderIdOption = Annotated[
    str | None,
    typer.Option("--provider-id", help="Approved live Provider ID."),
]
ModelIdOption = Annotated[
    str | None,
    typer.Option("--model-id", help="Approved live Model ID."),
]
ApprovedBindingOption = Annotated[
    list[str] | None,
    typer.Option(
        "--approved-live-binding",
        help="Approved live binding as PROVIDER_ID|MODEL_ID; repeatable.",
    ),
]
AllowLiveOption = Annotated[
    bool,
    typer.Option("--allow-live", help="Explicitly permit the live Shadow Provider."),
]
OutputFormatOption = Annotated[
    str,
    typer.Option("--format", help="Output format: text or json."),
]
OutputOption = Annotated[
    Path | None,
    typer.Option("--output", "-o", help="Optional report output path (.txt or .json)."),
]
ForceOption = Annotated[
    bool,
    typer.Option("--force", help="Replace an existing valid same-kind report."),
]

AnalyzeProjectArgument = Annotated[
    Path,
    typer.Argument(help="Agent project root to analyze in Shadow-only mode."),
]
AnalyzeProviderOption = Annotated[
    str,
    typer.Option(
        "--provider",
        help="Provider: offline_fixture or live_https.",
        case_sensitive=False,
    ),
]
AnalyzeResponseOption = Annotated[
    Path | None,
    typer.Option(
        "--response",
        help="Optional bounded SemanticModelOutput JSON fixture for offline mode.",
    ),
]
AnalyzeEndpointOption = Annotated[
    str | None,
    typer.Option("--endpoint", help="Explicit HTTPS endpoint for live Shadow mode."),
]
AnalyzeCredentialEnvOption = Annotated[
    str | None,
    typer.Option(
        "--credential-env", help="Environment variable containing the credential."
    ),
]
AnalyzeProviderIdOption = Annotated[
    str | None,
    typer.Option("--provider-id", help="Approved live Provider ID."),
]
AnalyzeModelIdOption = Annotated[
    str | None,
    typer.Option("--model-id", help="Approved live Model ID."),
]
AnalyzeApprovedBindingOption = Annotated[
    list[str] | None,
    typer.Option(
        "--approved-live-binding",
        help="Approved live binding PROVIDER_ID|MODEL_ID; repeatable.",
    ),
]
AnalyzeAllowLiveOption = Annotated[
    bool,
    typer.Option("--allow-live", help="Explicitly permit the live Shadow Provider."),
]
AnalyzeLanguageOption = Annotated[
    SemanticReportLanguage,
    typer.Option("--language", help="Text report language: en or zh."),
]


def register_semantic_commands(application: typer.Typer) -> None:
    """Register the explicit report-only semantic Shadow trial command."""

    semantic_application = typer.Typer(
        help=(
            "Run a bounded semantic Shadow trial; LLM output is evidence only "
            "and never a Policy or CI decision."
        ),
        add_completion=False,
        no_args_is_help=True,
        rich_markup_mode="rich",
        context_settings={"help_option_names": ["-h", "--help"]},
    )

    @semantic_application.command("trial")
    def trial_command(
        cases_path: CasesOption = None,
        config_path: ConfigOption = None,
        responses_path: ResponsesOption = None,
        provider: ProviderOption = "offline_fixture",
        endpoint: EndpointOption = None,
        credential_env: CredentialEnvOption = None,
        provider_id: ProviderIdOption = None,
        model_id: ModelIdOption = None,
        approved_live_binding: ApprovedBindingOption = None,
        allow_live: AllowLiveOption = False,
        output_format: OutputFormatOption = "text",
        output_path: OutputOption = None,
        force: ForceOption = False,
    ) -> None:
        """Run offline replay or an explicitly approved Live Shadow trial."""

        try:
            config, config_dir = _load_or_build_config(
                cases_path=cases_path,
                config_path=config_path,
                responses_path=responses_path,
                provider=provider,
                endpoint=endpoint,
                credential_env=credential_env,
                provider_id=provider_id,
                model_id=model_id,
                approved_live_binding=approved_live_binding,
                allow_live=allow_live,
            )
            cases = load_semantic_trial_cases(
                _resolve_trial_path(config_dir, config.cases_path)
            )
            responses = None
            if config.responses_path is not None:
                responses = load_semantic_trial_responses(
                    _resolve_trial_path(config_dir, config.responses_path)
                )
            report = run_semantic_trial(config, cases=cases, responses=responses)
            rendered = _render_report(report, output_format)
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                writer = ReportArtifactWriter()
                writer.write(
                    rendered,
                    output_path,
                    kind=ReportArtifactKind.SEMANTIC_EVALUATION,
                    output_format=_parse_output_format(output_format),
                    force=force,
                    protected_paths=(
                        tuple(
                            path
                            for path in (
                                _resolve_trial_path(config_dir, config.cases_path),
                                _resolve_trial_path(config_dir, config.responses_path)
                                if config.responses_path is not None
                                else None,
                            )
                            if path is not None
                        )
                    ),
                )
                typer.echo(f"Semantic Shadow trial report written: {output_path}")
        except (SemanticTrialError, ValidationError, ValueError) as error:
            typer.echo("Semantic trial configuration/input error.", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        except OSError as error:
            typer.echo("Semantic trial artifact output failed safely.", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Semantic trial failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

    @semantic_application.command("analyze")
    def analyze_command(
        project_root: AnalyzeProjectArgument,
        provider: AnalyzeProviderOption = "offline_fixture",
        response_path: AnalyzeResponseOption = None,
        endpoint: AnalyzeEndpointOption = None,
        credential_env: AnalyzeCredentialEnvOption = None,
        provider_id: AnalyzeProviderIdOption = None,
        model_id: AnalyzeModelIdOption = None,
        approved_live_binding: AnalyzeApprovedBindingOption = None,
        allow_live: AnalyzeAllowLiveOption = False,
        output_format: OutputFormatOption = "text",
        output_path: OutputOption = None,
        force: ForceOption = False,
        language: AnalyzeLanguageOption = SemanticReportLanguage.EN,
    ) -> None:
        """Run an end-to-end Semantic Shadow analysis over one Agent project."""

        try:
            framework_adapter = CodexAdapter()
            inspection = framework_adapter.inspect(
                FrameworkInspectionRequest(project_root=project_root)
            )
            deterministic = AgentAnalysisPipeline(adapter=framework_adapter).analyze(
                AgentAnalysisRequest(project_root=project_root)
            )
            semantic_input = TrustedSemanticInputBuilder().build(
                inspection,
                deterministic.manifest,
            )
            shadow_adapter = _build_analyze_adapter(
                semantic_input,
                provider=provider,
                response_path=response_path,
                endpoint=endpoint,
                credential_env=credential_env,
                provider_id=provider_id,
                model_id=model_id,
                approved_live_binding=approved_live_binding,
                allow_live=allow_live,
            )
            report = SemanticShadowPipeline(shadow_adapter).run(
                semantic_input,
                evidence=semantic_input.evidence,
            )
            rendered = _render_shadow_pipeline_report(
                report, output_format=output_format, language=language
            )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                writer = ReportArtifactWriter()
                writer.write(
                    rendered,
                    output_path,
                    kind=ReportArtifactKind.SEMANTIC_SHADOW_PIPELINE,
                    output_format=_parse_output_format(output_format),
                    force=force,
                    protected_paths=(response_path,)
                    if response_path is not None
                    else (),
                )
                typer.echo(f"Semantic Shadow pipeline report written: {output_path}")
        except (
            SemanticInputBuildError,
            SemanticTrialError,
            ValidationError,
            ValueError,
        ) as error:
            typer.echo("Semantic analysis configuration/input error.", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        except OSError as error:
            typer.echo("Semantic analysis artifact output failed safely.", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Semantic Shadow analysis failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

    @semantic_application.command("gate-pilot")
    def gate_pilot_command(
        corpus_path: Annotated[
            Path, typer.Option("--corpus", help="Gate-scoped human corpus JSON.")
        ],
        endpoint: Annotated[
            str | None,
            typer.Option("--endpoint", help="Explicit HTTPS Provider endpoint."),
        ] = None,
        credential_env: Annotated[
            str,
            typer.Option(
                "--credential-env", help="Credential environment variable name."
            ),
        ] = "AGENTSEC_PROVIDER_API_KEY",
        provider_id: Annotated[
            str, typer.Option("--provider-id", help="Provider identifier.")
        ] = "configured-provider",
        model_id: Annotated[
            str, typer.Option("--model-id", help="Model identifier.")
        ] = "configured-model",
        candidate_path: Annotated[
            Path | None,
            typer.Option(
                "--gate-candidate", help="Optional Semantic Gate candidate JSON."
            ),
        ] = None,
        allow_live: Annotated[
            bool,
            typer.Option(
                "--allow-live", help="Explicitly opt in to live external calls."
            ),
        ] = False,
        data_residency_approved: Annotated[
            bool, typer.Option("--data-residency-approved")
        ] = False,
        retention_policy_approved: Annotated[
            bool, typer.Option("--retention-policy-approved")
        ] = False,
        cost_approved: Annotated[bool, typer.Option("--cost-approved")] = False,
        review_owner_id: Annotated[
            str | None, typer.Option("--review-owner-id")
        ] = None,
        approval_id: Annotated[str | None, typer.Option("--approval-id")] = None,
        max_cases: Annotated[int, typer.Option("--max-cases", min=1, max=512)] = 40,
        max_calls: Annotated[int, typer.Option("--max-calls", min=1, max=512)] = 40,
        timeout_ms: Annotated[
            int, typer.Option("--timeout-ms", min=1, max=120000)
        ] = 30000,
        output_format: Annotated[
            str, typer.Option("--format", help="Output format: text or json.")
        ] = "text",
        output_path: Annotated[Path | None, typer.Option("--output", "-o")] = None,
        force: Annotated[bool, typer.Option("--force")] = False,
    ) -> None:
        """Run a bounded Real Provider Semantic Gate Pilot in report-only mode."""
        if force and output_path is None:
            typer.echo("Option error: --force requires --output.", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)
        try:
            corpus = load_semantic_gate_human_corpus(corpus_path)
            candidate = None
            if candidate_path is not None:
                candidate = cast(
                    SemanticGateCandidate,
                    _load_json_model(candidate_path, SemanticGateCandidate),
                )
            config = SemanticGatePilotConfig(
                endpoint_url=endpoint,
                provider_id=provider_id,
                model_id=model_id,
                credential_env=credential_env,
                corpus_path=str(corpus_path),
                gate_candidate_path=str(candidate_path) if candidate_path else None,
                max_cases=max_cases,
                max_calls=max_calls,
                timeout_ms=timeout_ms,
                allow_live=allow_live,
                data_residency_approved=data_residency_approved,
                retention_policy_approved=retention_policy_approved,
                cost_approved=cost_approved,
                review_owner_id=review_owner_id,
                approval_id=approval_id,
            )
            report = SemanticGatePilotRunner().run(config, corpus, candidate=candidate)
            rendered = (
                encode_semantic_gate_pilot_json(report)
                if output_format.casefold() == "json"
                else render_semantic_gate_pilot_text(report)
            )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                writer = ReportArtifactWriter()
                writer.write(
                    rendered,
                    output_path,
                    kind=ReportArtifactKind.SEMANTIC_GATE_PILOT,
                    output_format=_parse_output_format(output_format),
                    force=force,
                    protected_paths=(corpus_path, candidate_path)
                    if candidate_path
                    else (corpus_path,),
                )
                typer.echo(f"Semantic Gate Pilot report written: {output_path}")
            if report.status is not SemanticGatePilotStatus.COMPLETED:
                raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)
        except (ValueError, ValidationError) as error:
            typer.echo("Semantic Gate Pilot configuration/input error.", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        except typer.Exit:
            raise
        except OSError as error:
            typer.echo("Semantic Gate Pilot artifact output failed safely.", err=True)
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Semantic Gate Pilot failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

    @semantic_application.command("gate-qualify")
    def gate_qualify_command(
        candidate_path: Annotated[
            Path, typer.Option("--candidate", help="Semantic Gate candidate JSON.")
        ],
        corpus_path: Annotated[
            Path, typer.Option("--human-corpus", help="Human Corpus JSON.")
        ],
        evaluation_import_path: Annotated[
            Path,
            typer.Option(
                "--evaluation-import", help="Bound Provider Evaluation Import JSON."
            ),
        ],
        provider_promotion_path: Annotated[
            Path | None,
            typer.Option("--provider-promotion"),
        ] = None,
        evidence_confidence_path: Annotated[
            Path | None,
            typer.Option("--evidence-confidence"),
        ] = None,
        output_format: Annotated[
            str, typer.Option("--format", help="Output format: text or json.")
        ] = "text",
        output_path: Annotated[Path | None, typer.Option("--output", "-o")] = None,
        promotion_output_path: Annotated[
            Path | None,
            typer.Option("--promotion-output"),
        ] = None,
        force: Annotated[bool, typer.Option("--force")] = False,
    ) -> None:
        """Qualify a bound Provider evaluation for a report-only Semantic Gate."""

        if force and output_path is None:
            typer.echo("Option error: --force requires --output.", err=True)
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR)
        try:
            candidate = cast(
                SemanticGateCandidate,
                _load_json_model(candidate_path, SemanticGateCandidate),
            )
            corpus = load_semantic_gate_human_corpus(corpus_path)
            evaluation_import = cast(
                SemanticGateEvaluationImport,
                _load_json_model(evaluation_import_path, SemanticGateEvaluationImport),
            )
            provider_promotion = (
                _load_json_model(provider_promotion_path, ProviderPromotionReport)
                if provider_promotion_path is not None
                else None
            )
            evidence_confidence = (
                _load_json_model(
                    evidence_confidence_path, SemanticGateEvidenceConfidence
                )
                if evidence_confidence_path is not None
                else None
            )
            report = qualify_semantic_gate_evaluation(
                candidate=candidate,
                corpus=corpus,
                evaluation_import=evaluation_import,
                provider_promotion=cast(
                    "ProviderPromotionReport | None", provider_promotion
                ),
                evidence_confidence=cast(
                    "SemanticGateEvidenceConfidence | None", evidence_confidence
                ),
            )
            rendered = (
                encode_semantic_gate_qualification_json(report)
                if output_format.casefold() == "json"
                else render_semantic_gate_qualification_text(report)
            )
            if output_path is None:
                typer.echo(rendered, nl=False)
            else:
                ReportArtifactWriter().write(
                    rendered,
                    output_path,
                    kind=ReportArtifactKind.SEMANTIC_GATE_QUALIFICATION,
                    output_format=_parse_output_format(output_format),
                    force=force,
                    protected_paths=(
                        candidate_path,
                        corpus_path,
                        evaluation_import_path,
                    ),
                )
                typer.echo(f"Semantic Gate qualification written: {output_path}")
            if promotion_output_path is not None:
                promotion = promote_report_only(report)
                if promotion_output_path.exists() or promotion_output_path.is_symlink():
                    raise ValueError("promotion output already exists")
                promotion_output_path.parent.mkdir(parents=True, exist_ok=True)
                promotion_output_path.write_text(
                    encode_semantic_gate_promotion_json(promotion), encoding="utf-8"
                )
                promotion_output_path.chmod(0o600)
                typer.echo(
                    f"Semantic Gate report-only promotion written: "
                    f"{promotion_output_path}"
                )
        except (ValueError, ValidationError) as error:
            typer.echo(
                "Semantic Gate qualification configuration/input error.", err=True
            )
            raise typer.Exit(code=ExitCode.CONFIGURATION_ERROR) from error
        except OSError as error:
            typer.echo(
                "Semantic Gate qualification artifact output failed safely.", err=True
            )
            raise typer.Exit(code=ExitCode.ARTIFACT_ERROR) from error
        except Exception as error:
            typer.echo("Semantic Gate qualification failed safely.", err=True)
            raise typer.Exit(code=ExitCode.REQUIRED_ANALYSIS_FAILED) from error

    application.add_typer(semantic_application, name="semantic")


def _build_analyze_adapter(
    semantic_input: SemanticAnalysisInput,
    *,
    provider: str,
    response_path: Path | None,
    endpoint: str | None,
    credential_env: str | None,
    provider_id: str | None,
    model_id: str | None,
    approved_live_binding: list[str] | None,
    allow_live: bool,
) -> SemanticShadowInvocationAdapter:
    """Build an explicitly bounded offline or live Shadow adapter."""

    parsed_provider = provider.casefold()
    if parsed_provider == "offline_fixture":
        output = (
            _load_model_output(response_path)
            if response_path is not None
            else SemanticModelOutput(
                analysis_id=semantic_input.analysis_id,
                analyzed_evidence_ids=tuple(
                    item.evidence_id for item in semantic_input.evidence
                ),
                candidates=(),
                limitations=("Offline fixture emitted no semantic candidates.",),
            )
        )
        return SemanticShadowInvocationAdapter(
            provider=OfflineFixtureSemanticProvider(output=output)
        )
    if parsed_provider != "live_https":
        raise ValueError(
            "semantic analyze provider must be offline_fixture or live_https"
        )
    if not allow_live:
        raise ValueError("live semantic analyze requires --allow-live")
    if (
        endpoint is None
        or credential_env is None
        or provider_id is None
        or model_id is None
    ):
        raise ValueError(
            "live semantic analyze requires endpoint, credential, Provider, and Model"
        )
    bindings = tuple(_parse_binding(item) for item in (approved_live_binding or []))
    provider_instance = LiveSemanticProvider(
        LiveSemanticProviderConfig(
            endpoint_url=endpoint,
            credential_env=credential_env,
            provider_id=provider_id,
            model_id=model_id,
        )
    )
    return SemanticShadowInvocationAdapter(
        provider=provider_instance,
        allow_live_provider=True,
        approved_live_bindings=bindings,
    )


def _load_model_output(path: Path) -> SemanticModelOutput:
    """Read one bounded non-symlink model-output fixture without echoing it."""

    if path.suffix.lower() != ".json" or path.is_symlink():
        raise ValueError("semantic response fixture must be a regular .json file")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 131_072:
            raise ValueError("semantic response fixture exceeds the safe file limit")
        raw = os.read(descriptor, metadata.st_size + 1)
    except OSError as error:
        raise ValueError(
            "semantic response fixture could not be read safely"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > 131_072:
        raise ValueError("semantic response fixture exceeds the safe file limit")
    try:
        return SemanticModelOutput.model_validate_json(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(
            "semantic response fixture failed strict validation"
        ) from error


def _render_shadow_pipeline_report(
    report: object,
    *,
    output_format: str,
    language: SemanticReportLanguage,
) -> str:
    from agentsec.semantic import SemanticShadowPipelineReport

    if not isinstance(report, SemanticShadowPipelineReport):
        raise TypeError("semantic pipeline report has an invalid type")
    parsed = output_format.casefold()
    if parsed == "text":
        return render_semantic_shadow_pipeline_text(report, language=language)
    if parsed == "json":
        return encode_semantic_shadow_pipeline_report_json(report)
    raise ValueError("semantic analyze format must be text or json")


def _load_or_build_config(
    *,
    cases_path: Path | None,
    config_path: Path | None,
    responses_path: Path | None,
    provider: str,
    endpoint: str | None,
    credential_env: str | None,
    provider_id: str | None,
    model_id: str | None,
    approved_live_binding: list[str] | None,
    allow_live: bool,
) -> tuple[SemanticTrialConfig, Path]:
    if config_path is not None:
        config = load_semantic_trial_config(config_path)
        return config, config_path.parent
    if cases_path is None:
        raise SemanticTrialError("cases_path_required")
    bindings = tuple(_parse_binding(item) for item in (approved_live_binding or []))
    config = SemanticTrialConfig(
        provider=provider,  # type: ignore[arg-type]
        cases_path=str(cases_path),
        responses_path=str(responses_path) if responses_path is not None else None,
        endpoint_url=endpoint,
        credential_env=credential_env,
        provider_id=provider_id,
        model_id=model_id,
        allow_live_provider=allow_live,
        approved_live_bindings=bindings,
    )
    return config, Path.cwd()


def _parse_binding(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or "|" not in value:
        raise ValueError("live binding must use PROVIDER_ID|MODEL_ID")
    provider_id, model_id = value.split("|", 1)
    if not provider_id or not model_id:
        raise ValueError("live binding must contain Provider and Model IDs")
    return provider_id, model_id


def _resolve_trial_path(base: Path, value: str | None) -> Path:
    if value is None:
        raise SemanticTrialError("trial_path_missing")
    path = Path(value)
    return path if path.is_absolute() else base / path


def _parse_output_format(value: str) -> ReportArtifactFormat:
    try:
        return ReportArtifactFormat(value.casefold())
    except ValueError as error:
        raise ValueError("semantic trial format must be text or json") from error


def _render_report(report: object, output_format: str) -> str:
    from agentsec.semantic import SemanticEvaluationReport

    if not isinstance(report, SemanticEvaluationReport):
        raise TypeError("semantic trial report has an invalid type")
    parsed = output_format.casefold()
    if parsed == SemanticTrialFormat.TEXT:
        return render_semantic_evaluation_text(report)
    if parsed == SemanticTrialFormat.JSON:
        return encode_semantic_evaluation_json(report)
    raise ValueError("semantic trial format must be text or json")


def _load_json_model(path: Path, model: type[object]) -> object:
    """Load a bounded regular JSON model without echoing untrusted values."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("JSON input is missing, unsafe, or oversized")
    import json

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("JSON input is unreadable") from error
    return model.model_validate(payload)  # type: ignore[attr-defined]


__all__ = ["register_semantic_commands"]
