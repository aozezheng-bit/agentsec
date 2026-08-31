"""Protected configuration and execution helpers for the P3-04 trial CLI."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.semantic.evaluation import (
    SemanticEvaluationCase,
    SemanticEvaluationHarness,
    SemanticEvaluationReport,
)
from agentsec.semantic.invocation import SemanticShadowInvocationAdapter
from agentsec.semantic.live import LiveSemanticProvider, LiveSemanticProviderConfig
from agentsec.semantic.models import SemanticModelOutput
from agentsec.semantic.provider import (
    SemanticInvocationLimits,
    SemanticModelProvider,
    SemanticProviderMetadata,
    SemanticProviderRequest,
    SemanticProviderResponse,
)
from agentsec.semantic.provider_specific import (
    OpenAICompatibleProviderConfig,
    OpenAICompatibleSemanticProvider,
)

SEMANTIC_TRIAL_CONFIG_VERSION = "0.1.0"
SEMANTIC_TRIAL_CONFIG_FORMAT = "agentsec-semantic-trial-config"
SEMANTIC_TRIAL_CASE_SET_VERSION = "0.1.0"
SEMANTIC_TRIAL_CASE_SET_FORMAT = "agentsec-semantic-trial-case-set"
SEMANTIC_TRIAL_MAX_CONFIG_BYTES = 262_144
SEMANTIC_TRIAL_MAX_CASE_SET_BYTES = 16_777_216
SEMANTIC_TRIAL_MAX_RESPONSE_SET_BYTES = 16_777_216


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class SemanticTrialConfig(_Strict):
    """Strict non-secret configuration for one explicit Shadow trial."""

    format: Literal["agentsec-semantic-trial-config"] = "agentsec-semantic-trial-config"
    schema_version: Literal["0.1.0"] = "0.1.0"
    provider: Literal["offline_fixture", "live_https", "openai_compatible"] = (
        "offline_fixture"
    )
    cases_path: Annotated[str, Field(min_length=1, max_length=1024)]
    responses_path: Annotated[str, Field(min_length=1, max_length=1024)] | None = None
    endpoint_url: Annotated[str, Field(min_length=1, max_length=2048)] | None = None
    credential_env: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    provider_id: Annotated[str, Field(min_length=1, max_length=160)] | None = None
    model_id: Annotated[str, Field(min_length=1, max_length=160)] | None = None
    allow_live_provider: bool = False
    approved_live_bindings: tuple[tuple[str, str], ...] = ()
    timeout_ms: Annotated[int, Field(ge=1, le=120_000)] = 30_000
    max_input_tokens: Annotated[int, Field(ge=0, le=1_000_000)] = 32_768
    max_output_tokens: Annotated[int, Field(ge=0, le=1_000_000)] = 8_192

    @model_validator(mode="after")
    def provider_config_must_be_coherent(self) -> SemanticTrialConfig:
        if self.provider == "offline_fixture":
            if self.responses_path is None:
                raise ValueError("offline trial requires responses_path")
            if self.allow_live_provider:
                raise ValueError("offline trial cannot allow live Provider")
        else:
            if not self.allow_live_provider:
                raise ValueError("live trial requires explicit allow_live_provider")
            if self.endpoint_url is None or self.credential_env is None:
                raise ValueError("live trial requires endpoint_url and credential_env")
            if self.provider_id is None or self.model_id is None:
                raise ValueError("live trial requires provider_id and model_id")
            if (self.provider_id, self.model_id) not in self.approved_live_bindings:
                raise ValueError("live trial Provider/Model is not approved")
        return self


class SemanticTrialCaseSet(BaseModel):
    """Bounded case-set wrapper for the trial CLI."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    format: Literal["agentsec-semantic-trial-case-set"] = (
        "agentsec-semantic-trial-case-set"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    cases: tuple[SemanticEvaluationCase, ...]

    @model_validator(mode="after")
    def cases_must_be_sorted_unique(self) -> SemanticTrialCaseSet:
        ids = tuple(case.case_id for case in self.cases)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("semantic trial cases must be sorted and unique")
        return self


class SemanticTrialResponseSet(_Strict):
    """Strict offline response fixtures keyed by Analysis ID."""

    format: Literal["agentsec-semantic-trial-response-set"] = (
        "agentsec-semantic-trial-response-set"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    responses: dict[str, SemanticModelOutput]

    @model_validator(mode="after")
    def responses_must_be_keyed_by_analysis_id(self) -> SemanticTrialResponseSet:
        if len(self.responses) > 256:
            raise ValueError("semantic trial response count exceeds the bound")
        for case_id, response in self.responses.items():
            if not isinstance(case_id, str) or response.analysis_id != case_id:
                raise ValueError("semantic trial response key is inconsistent")
        return self


class SemanticTrialError(RuntimeError):
    """Safe trial configuration/input failure without file contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Semantic trial failed ({code}).")


class SemanticReplayProvider:
    """Deterministic offline Provider keyed by Analysis ID."""

    def __init__(self, outputs: dict[str, SemanticModelOutput]) -> None:
        self._outputs = dict(outputs)
        self._metadata = SemanticProviderMetadata()

    @property
    def metadata(self) -> SemanticProviderMetadata:
        return self._metadata

    def invoke(self, request: SemanticProviderRequest) -> SemanticProviderResponse:
        output = self._outputs.get(request.analysis_id)
        if output is None:
            raise SemanticTrialError("response_missing")
        if output.analysis_id != request.analysis_id:
            raise SemanticTrialError("response_analysis_mismatch")
        raw = json.dumps(
            output.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        import hashlib

        return SemanticProviderResponse(
            request_id=request.request_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            completion_status="complete",
            output_json=raw,
            output_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            input_tokens=0,
            output_tokens=0,
            cost_microunits=0,
        )


def load_semantic_trial_config(path: Path) -> SemanticTrialConfig:
    return SemanticTrialConfig.model_validate(
        _read_json(path, SEMANTIC_TRIAL_MAX_CONFIG_BYTES)
    )


def load_semantic_trial_cases(path: Path) -> tuple[SemanticEvaluationCase, ...]:
    payload = _read_json(path, SEMANTIC_TRIAL_MAX_CASE_SET_BYTES)
    try:
        case_set = SemanticTrialCaseSet.model_validate(payload)
    except ValueError as error:
        raise SemanticTrialError("invalid_case_set") from error
    return case_set.cases


def load_semantic_trial_responses(path: Path) -> dict[str, SemanticModelOutput]:
    payload = _read_json(path, SEMANTIC_TRIAL_MAX_RESPONSE_SET_BYTES)
    try:
        response_set = SemanticTrialResponseSet.model_validate(
            {
                "format": "agentsec-semantic-trial-response-set",
                "schema_version": "0.1.0",
                **payload,
            }
            if isinstance(payload, dict) and "format" not in payload
            else payload
        )
    except (TypeError, ValueError) as error:
        raise SemanticTrialError("invalid_response_set") from error
    return response_set.responses


def build_trial_adapter(
    config: SemanticTrialConfig,
    *,
    responses: dict[str, SemanticModelOutput] | None = None,
) -> SemanticShadowInvocationAdapter:
    if config.provider == "offline_fixture":
        if responses is None:
            raise SemanticTrialError("response_missing")
        provider: SemanticModelProvider = SemanticReplayProvider(responses)
        return SemanticShadowInvocationAdapter(
            provider=provider,
            limits=SemanticInvocationLimits(
                timeout_ms=config.timeout_ms,
                max_input_tokens=config.max_input_tokens,
                max_output_tokens=config.max_output_tokens,
            ),
        )
    if (
        config.endpoint_url is None
        or config.credential_env is None
        or config.provider_id is None
        or config.model_id is None
    ):
        raise SemanticTrialError("live_config_missing")
    if config.provider == "openai_compatible":
        provider = OpenAICompatibleSemanticProvider(
            OpenAICompatibleProviderConfig(
                endpoint_url=config.endpoint_url,
                credential_env=config.credential_env,
                provider_id=config.provider_id,
                model_id=config.model_id,
                timeout_ms=config.timeout_ms,
            )
        )
    else:
        provider = LiveSemanticProvider(
            LiveSemanticProviderConfig(
                endpoint_url=config.endpoint_url,
                credential_env=config.credential_env,
                provider_id=config.provider_id,
                model_id=config.model_id,
                timeout_ms=config.timeout_ms,
            )
        )
    return SemanticShadowInvocationAdapter(
        provider=provider,
        limits=SemanticInvocationLimits(
            timeout_ms=config.timeout_ms,
            max_input_tokens=config.max_input_tokens,
            max_output_tokens=config.max_output_tokens,
        ),
        allow_live_provider=True,
        approved_live_bindings=config.approved_live_bindings,
    )


def run_semantic_trial(
    config: SemanticTrialConfig,
    *,
    cases: tuple[SemanticEvaluationCase, ...],
    responses: dict[str, SemanticModelOutput] | None = None,
) -> SemanticEvaluationReport:
    adapter = build_trial_adapter(config, responses=responses)
    return SemanticEvaluationHarness().evaluate(cases, adapter)


def _read_json(path: Path, max_bytes: int) -> object:
    if not isinstance(path, Path) or path.is_symlink():
        raise SemanticTrialError("unsafe_input_path")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise SemanticTrialError("unsafe_input_path")
        content = os.read(descriptor, max_bytes + 1)
    except FileNotFoundError as error:
        raise SemanticTrialError("input_missing") from error
    except SemanticTrialError:
        raise
    except OSError as error:
        raise SemanticTrialError("input_read_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > max_bytes:
        raise SemanticTrialError("input_too_large")
    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SemanticTrialError("invalid_json") from error


__all__ = [
    "SEMANTIC_TRIAL_CASE_SET_FORMAT",
    "SEMANTIC_TRIAL_CASE_SET_VERSION",
    "SEMANTIC_TRIAL_CONFIG_FORMAT",
    "SEMANTIC_TRIAL_CONFIG_VERSION",
    "SemanticReplayProvider",
    "SemanticTrialCaseSet",
    "SemanticTrialConfig",
    "SemanticTrialError",
    "SemanticTrialResponseSet",
    "build_trial_adapter",
    "load_semantic_trial_cases",
    "load_semantic_trial_config",
    "load_semantic_trial_responses",
    "run_semantic_trial",
]
