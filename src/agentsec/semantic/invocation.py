"""P3-02 Shadow-only semantic invocation orchestration."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.domain.base import Sha256Digest
from agentsec.semantic.contract import SemanticAnalysisContract
from agentsec.semantic.models import (
    SemanticAnalysisInput,
    SemanticAnalysisResult,
    SemanticContractError,
    SemanticInvocationProvenance,
)
from agentsec.semantic.prompt import SemanticPromptBuilder
from agentsec.semantic.provider import (
    SEMANTIC_MODEL_ID,
    SEMANTIC_MODEL_PROVIDER_ID,
    SemanticInvocationLimits,
    SemanticModelProvider,
    SemanticProviderMetadata,
    SemanticProviderRequest,
    SemanticProviderResponse,
    build_semantic_provider_request,
    semantic_provider_input_characters,
)

SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION = "0.1.0"
SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION = "0.1.0"
SEMANTIC_SHADOW_INVOCATION_FORMAT = "agentsec-semantic-shadow-invocation-result"

_INVOCATION_ID_PATTERN = r"^semantic-shadow-invocation-sha256:[0-9a-f]{64}$"


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class SemanticShadowInvocationErrorCode(StrEnum):
    """Stable safe failures that never contain Provider or source text."""

    PROVIDER_NOT_APPROVED = "provider_not_approved"
    PROVIDER_CAPABILITY_VIOLATION = "provider_capability_violation"
    INPUT_BUDGET_EXCEEDED = "input_budget_exceeded"
    PROVIDER_FAILURE = "provider_failure"
    PROVIDER_RESPONSE_MISMATCH = "provider_response_mismatch"
    TIMEOUT_EXCEEDED = "timeout_exceeded"
    OUTPUT_BUDGET_EXCEEDED = "output_budget_exceeded"
    TOKEN_BUDGET_EXCEEDED = "token_budget_exceeded"
    COST_BUDGET_EXCEEDED = "cost_budget_exceeded"
    OUTPUT_TRUNCATED = "output_truncated"
    OUTPUT_FILTERED = "output_filtered"
    CONTRACT_REJECTED = "contract_rejected"


class SemanticShadowInvocationError(RuntimeError):
    """Safe P3-02 failure without raw Prompt, response, or dependency messages."""

    def __init__(self, code: SemanticShadowInvocationErrorCode) -> None:
        if not isinstance(code, SemanticShadowInvocationErrorCode):
            raise TypeError("semantic invocation error code is invalid")
        self.code = code
        super().__init__(f"Semantic Shadow invocation failed ({code.value}).")


class SemanticInvocationUsage(_Strict):
    """Bounded non-authoritative usage metadata retained without raw payloads."""

    input_characters: Annotated[int, Field(ge=1)]
    output_characters: Annotated[int, Field(ge=1)]
    input_tokens: Annotated[int, Field(ge=0)]
    output_tokens: Annotated[int, Field(ge=0)]
    cost_microunits: Literal[0] = 0
    attempts: Literal[1] = 1
    timeout_exceeded: Literal[False] = False
    raw_request_retained: Literal[False] = False
    raw_response_retained: Literal[False] = False


class SemanticShadowInvocationResult(_Strict):
    """Final operational wrapper around one validated candidate-evidence result."""

    format: Literal["agentsec-semantic-shadow-invocation-result"] = (
        "agentsec-semantic-shadow-invocation-result"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    adapter_version: Literal["0.1.0"] = "0.1.0"
    invocation_id: Annotated[str, Field(pattern=_INVOCATION_ID_PATTERN)]
    analysis_id: Annotated[str, Field(min_length=1, max_length=128)]
    provider: SemanticProviderMetadata
    request_id: Annotated[str, Field(min_length=1, max_length=160)]
    prompt_sha256: Sha256Digest
    input_sha256: Sha256Digest
    response_sha256: Sha256Digest
    invocation_sha256: Sha256Digest
    limits: SemanticInvocationLimits
    usage: SemanticInvocationUsage
    analysis: SemanticAnalysisResult
    operating_mode: Literal["shadow_only"] = "shadow_only"
    candidate_evidence_only: Literal[True] = True
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    blocks: Literal[False] = False
    policy_authority: Literal[False] = False
    raw_payloads_retained: Literal[False] = False

    @model_validator(mode="after")
    def result_must_be_coherent(self) -> SemanticShadowInvocationResult:
        if self.analysis_id != self.analysis.analysis_id:
            raise ValueError("semantic invocation Analysis ID is inconsistent")
        if self.input_sha256 != self.analysis.input_sha256:
            raise ValueError("semantic invocation input hash is inconsistent")
        if self.response_sha256 != self.analysis.model_output_sha256:
            raise ValueError("semantic invocation response hash is inconsistent")
        if self.invocation_sha256 != self.analysis.invocation.invocation_sha256:
            raise ValueError("semantic invocation provenance hash is inconsistent")
        if self.provider.provider_id != self.analysis.invocation.provider_id:
            raise ValueError("semantic invocation Provider binding is inconsistent")
        if self.provider.model_id != self.analysis.invocation.model_id:
            raise ValueError("semantic invocation Model binding is inconsistent")
        if self.analysis.invocation.prompt_version != "0.1.0":
            raise ValueError("semantic invocation Prompt binding is inconsistent")
        if self.usage.input_characters > self.limits.max_input_characters:
            raise ValueError("semantic invocation input usage exceeds limits")
        if self.usage.output_characters > self.limits.max_output_characters:
            raise ValueError("semantic invocation output usage exceeds limits")
        if self.usage.input_tokens > self.limits.max_input_tokens:
            raise ValueError("semantic invocation input tokens exceed limits")
        if self.usage.output_tokens > self.limits.max_output_tokens:
            raise ValueError("semantic invocation output tokens exceed limits")
        if self.invocation_id != semantic_shadow_invocation_id(self):
            raise ValueError("semantic Shadow invocation ID is inconsistent")
        return self


class SemanticShadowInvocationAdapter:
    """Invoke one approved in-memory Provider and validate through P3-01."""

    def __init__(
        self,
        *,
        provider: SemanticModelProvider,
        prompt_builder: SemanticPromptBuilder | None = None,
        contract: SemanticAnalysisContract | None = None,
        limits: SemanticInvocationLimits | None = None,
        clock: Callable[[], float] = time.monotonic,
        allow_live_provider: bool = False,
        approved_live_bindings: tuple[tuple[str, str], ...] = (),
    ) -> None:
        if not isinstance(provider, SemanticModelProvider):
            raise TypeError("provider must implement SemanticModelProvider")
        selected_limits = limits or SemanticInvocationLimits()
        if not isinstance(selected_limits, SemanticInvocationLimits):
            raise TypeError("limits must be SemanticInvocationLimits")
        if not callable(clock):
            raise TypeError("semantic invocation clock must be callable")
        self._provider = provider
        self._prompt_builder = prompt_builder or SemanticPromptBuilder()
        self._contract = contract or SemanticAnalysisContract()
        self._limits = selected_limits
        self._clock = clock
        if not isinstance(allow_live_provider, bool):
            raise TypeError("allow_live_provider must be a bool")
        if not isinstance(approved_live_bindings, tuple):
            raise TypeError("approved_live_bindings must be a tuple")
        for binding in approved_live_bindings:
            if (
                not isinstance(binding, tuple)
                or len(binding) != 2
                or not all(isinstance(value, str) and value for value in binding)
            ):
                raise TypeError("approved live Provider bindings must be string pairs")
        if len(set(approved_live_bindings)) != len(approved_live_bindings):
            raise ValueError("approved live Provider bindings must be unique")
        self._allow_live_provider = allow_live_provider
        self._approved_live_bindings = approved_live_bindings

    @property
    def provider_metadata(self) -> SemanticProviderMetadata:
        """Return the validated Provider metadata used by this Adapter."""

        return self._trusted_metadata()

    def invoke(
        self,
        semantic_input: SemanticAnalysisInput,
    ) -> SemanticShadowInvocationResult:
        if not isinstance(semantic_input, SemanticAnalysisInput):
            raise TypeError("semantic input must be SemanticAnalysisInput")

        metadata = self._trusted_metadata()
        prompt = self._prompt_builder.build(semantic_input)
        input_characters = (
            len(prompt.system_channel())
            + len(prompt.data_channel_json())
            + len(_output_schema_json())
        )
        if input_characters > self._limits.max_input_characters:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.INPUT_BUDGET_EXCEEDED
            )

        request = build_semantic_provider_request(
            prompt=prompt,
            metadata=metadata,
            limits=self._limits,
        )
        started = self._clock()
        try:
            response = self._provider.invoke(request)
        except Exception as error:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_FAILURE
            ) from error
        completed = self._clock()
        if completed < started:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_FAILURE
            )
        if (completed - started) * 1_000 > self._limits.timeout_ms:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.TIMEOUT_EXCEEDED
            )
        if not isinstance(response, SemanticProviderResponse):
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_RESPONSE_MISMATCH
            )
        self._validate_response(request, response)

        usage = SemanticInvocationUsage(
            input_characters=semantic_provider_input_characters(request),
            output_characters=len(response.output_json),
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_microunits=0,
        )
        invocation_sha256 = _invocation_sha256(request, response, usage)
        invocation = SemanticInvocationProvenance(
            provider_id=metadata.provider_id,
            model_id=metadata.model_id,
            prompt_version=prompt.prompt_version,
            invocation_sha256=invocation_sha256,
            invocation_mode=(
                "shadow_provider"
                if metadata.transport == "https_json"
                else "offline_fixture"
            ),
        )
        try:
            analysis = self._contract.validate_json(
                semantic_input,
                response.output_json,
                invocation,
            )
        except (SemanticContractError, ValueError) as error:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.CONTRACT_REJECTED
            ) from error

        provisional: dict[str, Any] = {
            "format": SEMANTIC_SHADOW_INVOCATION_FORMAT,
            "schema_version": SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION,
            "adapter_version": SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION,
            "analysis_id": semantic_input.analysis_id,
            "provider": metadata.model_dump(mode="json"),
            "request_id": request.request_id,
            "prompt_sha256": prompt.prompt_sha256,
            "input_sha256": analysis.input_sha256,
            "response_sha256": analysis.model_output_sha256,
            "invocation_sha256": invocation_sha256,
            "limits": self._limits.model_dump(mode="json"),
            "usage": usage.model_dump(mode="json"),
            "analysis": analysis.model_dump(mode="json"),
            "operating_mode": "shadow_only",
            "candidate_evidence_only": True,
            "report_only": True,
            "runtime_verified": False,
            "blocks": False,
            "policy_authority": False,
            "raw_payloads_retained": False,
        }
        invocation_id = "semantic-shadow-invocation-sha256:" + _canonical_hash(
            provisional
        )
        return SemanticShadowInvocationResult(
            invocation_id=invocation_id,
            analysis_id=semantic_input.analysis_id,
            provider=metadata,
            request_id=request.request_id,
            prompt_sha256=prompt.prompt_sha256,
            input_sha256=analysis.input_sha256,
            response_sha256=analysis.model_output_sha256,
            invocation_sha256=invocation_sha256,
            limits=self._limits,
            usage=usage,
            analysis=analysis,
        )

    def _trusted_metadata(self) -> SemanticProviderMetadata:
        try:
            metadata = self._provider.metadata
        except Exception as error:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_FAILURE
            ) from error
        if not isinstance(metadata, SemanticProviderMetadata):
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_CAPABILITY_VIOLATION
            )
        offline_identity = (
            metadata.provider_id == SEMANTIC_MODEL_PROVIDER_ID
            and metadata.model_id == SEMANTIC_MODEL_ID
            and metadata.transport == "in_memory_fixture"
        )
        live_identity = (
            metadata.transport == "https_json"
            and self._allow_live_provider
            and (metadata.provider_id, metadata.model_id)
            in self._approved_live_bindings
        )
        if not offline_identity and not live_identity:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_NOT_APPROVED
            )
        if (
            not metadata.structured_output_supported
            or not metadata.timeout_enforced
            or metadata.model_tools_enabled
            or metadata.model_filesystem_write
            or metadata.model_network_access
            or metadata.billable_invocation
            or (
                metadata.transport_network_access and metadata.transport != "https_json"
            )
            or metadata.raw_request_retained
            or metadata.raw_response_retained
        ):
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_CAPABILITY_VIOLATION
            )
        return metadata

    def _validate_response(
        self,
        request: SemanticProviderRequest,
        response: SemanticProviderResponse,
    ) -> None:
        if (
            response.request_id != request.request_id
            or response.provider_id != request.provider_id
            or response.model_id != request.model_id
        ):
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_RESPONSE_MISMATCH
            )
        if response.completion_status == "length":
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.OUTPUT_TRUNCATED
            )
        if response.completion_status == "content_filter":
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.OUTPUT_FILTERED
            )
        if response.completion_status != "complete":
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.PROVIDER_FAILURE
            )
        if len(response.output_json) > self._limits.max_output_characters:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.OUTPUT_BUDGET_EXCEEDED
            )
        if (
            response.input_tokens > self._limits.max_input_tokens
            or response.output_tokens > self._limits.max_output_tokens
        ):
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.TOKEN_BUDGET_EXCEEDED
            )
        if response.cost_microunits > self._limits.max_cost_microunits:
            raise SemanticShadowInvocationError(
                SemanticShadowInvocationErrorCode.COST_BUDGET_EXCEEDED
            )


def semantic_shadow_invocation_id(result: SemanticShadowInvocationResult) -> str:
    payload = result.model_dump(mode="json", exclude={"invocation_id"})
    return f"semantic-shadow-invocation-sha256:{_canonical_hash(payload)}"


def _invocation_sha256(
    request: SemanticProviderRequest,
    response: SemanticProviderResponse,
    usage: SemanticInvocationUsage,
) -> str:
    payload = {
        "request_id": request.request_id,
        "prompt_sha256": request.prompt_sha256,
        "input_sha256": request.input_sha256,
        "response_sha256": response.output_sha256,
        "provider_id": response.provider_id,
        "model_id": response.model_id,
        "usage": usage.model_dump(mode="json"),
    }
    return _canonical_hash(payload)


def _output_schema_json() -> str:
    from agentsec.semantic.prompt import semantic_model_output_schema_json

    return semantic_model_output_schema_json()


def _canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "SEMANTIC_SHADOW_INVOCATION_ADAPTER_VERSION",
    "SEMANTIC_SHADOW_INVOCATION_FORMAT",
    "SEMANTIC_SHADOW_INVOCATION_OUTPUT_VERSION",
    "SemanticInvocationUsage",
    "SemanticShadowInvocationAdapter",
    "SemanticShadowInvocationError",
    "SemanticShadowInvocationErrorCode",
    "SemanticShadowInvocationResult",
    "semantic_shadow_invocation_id",
]
