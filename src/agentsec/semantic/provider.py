"""P3-02 in-memory Provider contract and deterministic offline fixture."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.domain.base import Sha256Digest
from agentsec.semantic.models import SemanticModelOutput
from agentsec.semantic.prompt import (
    SEMANTIC_SYSTEM_PROMPT,
    SemanticPromptEnvelope,
    semantic_model_output_schema_json,
)

SEMANTIC_MODEL_PROVIDER_ID = "offline-fixture"
SEMANTIC_MODEL_ID = "agentsec-semantic-fixture-v1"
SEMANTIC_PROVIDER_CONTRACT_VERSION = "0.1.0"
SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION = "0.1.0"
SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION = "0.1.0"

SEMANTIC_PROVIDER_REQUEST_FORMAT = "agentsec-semantic-provider-request"
SEMANTIC_PROVIDER_RESPONSE_FORMAT = "agentsec-semantic-provider-response"
SEMANTIC_MAX_PROVIDER_INPUT_CHARACTERS = 262_144
SEMANTIC_MAX_PROVIDER_OUTPUT_CHARACTERS = 131_072

_STABLE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$"
_REQUEST_ID_PATTERN = r"^semantic-provider-request-sha256:[0-9a-f]{64}$"


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class SemanticProviderMetadata(_Strict):
    """Provider capabilities accepted by the P3-02 offline Shadow boundary."""

    provider_id: Annotated[
        str,
        Field(min_length=1, max_length=160, pattern=_STABLE_ID_PATTERN),
    ] = SEMANTIC_MODEL_PROVIDER_ID
    model_id: Annotated[
        str,
        Field(min_length=1, max_length=160, pattern=_STABLE_ID_PATTERN),
    ] = SEMANTIC_MODEL_ID
    contract_version: Literal["0.1.0"] = "0.1.0"
    transport: Literal["in_memory_fixture", "https_json"] = "in_memory_fixture"
    structured_output_supported: Literal[True] = True
    transport_network_access: bool = False
    timeout_enforced: Literal[True] = True
    model_tools_enabled: Literal[False] = False
    model_filesystem_write: Literal[False] = False
    model_network_access: Literal[False] = False
    billable_invocation: Literal[False] = False
    raw_request_retained: Literal[False] = False
    raw_response_retained: Literal[False] = False


class SemanticInvocationLimits(_Strict):
    """Trusted per-invocation limits; P3-02 permits one non-billable attempt."""

    timeout_ms: Annotated[int, Field(ge=1, le=120_000)] = 30_000
    max_input_characters: Annotated[
        int,
        Field(ge=1, le=SEMANTIC_MAX_PROVIDER_INPUT_CHARACTERS),
    ] = 131_072
    max_output_characters: Annotated[
        int,
        Field(ge=1, le=SEMANTIC_MAX_PROVIDER_OUTPUT_CHARACTERS),
    ] = 65_536
    max_input_tokens: Annotated[int, Field(ge=0, le=1_000_000)] = 32_768
    max_output_tokens: Annotated[int, Field(ge=0, le=1_000_000)] = 8_192
    max_cost_microunits: Literal[0] = 0
    max_attempts: Literal[1] = 1
    fallback_allowed: Literal[False] = False
    billable_invocation_allowed: Literal[False] = False


class SemanticProviderRequest(_Strict):
    """Provider-ready request with physically separate instruction/data channels."""

    format: Literal["agentsec-semantic-provider-request"] = (
        "agentsec-semantic-provider-request"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    provider_id: Annotated[str, Field(pattern=_STABLE_ID_PATTERN)]
    model_id: Annotated[str, Field(pattern=_STABLE_ID_PATTERN)]
    request_id: Annotated[str, Field(pattern=_REQUEST_ID_PATTERN)]
    analysis_id: Annotated[str, Field(min_length=1, max_length=128)]
    prompt_version: Literal["0.1.0"] = "0.1.0"
    prompt_sha256: Sha256Digest
    input_sha256: Sha256Digest
    system_channel: Annotated[str, Field(min_length=1, max_length=4_096)]
    data_channel_json: Annotated[
        str,
        Field(min_length=1, max_length=SEMANTIC_MAX_PROVIDER_INPUT_CHARACTERS),
    ]
    output_schema_json: Annotated[
        str,
        Field(min_length=1, max_length=SEMANTIC_MAX_PROVIDER_INPUT_CHARACTERS),
    ]
    limits: SemanticInvocationLimits
    model_tools_enabled: Literal[False] = False
    model_filesystem_write: Literal[False] = False
    model_network_access: Literal[False] = False
    raw_request_retained: Literal[False] = False

    @model_validator(mode="after")
    def bindings_must_be_recomputable(self) -> SemanticProviderRequest:
        if self.system_channel != SEMANTIC_SYSTEM_PROMPT:
            raise ValueError("semantic system channel is inconsistent")
        if self.output_schema_json != semantic_model_output_schema_json():
            raise ValueError("semantic output Schema channel is inconsistent")
        try:
            prompt_input = json.loads(self.data_channel_json)
        except json.JSONDecodeError as error:
            raise ValueError("semantic data channel is not valid JSON") from error
        from agentsec.semantic.models import SemanticAnalysisInput
        from agentsec.semantic.schema import encode_semantic_analysis_input_json

        parsed = SemanticAnalysisInput.model_validate(prompt_input)
        if parsed.analysis_id != self.analysis_id:
            raise ValueError("semantic Provider request Analysis ID is inconsistent")
        if (
            encode_semantic_analysis_input_json(parsed).strip()
            != self.data_channel_json
        ):
            raise ValueError("semantic data channel is not canonical")
        from agentsec.semantic.models import canonical_model_sha256

        if canonical_model_sha256(parsed) != self.input_sha256:
            raise ValueError("semantic Provider request input hash is inconsistent")
        if self.request_id != semantic_provider_request_id(self):
            raise ValueError("semantic Provider request ID is inconsistent")
        if semantic_provider_input_characters(self) > self.limits.max_input_characters:
            raise ValueError("semantic Provider request exceeds the input budget")
        return self


class SemanticProviderResponse(_Strict):
    """Untrusted bounded Provider response retained only for contract validation."""

    format: Literal["agentsec-semantic-provider-response"] = (
        "agentsec-semantic-provider-response"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    request_id: Annotated[str, Field(pattern=_REQUEST_ID_PATTERN)]
    provider_id: Annotated[str, Field(pattern=_STABLE_ID_PATTERN)]
    model_id: Annotated[str, Field(pattern=_STABLE_ID_PATTERN)]
    completion_status: Literal["complete", "length", "content_filter", "error"]
    output_json: Annotated[
        str,
        Field(min_length=1, max_length=SEMANTIC_MAX_PROVIDER_OUTPUT_CHARACTERS),
    ]
    output_sha256: Sha256Digest
    input_tokens: Annotated[int, Field(ge=0, le=1_000_000)]
    output_tokens: Annotated[int, Field(ge=0, le=1_000_000)]
    cost_microunits: Annotated[int, Field(ge=0, le=1_000_000_000)] = 0
    raw_response_retained: Literal[False] = False

    @field_validator("output_json")
    @classmethod
    def output_must_be_exact_text(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("semantic Provider output must be exact JSON text")
        return value

    @model_validator(mode="after")
    def response_hash_must_be_recomputable(self) -> SemanticProviderResponse:
        if self.output_sha256 != _sha256_text(self.output_json):
            raise ValueError("semantic Provider response hash is inconsistent")
        return self


@runtime_checkable
class SemanticModelProvider(Protocol):
    """No-I/O protocol implemented by the P3-02 in-memory fixture Provider."""

    @property
    def metadata(self) -> SemanticProviderMetadata:
        """Return fixed capability and retention declarations."""

    def invoke(self, request: SemanticProviderRequest) -> SemanticProviderResponse:
        """Return one bounded response while honoring request timeout limits."""


class OfflineFixtureSemanticProvider:
    """Deterministic in-memory Provider for replay before any live model trial."""

    def __init__(
        self,
        *,
        output: SemanticModelOutput | str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        completion_status: Literal[
            "complete", "length", "content_filter", "error"
        ] = "complete",
    ) -> None:
        if isinstance(output, SemanticModelOutput):
            output_json = json.dumps(
                output.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        elif isinstance(output, str):
            output_json = output
        else:
            raise TypeError(
                "offline semantic fixture output must be JSON text or model"
            )
        self._output_json = output_json
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self._completion_status = completion_status
        self._metadata = SemanticProviderMetadata()

    @property
    def metadata(self) -> SemanticProviderMetadata:
        return self._metadata

    def invoke(self, request: SemanticProviderRequest) -> SemanticProviderResponse:
        if not isinstance(request, SemanticProviderRequest):
            raise TypeError("semantic Provider request must be SemanticProviderRequest")
        return SemanticProviderResponse(
            request_id=request.request_id,
            provider_id=self.metadata.provider_id,
            model_id=self.metadata.model_id,
            completion_status=self._completion_status,
            output_json=self._output_json,
            output_sha256=_sha256_text(self._output_json),
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            cost_microunits=0,
        )


def build_semantic_provider_request(
    *,
    prompt: SemanticPromptEnvelope,
    metadata: SemanticProviderMetadata,
    limits: SemanticInvocationLimits,
) -> SemanticProviderRequest:
    if not isinstance(prompt, SemanticPromptEnvelope):
        raise TypeError("semantic prompt must be SemanticPromptEnvelope")
    if not isinstance(metadata, SemanticProviderMetadata):
        raise TypeError("semantic Provider metadata must be SemanticProviderMetadata")
    if not isinstance(limits, SemanticInvocationLimits):
        raise TypeError("semantic invocation limits must be SemanticInvocationLimits")
    provisional: dict[str, Any] = {
        "format": SEMANTIC_PROVIDER_REQUEST_FORMAT,
        "schema_version": SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION,
        "provider_id": metadata.provider_id,
        "model_id": metadata.model_id,
        "analysis_id": prompt.analysis_id,
        "prompt_version": prompt.prompt_version,
        "prompt_sha256": prompt.prompt_sha256,
        "input_sha256": prompt.input_sha256,
        "system_channel": prompt.system_channel(),
        "data_channel_json": prompt.data_channel_json(),
        "output_schema_json": semantic_model_output_schema_json(),
        "limits": limits.model_dump(mode="json"),
        "model_tools_enabled": False,
        "model_filesystem_write": False,
        "model_network_access": False,
        "raw_request_retained": False,
    }
    request_id = f"semantic-provider-request-sha256:{_canonical_hash(provisional)}"
    return SemanticProviderRequest(
        provider_id=metadata.provider_id,
        model_id=metadata.model_id,
        request_id=request_id,
        analysis_id=prompt.analysis_id,
        prompt_sha256=prompt.prompt_sha256,
        input_sha256=prompt.input_sha256,
        system_channel=prompt.system_channel(),
        data_channel_json=prompt.data_channel_json(),
        output_schema_json=semantic_model_output_schema_json(),
        limits=limits,
    )


def semantic_provider_request_id(request: SemanticProviderRequest) -> str:
    payload = request.model_dump(mode="json", exclude={"request_id"})
    return f"semantic-provider-request-sha256:{_canonical_hash(payload)}"


def semantic_provider_input_characters(request: SemanticProviderRequest) -> int:
    return (
        len(request.system_channel)
        + len(request.data_channel_json)
        + len(request.output_schema_json)
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "SEMANTIC_MODEL_ID",
    "SEMANTIC_MODEL_PROVIDER_ID",
    "SEMANTIC_PROVIDER_CONTRACT_VERSION",
    "SEMANTIC_PROVIDER_REQUEST_FORMAT",
    "SEMANTIC_PROVIDER_REQUEST_SCHEMA_VERSION",
    "SEMANTIC_PROVIDER_RESPONSE_FORMAT",
    "SEMANTIC_PROVIDER_RESPONSE_SCHEMA_VERSION",
    "OfflineFixtureSemanticProvider",
    "SemanticInvocationLimits",
    "SemanticModelProvider",
    "SemanticProviderMetadata",
    "SemanticProviderRequest",
    "SemanticProviderResponse",
    "build_semantic_provider_request",
    "semantic_provider_input_characters",
    "semantic_provider_request_id",
]
