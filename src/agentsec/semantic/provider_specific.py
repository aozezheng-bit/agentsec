"""Provider-specific request/response mapping for a structured JSON endpoint."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from agentsec.semantic.live import LiveSemanticProviderError
from agentsec.semantic.provider import (
    SemanticProviderMetadata,
    SemanticProviderRequest,
    SemanticProviderResponse,
)

SEMANTIC_PROVIDER_SPECIFIC_ADAPTER_VERSION = "0.1.0"
SEMANTIC_PROVIDER_SPECIFIC_FORMAT = "agentsec-provider-specific-structured-json"


@dataclass(frozen=True, slots=True)
class OpenAICompatibleProviderConfig:
    """Non-secret config for a provider using chat-style structured JSON output."""

    endpoint_url: str
    credential_env: str
    provider_id: str = "openai-compatible-shadow"
    model_id: str = "configured-shadow-model"
    timeout_ms: int = 30_000
    max_response_bytes: int = 1_048_576
    user_agent: str = "agentsec-shadow/0.2.0"

    def __post_init__(self) -> None:
        from agentsec.semantic.live import LiveSemanticProviderConfig

        # Reuse the strict HTTPS, credential-name, and bound validation.
        LiveSemanticProviderConfig(
            endpoint_url=self.endpoint_url,
            credential_env=self.credential_env,
            provider_id=self.provider_id,
            model_id=self.model_id,
            timeout_ms=self.timeout_ms,
            max_response_bytes=self.max_response_bytes,
            user_agent=self.user_agent,
        )


OpenAICompatibleTransport = Callable[
    [OpenAICompatibleProviderConfig, SemanticProviderRequest, str],
    tuple[str, int, int],
]


class OpenAICompatibleSemanticProvider:
    """Provider-specific adapter with injected transport for deterministic tests."""

    def __init__(
        self,
        config: OpenAICompatibleProviderConfig,
        *,
        transport: OpenAICompatibleTransport | None = None,
    ) -> None:
        if not isinstance(config, OpenAICompatibleProviderConfig):
            raise TypeError(
                "OpenAI-compatible Provider config must be "
                "OpenAICompatibleProviderConfig"
            )
        self._config = config
        self._transport = transport or _openai_compatible_transport
        self._metadata = SemanticProviderMetadata(
            provider_id=config.provider_id,
            model_id=config.model_id,
            transport="https_json",
            transport_network_access=True,
        )

    @property
    def config(self) -> OpenAICompatibleProviderConfig:
        return self._config

    @property
    def metadata(self) -> SemanticProviderMetadata:
        return self._metadata

    def invoke(self, request: SemanticProviderRequest) -> SemanticProviderResponse:
        import hashlib
        import os

        if not isinstance(request, SemanticProviderRequest):
            raise TypeError("semantic Provider request must be SemanticProviderRequest")
        credential = os.environ.get(self._config.credential_env)
        if not credential:
            raise LiveSemanticProviderError("credential_unavailable")
        if any(ord(char) < 32 for char in credential):
            raise LiveSemanticProviderError("credential_invalid")
        try:
            output_json, input_tokens, output_tokens = self._transport(
                self._config, request, credential
            )
        except LiveSemanticProviderError:
            raise
        except Exception as error:
            raise LiveSemanticProviderError("transport_failure") from error
        output_json = output_json.strip() if isinstance(output_json, str) else ""
        if not output_json:
            raise LiveSemanticProviderError("empty_response")
        if len(output_json.encode("utf-8")) > self._config.max_response_bytes:
            raise LiveSemanticProviderError("response_too_large")
        output_json = _normalize_output_limitations(output_json, request)
        return SemanticProviderResponse(
            request_id=request.request_id,
            provider_id=self.metadata.provider_id,
            model_id=self.metadata.model_id,
            completion_status="complete",
            output_json=output_json,
            output_sha256=hashlib.sha256(output_json.encode("utf-8")).hexdigest(),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_microunits=0,
        )


def _openai_compatible_transport(
    config: OpenAICompatibleProviderConfig,
    request: SemanticProviderRequest,
    credential: str,
) -> tuple[str, int, int]:
    """Map AgentSec channels to a documented chat-style JSON envelope.

    The HTTP mechanics intentionally delegate to the P3-03 safe transport after
    constructing the Provider-specific envelope. The response parser accepts
    only choices[0].message.content and usage token counters.
    """

    import urllib.error
    import urllib.request
    from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

    payload = {
        "model": request.model_id,
        "messages": [
            {"role": "system", "content": request.system_channel},
            {"role": "user", "content": request.data_channel_json},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "agentsec_semantic_model_output",
                "strict": True,
                "schema": json.loads(request.output_schema_json),
            },
        },
        "metadata": {"analysis_id": request.analysis_id},
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    http_request = urllib.request.Request(
        config.endpoint_url,
        data=body,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {credential}",
            "Content-Type": "application/json",
            "User-Agent": config.user_agent,
        },
        method="POST",
    )

    class _RejectRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise LiveSemanticProviderError("redirect_rejected")

    opener = build_opener(_RejectRedirect(), ProxyHandler({}))
    try:
        with opener.open(http_request, timeout=config.timeout_ms / 1000) as raw:
            response_body = raw.read(config.max_response_bytes + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise LiveSemanticProviderError("transport_failure") from error
    if len(response_body) > config.max_response_bytes:
        raise LiveSemanticProviderError("response_too_large")
    try:
        envelope = json.loads(response_body.decode("utf-8"))
        content = envelope["choices"][0]["message"]["content"]
        usage = envelope.get("usage", {})
        input_tokens = int(usage.get("prompt_tokens", 0))
        output_tokens = int(usage.get("completion_tokens", 0))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
    ) as error:
        raise LiveSemanticProviderError("invalid_response") from error
    if isinstance(content, dict):
        content = json.dumps(content, ensure_ascii=False, sort_keys=True)
    if not isinstance(content, str):
        raise LiveSemanticProviderError("invalid_response")
    return content, input_tokens, output_tokens


def _normalize_output_limitations(
    output_json: str, request: SemanticProviderRequest
) -> str:
    """Trusted canonicalization of model-provided limitation ordering.

    The P3-01 output contract requires sorted, unique limitation arrays for
    deterministic hashing. Models naturally emit semantically identical but
    unordered arrays. This Value-neutral step only sorts and deduplicates
    limitation strings (top-level and per-candidate) before contract
    validation; every other field passes through untouched. If parsing
    fails, the original text is returned so the strict contract remains the
    sole authority that accepts or rejects the output.
    """

    del request
    try:
        payload = json.loads(output_json)
    except (json.JSONDecodeError, TypeError):
        return output_json
    if not isinstance(payload, dict):
        return output_json
    changed = False

    top = payload.get("limitations")
    if isinstance(top, list) and all(isinstance(v, str) for v in top):
        normalized = sorted(set(top))
        if normalized != top:
            payload["limitations"] = normalized
            changed = True

    candidates = payload.get("candidates")
    if isinstance(candidates, list) and all(
        isinstance(candidate, dict) for candidate in candidates
    ):
        keyed = [
            (candidate.get("candidate_key"), index, candidate)
            for index, candidate in enumerate(candidates)
        ]
        if all(isinstance(key, str) and key for key, _index, _candidate in keyed):
            sorted_candidates = [
                candidate
                for _key, _index, candidate in sorted(
                    keyed, key=lambda item: (item[0], item[1])
                )
            ]
            if sorted_candidates != candidates:
                payload["candidates"] = sorted_candidates
                changed = True
        for candidate in candidates:
            values = candidate.get("limitations")
            if isinstance(values, list) and all(isinstance(v, str) for v in values):
                normalized = sorted(set(values))
                if normalized != values:
                    candidate["limitations"] = normalized
                    changed = True
    if not changed:
        return output_json
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


__all__ = [
    "SEMANTIC_PROVIDER_SPECIFIC_ADAPTER_VERSION",
    "SEMANTIC_PROVIDER_SPECIFIC_FORMAT",
    "OpenAICompatibleProviderConfig",
    "OpenAICompatibleSemanticProvider",
]
