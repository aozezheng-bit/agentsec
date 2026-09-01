"""Opt-in Live Provider transport for Shadow-only semantic trials.

The transport is intentionally injected and never constructed implicitly by the
CLI or the Shadow Invocation Adapter. A caller must provide an explicit HTTPS
endpoint and environment-variable credential name; credential values are never
stored in the configuration or reports.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from agentsec.semantic.provider import (
    SemanticProviderMetadata,
    SemanticProviderRequest,
    SemanticProviderResponse,
)

SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION = "0.1.0"
SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION = "0.1.0"
SEMANTIC_LIVE_PROVIDER_ID = "https-json-shadow"
SEMANTIC_LIVE_PROVIDER_FORMAT = "agentsec-live-semantic-provider-config"
_CREDENTIAL_ENV_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


class LiveSemanticProviderError(RuntimeError):
    """Safe live Provider failure without endpoint, credential, or body values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"Live semantic Provider failed ({code}).")


@dataclass(frozen=True, slots=True)
class LiveSemanticProviderConfig:
    """Explicit, non-secret live transport configuration."""

    endpoint_url: str
    credential_env: str
    provider_id: str = SEMANTIC_LIVE_PROVIDER_ID
    model_id: str = "configured-shadow-model"
    timeout_ms: int = 30_000
    max_response_bytes: int = 1_048_576
    user_agent: str = "agentsec-shadow/0.1.0"

    def __post_init__(self) -> None:
        parsed = urlparse(self.endpoint_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("live Provider endpoint must be an HTTPS URL")
        if parsed.username or parsed.password:
            raise ValueError("live Provider endpoint must not contain credentials")
        if not _CREDENTIAL_ENV_PATTERN.fullmatch(self.credential_env):
            raise ValueError("live Provider credential_env must be an env name")
        if not self.provider_id or not self.model_id:
            raise ValueError("live Provider identifiers must be non-empty")
        if self.timeout_ms < 1 or self.timeout_ms > 120_000:
            raise ValueError("live Provider timeout is outside the safe bound")
        if self.max_response_bytes < 1 or self.max_response_bytes > 4_194_304:
            raise ValueError("live Provider response bound is outside the safe bound")
        if "\n" in self.user_agent or "\r" in self.user_agent:
            raise ValueError("live Provider user agent contains unsafe controls")


LiveTransport = Callable[
    [LiveSemanticProviderConfig, SemanticProviderRequest, str],
    tuple[str, int, int],
]


class LiveSemanticProvider:
    """Explicit live HTTPS Provider; usable only through Shadow invocation."""

    def __init__(
        self,
        config: LiveSemanticProviderConfig,
        *,
        transport: LiveTransport | None = None,
    ) -> None:
        if not isinstance(config, LiveSemanticProviderConfig):
            raise TypeError("live Provider config must be LiveSemanticProviderConfig")
        self._config = config
        self._transport = transport or _https_json_transport
        self._metadata = SemanticProviderMetadata(
            provider_id=config.provider_id,
            model_id=config.model_id,
            transport="https_json",
            transport_network_access=True,
        )

    @property
    def config(self) -> LiveSemanticProviderConfig:
        """Return non-secret configuration metadata."""

        return self._config

    @property
    def metadata(self) -> SemanticProviderMetadata:
        return self._metadata

    def invoke(self, request: SemanticProviderRequest) -> SemanticProviderResponse:
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
        if not isinstance(output_json, str) or not output_json.strip():
            raise LiveSemanticProviderError("empty_response")
        if len(output_json.encode("utf-8")) > self._config.max_response_bytes:
            raise LiveSemanticProviderError("response_too_large")
        return SemanticProviderResponse(
            request_id=request.request_id,
            provider_id=self.metadata.provider_id,
            model_id=self.metadata.model_id,
            completion_status="complete",
            output_json=output_json.strip(),
            output_sha256=_sha256_text(output_json.strip()),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_microunits=0,
        )


def _https_json_transport(
    config: LiveSemanticProviderConfig,
    request: SemanticProviderRequest,
    credential: str,
) -> tuple[str, int, int]:
    payload = {
        "system": request.system_channel,
        "data": json.loads(request.data_channel_json),
        "response_schema": json.loads(request.output_schema_json),
        "model": request.model_id,
        "analysis_id": request.analysis_id,
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
        response = json.loads(response_body.decode("utf-8"))
        output_json = response["output_json"]
        input_tokens = int(response.get("input_tokens", 0))
        output_tokens = int(response.get("output_tokens", 0))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise LiveSemanticProviderError("invalid_response") from error
    if not isinstance(output_json, str):
        raise LiveSemanticProviderError("invalid_response")
    return output_json, input_tokens, output_tokens


def _sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "SEMANTIC_LIVE_PROVIDER_CONFIG_VERSION",
    "SEMANTIC_LIVE_PROVIDER_FORMAT",
    "SEMANTIC_LIVE_PROVIDER_ID",
    "SEMANTIC_LIVE_PROVIDER_TRANSPORT_VERSION",
    "LiveSemanticProvider",
    "LiveSemanticProviderConfig",
    "LiveSemanticProviderError",
]
