"""P2-02 static MCP declaration parser tests."""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import pytest

from agentsec.parsers import (
    McpApprovalMode,
    McpAuthMode,
    McpConfigurationParser,
    McpEnvironmentSource,
    McpParseError,
    McpParseIssueCode,
    McpParseLimits,
    McpTransport,
    TomlStructuredParser,
)


def _parse_toml(content: str):  # type: ignore[no-untyped-def]
    document = TomlStructuredParser().parse(content)
    return McpConfigurationParser().parse(document)


def test_mcp_parser_extracts_stdio_server_controls_without_copying_static_secrets() -> (
    None
):
    content = """
[mcp_servers.docs]
command = "npx"
args = ["-y", "@example/docs-server"]
cwd = "/workspace"
enabled = false
required = true
startup_timeout_sec = 12.5
tool_timeout_ms = 5000
enabled_tools = ["search", "read"]
disabled_tools = ["delete"]
default_tools_approval_mode = "prompt"
experimental_environment = "local"
env = { EXAMPLE_TOKEN = "STATIC_SECRET_DO_NOT_COPY" }
env_vars = ["HOME", { name = "REMOTE_TOKEN", source = "remote" }]

[mcp_servers.docs.tools.write]
approval_mode = "writes"
"""

    parsed = _parse_toml(content)

    assert len(parsed.servers) == 1
    server = parsed.servers[0]
    assert server.name == "docs"
    assert server.transport is McpTransport.STDIO
    assert server.command is not None and server.command.value == "npx"
    assert tuple(item.value for item in server.arguments) == (
        "-y",
        "@example/docs-server",
    )
    assert server.working_directory is not None
    assert server.working_directory.value == "/workspace"
    assert server.enabled is False
    assert server.required is True
    assert server.startup_timeout_seconds is not None
    assert server.startup_timeout_seconds.value == 12.5
    assert server.tool_timeout_seconds is not None
    assert server.tool_timeout_seconds.value == 5.0
    assert tuple(item.value for item in server.enabled_tools) == ("search", "read")
    assert tuple(item.value for item in server.disabled_tools) == ("delete",)
    assert server.default_approval_mode is not None
    assert server.default_approval_mode.value is McpApprovalMode.PROMPT
    assert server.experimental_environment is not None
    assert server.experimental_environment.value is McpEnvironmentSource.LOCAL
    assert tuple(item.value for item in server.static_environment_names) == (
        "EXAMPLE_TOKEN",
    )
    assert tuple(
        (item.name.value, item.source) for item in server.environment_references
    ) == (
        ("HOME", McpEnvironmentSource.LOCAL),
        ("REMOTE_TOKEN", McpEnvironmentSource.REMOTE),
    )
    assert server.start_line == 2
    assert server.end_line == 18
    assert server.tool_policies[0].tool_name == "write"
    assert server.tool_policies[0].approval_mode.value is McpApprovalMode.WRITES
    assert "STATIC_SECRET_DO_NOT_COPY" not in repr(server)


def test_mcp_parser_extracts_sanitized_streamable_http_server() -> None:
    content = """
[mcp_servers.api]
url = "https://api.example.invalid/mcp?token=SECRET#fragment"
bearer_token_env_var = "MCP_BEARER_TOKEN"
auth = "oauth"
oauth_resource = "https://api.example.invalid/resource"
scopes = ["tools.read", "tools.write"]
http_headers = { "X-Static-Key" = "STATIC_SECRET_DO_NOT_COPY" }
env_http_headers = { "Authorization" = "MCP_AUTH_HEADER" }
"""

    server = _parse_toml(content).servers[0]

    assert server.transport is McpTransport.STREAMABLE_HTTP
    assert server.endpoint is not None
    assert server.endpoint.value.scheme == "https"
    assert server.endpoint.value.host == "api.example.invalid"
    assert server.endpoint.value.path == "/mcp"
    assert server.endpoint.value.query_or_fragment_present is True
    assert server.endpoint.value.is_local is False
    assert server.bearer_token_env_var is not None
    assert server.bearer_token_env_var.value == "MCP_BEARER_TOKEN"
    assert server.auth_mode is not None
    assert server.auth_mode.value is McpAuthMode.OAUTH
    assert server.oauth_resource is not None
    assert server.oauth_resource.value.endswith("/resource")
    assert tuple(item.value for item in server.oauth_scopes) == (
        "tools.read",
        "tools.write",
    )
    assert tuple(item.value for item in server.static_http_header_names) == (
        "X-Static-Key",
    )
    assert server.environment_http_headers[0].header.value == "Authorization"
    assert (
        server.environment_http_headers[0].environment_variable.value
        == "MCP_AUTH_HEADER"
    )
    rendered = repr(server)
    assert "STATIC_SECRET_DO_NOT_COPY" not in rendered
    assert "token=SECRET" not in rendered


def test_mcp_parser_extracts_plugin_bundled_server_without_launch_fields() -> None:
    content = """
[plugins.example]
enabled = true

[plugins.example.mcp_servers.bundled]
enabled = true
required = false
default_tools_approval_mode = "auto"
"""

    server = _parse_toml(content).servers[0]

    assert server.name == "bundled"
    assert server.scope_path == ("plugins", "example", "mcp_servers")
    assert server.transport is McpTransport.PLUGIN_BUNDLED
    assert server.command is None
    assert server.endpoint is None
    assert server.enabled is True
    assert server.required is False


def test_mcp_parser_applies_enabled_and_required_defaults() -> None:
    server = _parse_toml('[mcp_servers.local]\ncommand = "example-server"\n').servers[0]

    assert server.enabled is True
    assert server.enabled_declaration is None
    assert server.required is False
    assert server.required_declaration is None


def test_mcp_parser_retains_unknown_field_location_without_its_value() -> None:
    content = """
[mcp_servers.local]
command = "example-server"
future_secret_setting = "DO_NOT_COPY_THIS_VALUE"
"""

    server = _parse_toml(content).servers[0]

    assert len(server.unknown_fields) == 1
    assert server.unknown_fields[0].path[-1] == "future_secret_setting"
    assert server.unknown_fields[0].start_line == 4
    assert "DO_NOT_COPY_THIS_VALUE" not in repr(server)


@pytest.mark.parametrize(
    ("content", "code"),
    [
        ('mcp_servers = "invalid"\n', McpParseIssueCode.INVALID_ROOT),
        (
            '[mcp_servers.bad]\ncommand="x"\nurl="https://x.invalid"\n',
            McpParseIssueCode.CONFLICTING_FIELDS,
        ),
        (
            "[mcp_servers.bad]\nenabled=true\n",
            McpParseIssueCode.MISSING_TRANSPORT,
        ),
        (
            "[mcp_servers.bad]\ncommand=1\n",
            McpParseIssueCode.INVALID_FIELD,
        ),
        (
            '[mcp_servers.bad]\nurl="file:///tmp/socket"\n',
            McpParseIssueCode.INVALID_ENDPOINT,
        ),
        (
            '[mcp_servers.bad]\nurl="https://user:pass@x.invalid/mcp"\n',
            McpParseIssueCode.INVALID_ENDPOINT,
        ),
        (
            '[mcp_servers.bad]\ncommand="x"\nstartup_timeout_sec=1\nstartup_timeout_ms=1000\n',
            McpParseIssueCode.CONFLICTING_FIELDS,
        ),
        (
            '[mcp_servers.bad]\ncommand="x"\nauth="unknown"\n',
            McpParseIssueCode.INVALID_FIELD,
        ),
        (
            '[mcp_servers.bad]\ncommand="x"\nenv_vars=[{source="local"}]\n',
            McpParseIssueCode.INVALID_FIELD,
        ),
    ],
)
def test_mcp_parser_rejects_invalid_or_conflicting_declarations(
    content: str,
    code: McpParseIssueCode,
) -> None:
    with pytest.raises(McpParseError) as captured:
        _parse_toml(content)

    assert captured.value.code is code


def test_mcp_parser_never_launches_declared_commands_or_connects_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "must-not-exist"
    content = f'''
[mcp_servers.malicious]
command = "touch"
args = ["{marker}"]
url = "https://network.invalid/mcp"
'''

    def prohibited(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("MCP parser attempted a prohibited side effect")

    monkeypatch.setattr(subprocess, "run", prohibited)
    monkeypatch.setattr(socket, "socket", prohibited)

    with pytest.raises(McpParseError) as captured:
        _parse_toml(content)

    assert captured.value.code is McpParseIssueCode.CONFLICTING_FIELDS
    assert not marker.exists()


def test_mcp_parser_enforces_server_list_and_map_limits() -> None:
    with pytest.raises(McpParseError) as servers:
        McpConfigurationParser(McpParseLimits(max_servers=1)).parse(
            TomlStructuredParser().parse(
                '[mcp_servers.one]\ncommand="one"\n[mcp_servers.two]\ncommand="two"\n'
            )
        )
    assert servers.value.code is McpParseIssueCode.LIMIT_EXCEEDED

    with pytest.raises(McpParseError) as arguments:
        McpConfigurationParser(McpParseLimits(max_list_items=1)).parse(
            TomlStructuredParser().parse(
                '[mcp_servers.one]\ncommand="one"\nargs=["a", "b"]\n'
            )
        )
    assert arguments.value.code is McpParseIssueCode.LIMIT_EXCEEDED

    with pytest.raises(McpParseError) as environment:
        McpConfigurationParser(McpParseLimits(max_map_entries=1)).parse(
            TomlStructuredParser().parse(
                '[mcp_servers.one]\ncommand="one"\nenv={A="1", B="2"}\n'
            )
        )
    assert environment.value.code is McpParseIssueCode.LIMIT_EXCEEDED


def test_mcp_parser_returns_empty_when_no_mcp_configuration_exists() -> None:
    document = TomlStructuredParser().parse('[agent]\nname="local"\n')

    assert McpConfigurationParser().parse(document).servers == ()


def test_mcp_parser_is_deterministic() -> None:
    document = TomlStructuredParser().parse(
        '[mcp_servers.local]\ncommand="example"\nargs=["serve"]\n'
    )
    parser = McpConfigurationParser()

    assert parser.parse(document) == parser.parse(document)
