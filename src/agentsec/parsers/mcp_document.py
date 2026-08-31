"""Static MCP declaration parser over normalized structured configuration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, cast
from urllib.parse import urlsplit

from agentsec.parsers.declarations import SourceBackedValue, UnknownDeclarationField
from agentsec.parsers.structured import (
    StructuredDocument,
    StructuredNode,
    StructuredNodeKind,
    StructuredPath,
)


class McpTransport(StrEnum):
    """Static MCP transport declarations supported by current Codex config."""

    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"
    PLUGIN_BUNDLED = "plugin_bundled"


class McpAuthMode(StrEnum):
    """Reviewed static MCP authentication modes."""

    OAUTH = "oauth"
    CHATGPT = "chatgpt"


class McpApprovalMode(StrEnum):
    """Reviewed MCP default and per-tool approval modes."""

    AUTO = "auto"
    PROMPT = "prompt"
    WRITES = "writes"
    APPROVE = "approve"


class McpEnvironmentSource(StrEnum):
    """Where one environment reference is expected to resolve."""

    LOCAL = "local"
    REMOTE = "remote"


class McpParseIssueCode(StrEnum):
    """Stable safe failure categories for MCP declarations."""

    INVALID_ROOT = "invalid_root"
    INVALID_SERVER = "invalid_server"
    INVALID_FIELD = "invalid_field"
    CONFLICTING_FIELDS = "conflicting_fields"
    MISSING_TRANSPORT = "missing_transport"
    INVALID_ENDPOINT = "invalid_endpoint"
    LIMIT_EXCEEDED = "limit_exceeded"


@dataclass(frozen=True, slots=True)
class McpParseLimits:
    """Bound declaration materialization independently from structured parsing."""

    max_servers: int = 256
    max_list_items: int = 512
    max_map_entries: int = 512

    def __post_init__(self) -> None:
        if min(self.max_servers, self.max_list_items, self.max_map_entries) < 1:
            raise ValueError("MCP parser limits must be positive")


@dataclass(frozen=True, slots=True)
class McpEndpoint:
    """A sanitized endpoint that omits credentials, query, and fragment values."""

    scheme: str
    host: str
    port: int | None
    path: str
    query_or_fragment_present: bool
    is_local: bool


@dataclass(frozen=True, slots=True)
class McpEnvironmentReference:
    """One named environment lookup without reading the variable value."""

    name: SourceBackedValue[str]
    source: McpEnvironmentSource


@dataclass(frozen=True, slots=True)
class McpHeaderEnvironmentReference:
    """One HTTP header whose value comes from a named environment variable."""

    header: SourceBackedValue[str]
    environment_variable: SourceBackedValue[str]


@dataclass(frozen=True, slots=True)
class McpToolPolicy:
    """One source-backed per-tool approval override."""

    tool_name: str
    approval_mode: SourceBackedValue[McpApprovalMode]


@dataclass(frozen=True, slots=True)
class McpServerDeclaration:
    """One static MCP server declaration with secret values intentionally omitted."""

    name: str
    scope_path: StructuredPath
    transport: McpTransport
    start_line: int
    end_line: int
    enabled: bool
    enabled_declaration: SourceBackedValue[bool] | None
    required: bool
    required_declaration: SourceBackedValue[bool] | None
    command: SourceBackedValue[str] | None
    arguments: tuple[SourceBackedValue[str], ...]
    working_directory: SourceBackedValue[str] | None
    endpoint: SourceBackedValue[McpEndpoint] | None
    bearer_token_env_var: SourceBackedValue[str] | None
    auth_mode: SourceBackedValue[McpAuthMode] | None
    oauth_resource: SourceBackedValue[str] | None
    oauth_scopes: tuple[SourceBackedValue[str], ...]
    enabled_tools: tuple[SourceBackedValue[str], ...]
    disabled_tools: tuple[SourceBackedValue[str], ...]
    startup_timeout_seconds: SourceBackedValue[float] | None
    tool_timeout_seconds: SourceBackedValue[float] | None
    default_approval_mode: SourceBackedValue[McpApprovalMode] | None
    tool_policies: tuple[McpToolPolicy, ...]
    experimental_environment: SourceBackedValue[McpEnvironmentSource] | None
    static_environment_names: tuple[SourceBackedValue[str], ...]
    environment_references: tuple[McpEnvironmentReference, ...]
    static_http_header_names: tuple[SourceBackedValue[str], ...]
    environment_http_headers: tuple[McpHeaderEnvironmentReference, ...]
    unknown_fields: tuple[UnknownDeclarationField, ...]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("MCP server name must not be empty")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("MCP server requires a coherent source range")


@dataclass(frozen=True, slots=True)
class ParsedMcpConfiguration:
    """Ordered static MCP declarations extracted without starting a server."""

    servers: tuple[McpServerDeclaration, ...]


class McpParseError(RuntimeError):
    """Safe MCP parser failure that never copies secret configuration values."""

    def __init__(
        self,
        code: McpParseIssueCode,
        *,
        line: int | None = None,
    ) -> None:
        self.code = code
        self.line = line
        super().__init__(f"MCP parsing failed safely: {code.value}.")


class McpConfigurationParser:
    """Interpret normalized Codex MCP tables without I/O, expansion, or execution."""

    _KNOWN_SERVER_FIELDS = {
        "args",
        "auth",
        "bearer_token_env_var",
        "command",
        "cwd",
        "default_tools_approval_mode",
        "disabled_tools",
        "enabled",
        "enabled_tools",
        "env",
        "env_http_headers",
        "env_vars",
        "experimental_environment",
        "http_headers",
        "oauth_resource",
        "required",
        "scopes",
        "startup_timeout_ms",
        "startup_timeout_sec",
        "tool_timeout_ms",
        "tool_timeout_sec",
        "tools",
        "url",
    }

    def __init__(self, limits: McpParseLimits | None = None) -> None:
        self._limits = limits if limits is not None else McpParseLimits()

    def parse(self, document: StructuredDocument) -> ParsedMcpConfiguration:
        """Extract top-level and plugin-bundled `mcp_servers` declarations."""

        node_by_path = {node.path: node for node in document.nodes}
        for node in document.nodes:
            if self._is_mcp_root_path(node.path) and (
                node.kind is not StructuredNodeKind.OBJECT
            ):
                self._raise(McpParseIssueCode.INVALID_ROOT, line=node.start_line)
        roots = self._mcp_roots(document)
        server_nodes: list[tuple[StructuredPath, StructuredNode, bool]] = []
        for root in roots:
            plugin_bundled = root.path[:1] == ("plugins",)
            for child in self._direct_children(document, root.path):
                if child.kind is not StructuredNodeKind.OBJECT:
                    self._raise(McpParseIssueCode.INVALID_SERVER, line=child.start_line)
                server_nodes.append((root.path, child, plugin_bundled))
        if len(server_nodes) > self._limits.max_servers:
            self._raise(McpParseIssueCode.LIMIT_EXCEEDED, line=None)

        servers = tuple(
            self._parse_server(
                document,
                node_by_path,
                root_path,
                node,
                plugin_bundled=plugin_bundled,
            )
            for root_path, node, plugin_bundled in sorted(
                server_nodes,
                key=lambda item: (item[1].start_line, item[1].path),
            )
        )
        return ParsedMcpConfiguration(servers=servers)

    def _parse_server(
        self,
        document: StructuredDocument,
        nodes: dict[StructuredPath, StructuredNode],
        root_path: StructuredPath,
        server_node: StructuredNode,
        *,
        plugin_bundled: bool,
    ) -> McpServerDeclaration:
        name = server_node.path[-1]
        if not isinstance(name, str) or not name:
            self._raise(McpParseIssueCode.INVALID_SERVER, line=server_node.start_line)
        path = server_node.path
        command = self._optional_string(nodes, path + ("command",))
        url = self._optional_string(nodes, path + ("url",))
        if command is not None and url is not None:
            self._raise(McpParseIssueCode.CONFLICTING_FIELDS, line=url.start_line)
        if command is not None:
            transport = McpTransport.STDIO
        elif url is not None:
            transport = McpTransport.STREAMABLE_HTTP
        elif plugin_bundled:
            transport = McpTransport.PLUGIN_BUNDLED
        else:
            self._raise(
                McpParseIssueCode.MISSING_TRANSPORT, line=server_node.start_line
            )

        endpoint = (
            None
            if url is None
            else SourceBackedValue(
                value=self._parse_endpoint(url.value, line=url.start_line),
                path=url.path,
                start_line=url.start_line,
                end_line=url.end_line,
            )
        )
        enabled_declaration = self._optional_bool(nodes, path + ("enabled",))
        required_declaration = self._optional_bool(nodes, path + ("required",))
        unknown = tuple(
            UnknownDeclarationField(
                path=child.path,
                start_line=child.start_line,
                end_line=child.end_line,
            )
            for child in self._direct_children(document, path)
            if child.path[-1] not in self._KNOWN_SERVER_FIELDS
        )
        subtree = tuple(
            node for node in document.nodes if node.path[: len(path)] == path
        )
        declaration_end_line = max(node.end_line for node in subtree)

        return McpServerDeclaration(
            name=name,
            scope_path=root_path,
            transport=transport,
            start_line=server_node.start_line,
            end_line=declaration_end_line,
            enabled=(
                True if enabled_declaration is None else enabled_declaration.value
            ),
            enabled_declaration=enabled_declaration,
            required=(
                False if required_declaration is None else required_declaration.value
            ),
            required_declaration=required_declaration,
            command=command,
            arguments=self._string_array(document, nodes, path + ("args",)),
            working_directory=self._optional_string(nodes, path + ("cwd",)),
            endpoint=endpoint,
            bearer_token_env_var=self._optional_string(
                nodes, path + ("bearer_token_env_var",)
            ),
            auth_mode=self._optional_enum(
                nodes,
                path + ("auth",),
                McpAuthMode,
            ),
            oauth_resource=self._optional_string(nodes, path + ("oauth_resource",)),
            oauth_scopes=self._string_array(
                document,
                nodes,
                path + ("scopes",),
            ),
            enabled_tools=self._string_array(
                document,
                nodes,
                path + ("enabled_tools",),
            ),
            disabled_tools=self._string_array(
                document,
                nodes,
                path + ("disabled_tools",),
            ),
            startup_timeout_seconds=self._timeout(
                nodes,
                seconds_path=path + ("startup_timeout_sec",),
                milliseconds_path=path + ("startup_timeout_ms",),
            ),
            tool_timeout_seconds=self._timeout(
                nodes,
                seconds_path=path + ("tool_timeout_sec",),
                milliseconds_path=path + ("tool_timeout_ms",),
            ),
            default_approval_mode=self._optional_enum(
                nodes,
                path + ("default_tools_approval_mode",),
                McpApprovalMode,
            ),
            tool_policies=self._tool_policies(document, nodes, path + ("tools",)),
            experimental_environment=self._optional_enum(
                nodes,
                path + ("experimental_environment",),
                McpEnvironmentSource,
            ),
            static_environment_names=self._map_key_names(
                document,
                nodes,
                path + ("env",),
            ),
            environment_references=self._environment_references(
                document,
                nodes,
                path + ("env_vars",),
            ),
            static_http_header_names=self._map_key_names(
                document,
                nodes,
                path + ("http_headers",),
            ),
            environment_http_headers=self._environment_http_headers(
                document,
                nodes,
                path + ("env_http_headers",),
            ),
            unknown_fields=unknown,
        )

    @staticmethod
    def _mcp_roots(document: StructuredDocument) -> tuple[StructuredNode, ...]:
        roots = [
            node
            for node in document.nodes
            if node.kind is StructuredNodeKind.OBJECT
            and McpConfigurationParser._is_mcp_root_path(node.path)
        ]
        return tuple(sorted(roots, key=lambda node: (node.start_line, node.path)))

    @staticmethod
    def _is_mcp_root_path(path: StructuredPath) -> bool:
        return path == ("mcp_servers",) or (
            len(path) == 3 and path[0] == "plugins" and path[2] == "mcp_servers"
        )

    @staticmethod
    def _direct_children(
        document: StructuredDocument,
        path: StructuredPath,
    ) -> tuple[StructuredNode, ...]:
        return tuple(node for node in document.nodes if node.path[:-1] == path)

    def _string_array(
        self,
        document: StructuredDocument,
        nodes: dict[StructuredPath, StructuredNode],
        path: StructuredPath,
    ) -> tuple[SourceBackedValue[str], ...]:
        container = nodes.get(path)
        if container is None:
            return ()
        if container.kind is not StructuredNodeKind.ARRAY:
            self._raise(McpParseIssueCode.INVALID_FIELD, line=container.start_line)
        children = sorted(
            self._direct_children(document, path),
            key=lambda node: node.path[-1],
        )
        if len(children) > self._limits.max_list_items:
            self._raise(McpParseIssueCode.LIMIT_EXCEEDED, line=container.start_line)
        values: list[SourceBackedValue[str]] = []
        for child in children:
            if child.kind is not StructuredNodeKind.STRING:
                self._raise(McpParseIssueCode.INVALID_FIELD, line=child.start_line)
            values.append(self._source_value(child.value, child))  # type: ignore[arg-type]
        return tuple(values)

    def _map_key_names(
        self,
        document: StructuredDocument,
        nodes: dict[StructuredPath, StructuredNode],
        path: StructuredPath,
    ) -> tuple[SourceBackedValue[str], ...]:
        container = nodes.get(path)
        if container is None:
            return ()
        if container.kind is not StructuredNodeKind.OBJECT:
            self._raise(McpParseIssueCode.INVALID_FIELD, line=container.start_line)
        children = self._direct_children(document, path)
        if len(children) > self._limits.max_map_entries:
            self._raise(McpParseIssueCode.LIMIT_EXCEEDED, line=container.start_line)
        values: list[SourceBackedValue[str]] = []
        for child in children:
            name = child.path[-1]
            if not isinstance(name, str) or child.kind is not StructuredNodeKind.STRING:
                self._raise(McpParseIssueCode.INVALID_FIELD, line=child.start_line)
            values.append(
                SourceBackedValue(
                    value=name,
                    path=child.path,
                    start_line=child.start_line,
                    end_line=child.end_line,
                )
            )
        return tuple(values)

    def _environment_references(
        self,
        document: StructuredDocument,
        nodes: dict[StructuredPath, StructuredNode],
        path: StructuredPath,
    ) -> tuple[McpEnvironmentReference, ...]:
        container = nodes.get(path)
        if container is None:
            return ()
        if container.kind is not StructuredNodeKind.ARRAY:
            self._raise(McpParseIssueCode.INVALID_FIELD, line=container.start_line)
        items = sorted(
            self._direct_children(document, path),
            key=lambda node: node.path[-1],
        )
        if len(items) > self._limits.max_list_items:
            self._raise(McpParseIssueCode.LIMIT_EXCEEDED, line=container.start_line)
        result: list[McpEnvironmentReference] = []
        for item in items:
            if item.kind is StructuredNodeKind.STRING:
                result.append(
                    McpEnvironmentReference(
                        name=self._source_value(cast(str, item.value), item),
                        source=McpEnvironmentSource.LOCAL,
                    )
                )
                continue
            if item.kind is not StructuredNodeKind.OBJECT:
                self._raise(McpParseIssueCode.INVALID_FIELD, line=item.start_line)
            name = self._required_string(nodes, item.path + ("name",))
            source = self._optional_enum(
                nodes,
                item.path + ("source",),
                McpEnvironmentSource,
            )
            result.append(
                McpEnvironmentReference(
                    name=name,
                    source=(
                        McpEnvironmentSource.LOCAL if source is None else source.value
                    ),
                )
            )
        return tuple(result)

    def _environment_http_headers(
        self,
        document: StructuredDocument,
        nodes: dict[StructuredPath, StructuredNode],
        path: StructuredPath,
    ) -> tuple[McpHeaderEnvironmentReference, ...]:
        container = nodes.get(path)
        if container is None:
            return ()
        if container.kind is not StructuredNodeKind.OBJECT:
            self._raise(McpParseIssueCode.INVALID_FIELD, line=container.start_line)
        children = self._direct_children(document, path)
        if len(children) > self._limits.max_map_entries:
            self._raise(McpParseIssueCode.LIMIT_EXCEEDED, line=container.start_line)
        result: list[McpHeaderEnvironmentReference] = []
        for child in children:
            header = child.path[-1]
            if (
                not isinstance(header, str)
                or child.kind is not StructuredNodeKind.STRING
            ):
                self._raise(McpParseIssueCode.INVALID_FIELD, line=child.start_line)
            result.append(
                McpHeaderEnvironmentReference(
                    header=SourceBackedValue(
                        value=header,
                        path=child.path,
                        start_line=child.start_line,
                        end_line=child.end_line,
                    ),
                    environment_variable=self._source_value(
                        cast(str, child.value),
                        child,
                    ),
                )
            )
        return tuple(result)

    def _tool_policies(
        self,
        document: StructuredDocument,
        nodes: dict[StructuredPath, StructuredNode],
        path: StructuredPath,
    ) -> tuple[McpToolPolicy, ...]:
        container = nodes.get(path)
        if container is None:
            return ()
        if container.kind is not StructuredNodeKind.OBJECT:
            self._raise(McpParseIssueCode.INVALID_FIELD, line=container.start_line)
        children = self._direct_children(document, path)
        if len(children) > self._limits.max_map_entries:
            self._raise(McpParseIssueCode.LIMIT_EXCEEDED, line=container.start_line)
        policies: list[McpToolPolicy] = []
        for child in children:
            tool_name = child.path[-1]
            if (
                not isinstance(tool_name, str)
                or child.kind is not StructuredNodeKind.OBJECT
            ):
                self._raise(McpParseIssueCode.INVALID_FIELD, line=child.start_line)
            mode = self._optional_enum(
                nodes,
                child.path + ("approval_mode",),
                McpApprovalMode,
            )
            if mode is None:
                self._raise(McpParseIssueCode.INVALID_FIELD, line=child.start_line)
            policies.append(McpToolPolicy(tool_name=tool_name, approval_mode=mode))
        return tuple(policies)

    def _timeout(
        self,
        nodes: dict[StructuredPath, StructuredNode],
        *,
        seconds_path: StructuredPath,
        milliseconds_path: StructuredPath,
    ) -> SourceBackedValue[float] | None:
        seconds = nodes.get(seconds_path)
        milliseconds = nodes.get(milliseconds_path)
        if seconds is not None and milliseconds is not None:
            self._raise(
                McpParseIssueCode.CONFLICTING_FIELDS,
                line=milliseconds.start_line,
            )
        node = seconds if seconds is not None else milliseconds
        if node is None:
            return None
        if node.kind not in {StructuredNodeKind.INTEGER, StructuredNodeKind.FLOAT}:
            self._raise(McpParseIssueCode.INVALID_FIELD, line=node.start_line)
        value = float(cast(int | float, node.value))
        if milliseconds is not None:
            value /= 1_000
        if value <= 0:
            self._raise(McpParseIssueCode.INVALID_FIELD, line=node.start_line)
        return self._source_value(value, node)

    @staticmethod
    def _optional_string(
        nodes: dict[StructuredPath, StructuredNode],
        path: StructuredPath,
    ) -> SourceBackedValue[str] | None:
        node = nodes.get(path)
        if node is None:
            return None
        if node.kind is not StructuredNodeKind.STRING:
            raise McpParseError(McpParseIssueCode.INVALID_FIELD, line=node.start_line)
        return McpConfigurationParser._source_value(cast(str, node.value), node)

    @staticmethod
    def _required_string(
        nodes: dict[StructuredPath, StructuredNode],
        path: StructuredPath,
    ) -> SourceBackedValue[str]:
        value = McpConfigurationParser._optional_string(nodes, path)
        if value is None:
            parent = nodes.get(path[:-1])
            raise McpParseError(
                McpParseIssueCode.INVALID_FIELD,
                line=None if parent is None else parent.start_line,
            )
        return value

    @staticmethod
    def _optional_bool(
        nodes: dict[StructuredPath, StructuredNode],
        path: StructuredPath,
    ) -> SourceBackedValue[bool] | None:
        node = nodes.get(path)
        if node is None:
            return None
        if node.kind is not StructuredNodeKind.BOOLEAN:
            raise McpParseError(McpParseIssueCode.INVALID_FIELD, line=node.start_line)
        return McpConfigurationParser._source_value(cast(bool, node.value), node)

    @staticmethod
    def _optional_enum[E: StrEnum](
        nodes: dict[StructuredPath, StructuredNode],
        path: StructuredPath,
        enum_type: type[E],
    ) -> SourceBackedValue[E] | None:
        raw = McpConfigurationParser._optional_string(nodes, path)
        if raw is None:
            return None
        try:
            value = enum_type(raw.value)
        except ValueError as error:
            raise McpParseError(
                McpParseIssueCode.INVALID_FIELD,
                line=raw.start_line,
            ) from error
        return SourceBackedValue(
            value=value,
            path=raw.path,
            start_line=raw.start_line,
            end_line=raw.end_line,
        )

    @staticmethod
    def _source_value[T](value: T, node: StructuredNode) -> SourceBackedValue[T]:
        return SourceBackedValue(
            value=value,
            path=node.path,
            start_line=node.start_line,
            end_line=node.end_line,
        )

    @staticmethod
    def _parse_endpoint(value: str, *, line: int) -> McpEndpoint:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as error:
            raise McpParseError(
                McpParseIssueCode.INVALID_ENDPOINT,
                line=line,
            ) from error
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise McpParseError(McpParseIssueCode.INVALID_ENDPOINT, line=line)
        host = parsed.hostname.lower()
        return McpEndpoint(
            scheme=parsed.scheme.lower(),
            host=host,
            port=port,
            path=parsed.path or "/",
            query_or_fragment_present=bool(parsed.query or parsed.fragment),
            is_local=host in {"localhost", "127.0.0.1", "::1"},
        )

    @staticmethod
    def _raise(
        code: McpParseIssueCode,
        *,
        line: int | None,
    ) -> NoReturn:
        raise McpParseError(code, line=line)
