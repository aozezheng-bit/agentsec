"""Versioned Agent Manifest vocabulary shared by builders and resolvers."""

from __future__ import annotations

from enum import StrEnum


class ManifestSourceScope(StrEnum):
    """Portable trust scope for a Manifest source asset."""

    PROJECT = "project"
    USER = "user"
    PLUGIN = "plugin"


class ManifestAssetFormat(StrEnum):
    """Normalized syntax of one Manifest source asset."""

    MARKDOWN = "markdown"
    RULES = "rules"
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"


class ManifestAssetRole(StrEnum):
    """Normalized reason one source participates in the Manifest."""

    AGENT_INSTRUCTIONS = "agent_instructions"
    INSTRUCTION_OVERRIDE = "instruction_override"
    SKILL = "skill"
    PREFIX_RULES = "prefix_rules"
    FRAMEWORK_CONFIG = "framework_config"
    MCP_CONFIG = "mcp_config"


class ManifestResolutionStatus(StrEnum):
    """How completely one Manifest dimension has been deterministically resolved."""

    UNRESOLVED = "unresolved"
    PARTIAL = "partial"
    RESOLVED = "resolved"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    CONFLICT = "conflict"


class ManifestInstructionKind(StrEnum):
    """Instruction-source roles understood before inheritance resolution."""

    BASE = "base"
    OVERRIDE = "override"


class ManifestInstructionResolutionAction(StrEnum):
    """Decision recorded for one instruction candidate."""

    SELECTED = "selected"
    OVERRIDDEN = "overridden"
    CONFLICT = "conflict"


class ManifestInstructionResolutionReason(StrEnum):
    """Safe explanation for one instruction resolution decision."""

    ONLY_CANDIDATE = "only_candidate"
    INHERITED = "inherited"
    OVERRIDE_REPLACES_BASE = "override_replaces_base"
    AMBIGUOUS_DUPLICATE = "ambiguous_duplicate"


class ManifestConfigurationKind(StrEnum):
    """Configuration families represented by one static source asset."""

    FRAMEWORK_CONFIG = "framework_config"
    PREFIX_RULES = "prefix_rules"
    MCP_CONFIG = "mcp_config"


class ManifestConfigurationResolutionAction(StrEnum):
    """Decision recorded for one configuration source."""

    SELECTED = "selected"
    CONFLICT = "conflict"


class ManifestConfigurationResolutionReason(StrEnum):
    """Safe explanation for one configuration source ordering decision."""

    USER_SCOPE = "user_scope"
    PROJECT_ROOT = "project_root"
    NESTED_PROJECT = "nested_project"
    SAME_PRECEDENCE = "same_precedence"
    INCOMPLETE_COVERAGE = "incomplete_coverage"


class ManifestToolKind(StrEnum):
    """Normalized tool families available to later capability extraction."""

    SKILL = "skill"
    MCP_SERVER = "mcp_server"
    MCP_TOOL = "mcp_tool"
    COMMAND = "command"
    BUILTIN = "builtin"
    PLUGIN = "plugin"
    OTHER = "other"


class ManifestToolAvailability(StrEnum):
    """Static availability state of a tool declaration."""

    DECLARED = "declared"
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class ManifestToolSideEffect(StrEnum):
    """Potential side-effect families assigned by later deterministic analysis."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    DESTRUCTIVE = "destructive"
    SECRET_ACCESS = "secret_access"
    PRIVILEGED = "privileged"
    UNKNOWN = "unknown"


class ManifestPermissionAction(StrEnum):
    """Normalized permission actions for an Agent capability profile."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    SECRET_ACCESS = "secret_access"
    ADMIN = "admin"
    DEPLOY = "deploy"
    PUBLISH = "publish"
    DELEGATE = "delegate"
    PERSIST = "persist"
    UNKNOWN = "unknown"


class ManifestPermissionEffect(StrEnum):
    """Decision applied to a normalized permission declaration."""

    ALLOW = "allow"
    PROMPT = "prompt"
    DENY = "deny"
    UNKNOWN = "unknown"


class ManifestResourceKind(StrEnum):
    """Resource families to which permissions or controls may apply."""

    FILESYSTEM = "filesystem"
    REPOSITORY = "repository"
    SHELL = "shell"
    NETWORK = "network"
    ENVIRONMENT = "environment"
    SECRET_STORE = "secret_store"
    IDENTITY = "identity"
    PRODUCTION = "production"
    TOOL = "tool"
    MEMORY = "memory"
    OTHER = "other"
    UNKNOWN = "unknown"


class ManifestResourceScope(StrEnum):
    """Normalized operational scope for a permission or resource."""

    PROJECT = "project"
    USER = "user"
    SYSTEM = "system"
    EXTERNAL = "external"
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"
    UNKNOWN = "unknown"


class ManifestControlKind(StrEnum):
    """Guardrail and policy controls represented in the Manifest."""

    HUMAN_APPROVAL = "human_approval"
    SANDBOX = "sandbox"
    PREFIX_RULE = "prefix_rule"
    TRUST = "trust"
    TOOL_FILTER = "tool_filter"
    TIMEOUT = "timeout"
    NETWORK_POLICY = "network_policy"
    SECRET_HANDLING = "secret_handling"
    ENABLEMENT = "enablement"
    REQUIRED = "required"
    OTHER = "other"


class ManifestControlState(StrEnum):
    """Normalized state of one Agent control."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    REQUIRED = "required"
    OPTIONAL = "optional"
    ALLOW = "allow"
    PROMPT = "prompt"
    DENY = "deny"
    CONFIGURED = "configured"
    UNKNOWN = "unknown"


class ManifestPrincipalKind(StrEnum):
    """Runtime principal families used by an Agent or tool."""

    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    API_CLIENT = "api_client"
    OAUTH_SESSION = "oauth_session"
    CHATGPT = "chatgpt"
    PLUGIN = "plugin"
    ANONYMOUS = "anonymous"
    UNKNOWN = "unknown"


class ManifestAuthenticationKind(StrEnum):
    """Authentication mechanisms without credential values."""

    NONE = "none"
    API_KEY = "api_key"
    TOKEN = "token"
    OAUTH = "oauth"
    ENVIRONMENT = "environment"
    CHATGPT = "chatgpt"
    UNKNOWN = "unknown"


class ManifestEnvironmentKind(StrEnum):
    """Operational environment associated with a runtime identity."""

    LOCAL = "local"
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class ManifestRelationKind(StrEnum):
    """Agent, tool, Skill, MCP, and memory relationship families."""

    DELEGATES_TO = "delegates_to"
    USES_SKILL = "uses_skill"
    USES_MCP = "uses_mcp"
    USES_TOOL = "uses_tool"
    READS_MEMORY = "reads_memory"
    WRITES_MEMORY = "writes_memory"
    PERSISTS_MEMORY = "persists_memory"
    OTHER = "other"


class ManifestRelationState(StrEnum):
    """Resolution state of one normalized relationship."""

    DECLARED = "declared"
    ACTIVE = "active"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class ManifestUnknownDimension(StrEnum):
    """Manifest dimensions to which an explicit Unknown may belong."""

    IDENTITY = "identity"
    INSTRUCTIONS = "instructions"
    TOOLS = "tools"
    PERMISSIONS = "permissions"
    CONTROLS = "controls"
    RUNTIME_IDENTITIES = "runtime_identities"
    RELATIONSHIPS = "relationships"
    COVERAGE = "coverage"


class ManifestUnknownReason(StrEnum):
    """Stable reasons a Manifest fact cannot yet be resolved."""

    NOT_ANALYZED = "not_analyzed"
    MISSING_SOURCE = "missing_source"
    INCOMPLETE_COVERAGE = "incomplete_coverage"
    UNSUPPORTED_FIELD = "unsupported_field"
    AMBIGUOUS_PRECEDENCE = "ambiguous_precedence"
    CONFLICTING_DECLARATIONS = "conflicting_declarations"
    RUNTIME_VERIFICATION_REQUIRED = "runtime_verification_required"


class ManifestCoverageIssueCode(StrEnum):
    """Stable source-coverage failures retained in an Agent Manifest."""

    UNREADABLE = "unreadable"
    UNSUPPORTED_ENCODING = "unsupported_encoding"
    TOO_LARGE = "too_large"
    DEPTH_EXCEEDED = "depth_exceeded"
    ASSET_LIMIT_EXCEEDED = "asset_limit_exceeded"
    EXTERNAL_SYMLINK = "external_symlink"
    UNSUPPORTED_FORMAT = "unsupported_format"
    PARSE_ERROR = "parse_error"
    UNKNOWN = "unknown"
