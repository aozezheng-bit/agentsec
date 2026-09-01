"""Safe YAML loading and precedence rules for AgentSec project config."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agentsec.config.models import ProjectConfig, default_project_config
from agentsec.versioning import CONFIG_SCHEMA_VERSION, can_read_interface_version

DEFAULT_CONFIG_RELATIVE_PATH = Path(".agentsec/config.yaml")
MAX_CONFIG_FILE_SIZE_BYTES = 262_144


class ConfigSource(StrEnum):
    """How the effective project configuration was selected."""

    DEFAULT = "default"
    DISCOVERED = "discovered"
    EXPLICIT = "explicit"


@dataclass(frozen=True, slots=True)
class LoadedProjectConfig:
    """Effective configuration plus its provenance."""

    config: ProjectConfig
    source: ConfigSource
    path: Path | None


class ConfigurationError(RuntimeError):
    """A safe, user-facing configuration loading failure."""

    def __init__(self, message: str, *, path: Path | None = None) -> None:
        self.path = path
        prefix = f"{path}: " if path is not None else ""
        super().__init__(f"{prefix}{message}")


def load_project_config(
    project_root: Path,
    *,
    config_path: Path | None = None,
) -> LoadedProjectConfig:
    """Load explicit, discovered, or default project configuration.

    Explicit paths are user-selected and may live outside the project root.
    Automatically discovered config symlinks must remain within the root.
    """

    if config_path is not None:
        selected_path = config_path
        source = ConfigSource.EXPLICIT
        if not selected_path.exists():
            raise ConfigurationError(
                "explicit configuration file does not exist",
                path=selected_path,
            )
    else:
        selected_path = project_root / DEFAULT_CONFIG_RELATIVE_PATH
        source = ConfigSource.DISCOVERED
        if not selected_path.exists() and not selected_path.is_symlink():
            return LoadedProjectConfig(
                config=default_project_config(),
                source=ConfigSource.DEFAULT,
                path=None,
            )
        _validate_discovered_config_location(project_root, selected_path)

    payload = _read_yaml_mapping(selected_path)
    config = _validate_project_config(payload, selected_path)
    return LoadedProjectConfig(config=config, source=source, path=selected_path)


def _validate_discovered_config_location(project_root: Path, path: Path) -> None:
    """Prevent an automatically discovered symlink from escaping the root."""

    try:
        resolved_root = project_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ConfigurationError(
            "could not resolve discovered configuration path",
            path=path,
        ) from error

    if not resolved_path.is_relative_to(resolved_root):
        raise ConfigurationError(
            "discovered configuration resolves outside the project root",
            path=path,
        )


def _read_yaml_mapping(path: Path) -> dict[str, Any]:
    """Read one bounded UTF-8 YAML mapping using the safe loader."""

    try:
        stat = path.stat()
    except OSError as error:
        raise ConfigurationError(
            "could not stat configuration file",
            path=path,
        ) from error

    if not path.is_file():
        raise ConfigurationError("configuration path is not a file", path=path)
    if stat.st_size > MAX_CONFIG_FILE_SIZE_BYTES:
        raise ConfigurationError(
            f"configuration exceeds {MAX_CONFIG_FILE_SIZE_BYTES} bytes",
            path=path,
        )

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ConfigurationError(
            "configuration must be valid UTF-8",
            path=path,
        ) from error
    except OSError as error:
        raise ConfigurationError(
            "could not read configuration file",
            path=path,
        ) from error

    if not text.strip():
        raise ConfigurationError("configuration file is empty", path=path)

    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ConfigurationError("invalid YAML configuration", path=path) from error

    if not isinstance(payload, dict):
        raise ConfigurationError("configuration root must be a mapping", path=path)
    if "version" not in payload:
        raise ConfigurationError("configuration requires a version field", path=path)

    return payload


def _validate_project_config(payload: dict[str, Any], path: Path) -> ProjectConfig:
    """Validate schema shape and compatibility after safe YAML decoding."""

    try:
        config = ProjectConfig.model_validate(payload)
    except ValidationError as error:
        raise ConfigurationError(
            f"configuration validation failed: {error.errors(include_url=False)}",
            path=path,
        ) from error

    if not can_read_interface_version(
        produced=config.version,
        supported=CONFIG_SCHEMA_VERSION,
    ):
        raise ConfigurationError(
            "unsupported configuration version "
            f"'{config.version}'; supported version is '{CONFIG_SCHEMA_VERSION}'",
            path=path,
        )

    return config
