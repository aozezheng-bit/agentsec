"""Tests for strict, versioned and non-executing project configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.config import (
    CONFIG_SCHEMA_VERSION,
    MAX_CONFIG_FILE_SIZE_BYTES,
    ConfigSource,
    ConfigurationError,
    OutputFormat,
    default_project_config,
    load_project_config,
)


def write_config(path: Path, text: str) -> Path:
    """Write a UTF-8 config fixture and return its path."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_missing_project_config_uses_versioned_secure_defaults(tmp_path: Path) -> None:
    """Repositories without config remain usable and deterministic."""

    loaded = load_project_config(tmp_path)

    assert loaded.config == default_project_config()
    assert loaded.source is ConfigSource.DEFAULT
    assert loaded.path is None
    assert loaded.config.output.redact_secrets is True


def test_project_local_config_is_discovered_and_validated(tmp_path: Path) -> None:
    """The conventional project-local path overrides built-in defaults."""

    path = write_config(
        tmp_path / ".agentsec/config.yaml",
        f"""
version: "{CONFIG_SCHEMA_VERSION}"
discovery:
  include:
    - AGENTS.md
    - "**/SKILL.md"
  exclude:
    - ".git/**"
limits:
  max_file_size_bytes: 2048
  max_depth: 7
  max_assets: 12
output:
  format: json
  redact_secrets: true
""".lstrip(),
    )

    loaded = load_project_config(tmp_path)

    assert loaded.source is ConfigSource.DISCOVERED
    assert loaded.path == path
    assert loaded.config.discovery.include == ("AGENTS.md", "**/SKILL.md")
    assert loaded.config.limits.max_depth == 7
    assert loaded.config.output.format is OutputFormat.JSON


def test_explicit_config_takes_precedence_over_discovered_config(
    tmp_path: Path,
) -> None:
    """A user-selected path is the highest-precedence project config."""

    write_config(
        tmp_path / ".agentsec/config.yaml",
        f'version: "{CONFIG_SCHEMA_VERSION}"\nlimits:\n  max_depth: 5\n',
    )
    explicit_path = write_config(
        tmp_path / "alternate.yaml",
        f'version: "{CONFIG_SCHEMA_VERSION}"\nlimits:\n  max_depth: 9\n',
    )

    loaded = load_project_config(tmp_path, config_path=explicit_path)

    assert loaded.source is ConfigSource.EXPLICIT
    assert loaded.path == explicit_path
    assert loaded.config.limits.max_depth == 9


def test_explicit_config_may_live_outside_project_root(tmp_path: Path) -> None:
    """An explicit path represents deliberate user-selected input."""

    project_root = tmp_path / "project"
    project_root.mkdir()
    external_path = write_config(
        tmp_path / "external/config.yaml",
        f'version: "{CONFIG_SCHEMA_VERSION}"\n',
    )

    loaded = load_project_config(project_root, config_path=external_path)

    assert loaded.source is ConfigSource.EXPLICIT
    assert loaded.path == external_path


def test_missing_explicit_config_is_an_error(tmp_path: Path) -> None:
    """Explicit operator intent is never silently replaced by defaults."""

    with pytest.raises(ConfigurationError, match="does not exist"):
        load_project_config(tmp_path, config_path=tmp_path / "missing.yaml")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "empty"),
        ("- one\n- two\n", "root must be a mapping"),
        ("version: [\n", "invalid YAML"),
        ("output:\n  format: text\n", "requires a version"),
        (
            f'version: "{CONFIG_SCHEMA_VERSION}"\nunknown: true\n',
            "validation failed",
        ),
        (
            'version: "0.2.0"\n',
            "unsupported configuration version",
        ),
        (
            f'version: "{CONFIG_SCHEMA_VERSION}"\noutput:\n  redact_secrets: false\n',
            "secret redaction cannot be disabled",
        ),
        (
            f'version: "{CONFIG_SCHEMA_VERSION}"\ndiscovery:\n'
            '  include: ["../AGENTS.md"]\n',
            "must not traverse",
        ),
        (
            f'version: "{CONFIG_SCHEMA_VERSION}"\ndiscovery:\n'
            '  include: ["AGENTS.md", "AGENTS.md"]\n',
            "must be unique",
        ),
    ],
)
def test_invalid_configuration_is_rejected(
    tmp_path: Path,
    content: str,
    message: str,
) -> None:
    """Malformed, incompatible, or unsafe fields fail closed."""

    path = write_config(tmp_path / "config.yaml", content)

    with pytest.raises(ConfigurationError, match=message):
        load_project_config(tmp_path, config_path=path)


def test_python_object_yaml_tags_are_not_constructed(tmp_path: Path) -> None:
    """Safe YAML loading rejects arbitrary Python object constructors."""

    path = write_config(
        tmp_path / "config.yaml",
        "!!python/object/apply:os.system ['echo unsafe']\n",
    )

    with pytest.raises(ConfigurationError, match="invalid YAML"):
        load_project_config(tmp_path, config_path=path)


def test_invalid_utf8_is_rejected(tmp_path: Path) -> None:
    """Configuration decoding errors are visible and do not fall back."""

    path = tmp_path / "config.yaml"
    path.write_bytes(b'version: "0.1.0"\n\xff\xfe')

    with pytest.raises(ConfigurationError, match="valid UTF-8"):
        load_project_config(tmp_path, config_path=path)


def test_oversized_config_is_rejected_before_yaml_parsing(tmp_path: Path) -> None:
    """A bounded config prevents configuration-based resource exhaustion."""

    path = tmp_path / "config.yaml"
    path.write_bytes(b" " * (MAX_CONFIG_FILE_SIZE_BYTES + 1))

    with pytest.raises(ConfigurationError, match="exceeds"):
        load_project_config(tmp_path, config_path=path)


def test_discovered_config_symlink_cannot_escape_project_root(
    tmp_path: Path,
) -> None:
    """Automatic discovery cannot read a config file outside the target root."""

    project_root = tmp_path / "project"
    config_directory = project_root / ".agentsec"
    config_directory.mkdir(parents=True)
    external_path = write_config(
        tmp_path / "external.yaml",
        f'version: "{CONFIG_SCHEMA_VERSION}"\n',
    )
    (config_directory / "config.yaml").symlink_to(external_path)

    with pytest.raises(ConfigurationError, match="outside the project root"):
        load_project_config(project_root)


def test_discovered_config_symlink_cycle_is_a_configuration_error(
    tmp_path: Path,
) -> None:
    """A cyclic automatically discovered config link cannot crash the CLI."""

    config_directory = tmp_path / ".agentsec"
    config_directory.mkdir()
    config_path = config_directory / "config.yaml"
    config_path.symlink_to(config_path)

    with pytest.raises(ConfigurationError, match="could not resolve"):
        load_project_config(tmp_path)
