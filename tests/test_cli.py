"""Tests for the stable AgentSec command-line root interface."""

from __future__ import annotations

from typer.testing import CliRunner

from agentsec import __version__
from agentsec.cli import app

runner = CliRunner()


def test_no_arguments_displays_help_successfully() -> None:
    """Invoking the root without a subcommand is an informative success."""

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "Evidence-backed security diagnostics" in result.stdout
    assert "scan" in result.stdout
    assert "baseline" in result.stdout
    assert "version" in result.stdout
    assert "rules" in result.stdout


def test_help_option_displays_root_help() -> None:
    """Both conventional help names are registered on the root application."""

    long_result = runner.invoke(app, ["--help"])
    short_result = runner.invoke(app, ["-h"])

    assert long_result.exit_code == 0
    assert short_result.exit_code == 0
    assert "Usage:" in long_result.stdout
    assert "Usage:" in short_result.stdout


def test_version_subcommand_prints_the_package_version() -> None:
    """The explicit version command uses the central package version."""

    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout == f"agentsec {__version__}\n"


def test_version_option_prints_the_package_version() -> None:
    """The eager global version option works without choosing a command."""

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == f"agentsec {__version__}\n"


def test_unknown_command_returns_a_nonzero_exit_code() -> None:
    """Unknown commands fail visibly instead of being silently accepted."""

    result = runner.invoke(app, ["unknown-command"])

    assert result.exit_code == 2
    assert "No such command" in result.stderr
