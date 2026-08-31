"""Consistency checks for the P1-30 README and PoC usage guide."""

from __future__ import annotations

import re
from pathlib import Path

from typer.testing import CliRunner

from agentsec.cli import app
from agentsec.versioning import current_versions

REPOSITORY_ROOT = Path(__file__).parents[1]
README_PATH = REPOSITORY_ROOT / "README.md"
USAGE_PATH = REPOSITORY_ROOT / "docs" / "poc-usage.md"
runner = CliRunner()


def _local_markdown_links(path: Path) -> tuple[str, ...]:
    """Return document-relative non-URL links from one Markdown file."""

    text = path.read_text(encoding="utf-8")
    links = re.findall(r"\[[^\]]+\]\(([^)]+)\)", text)
    return tuple(
        link.split("#", maxsplit=1)[0]
        for link in links
        if link
        and not link.startswith("#")
        and "://" not in link
        and not link.startswith("mailto:")
    )


def test_readme_and_usage_guide_local_links_resolve() -> None:
    """A new user never lands on a missing repository document."""

    for document in (README_PATH, USAGE_PATH):
        for link in _local_markdown_links(document):
            assert (document.parent / link).resolve().exists(), (document, link)


def test_usage_guide_records_the_current_interface_versions() -> None:
    """Copyable compatibility values match the implementation constants."""

    text = USAGE_PATH.read_text(encoding="utf-8")
    versions = current_versions()
    expected = {
        "PACKAGE_VERSION": versions.package,
        "CONFIG_SCHEMA_VERSION": versions.config_schema,
        "DOMAIN_SCHEMA_VERSION": versions.domain_schema,
        "AGENT_MANIFEST_SCHEMA_VERSION": versions.agent_manifest_schema,
        "CAPABILITY_DIFF_SCHEMA_VERSION": versions.capability_diff_schema,
        "CAPABILITY_RULE_PACK_VERSION": versions.capability_rule_pack,
        "CAPABILITY_RISK_MODEL_VERSION": versions.capability_risk_model,
        "CAPABILITY_ASSESSMENT_OUTPUT_VERSION": (versions.capability_assessment_output),
        "CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION": (
            versions.capability_change_impact_output
        ),
        "BASELINE_SCHEMA_VERSION": versions.baseline_schema,
        "DIFF_OUTPUT_VERSION": versions.diff_output,
        "ASSESSMENT_OUTPUT_VERSION": versions.assessment_output,
        "RULE_PACK_VERSION": versions.rule_pack,
        "RISK_MODEL_VERSION": versions.risk_model,
        "CVSS_HARD_GATE_VERSION": versions.cvss_hard_gate,
    }

    for name, version in expected.items():
        assert f"{name} = {version}" in text


def test_documented_command_surface_matches_cli_help() -> None:
    """The guide names every current command without inventing rule enumeration."""

    result = runner.invoke(app, ["--help"])
    guide = USAGE_PATH.read_text(encoding="utf-8")

    assert result.exit_code == 0
    for command in (
        "version",
        "scan",
        "baseline",
        "diff",
        "rules",
        "manifest",
        "capability",
    ):
        assert command in result.stdout
        assert command in guide
    assert "agentsec rules list" in guide
    assert "agentsec manifest" in guide
    assert "agentsec capability assess" in guide
    assert "agentsec capability diff" in guide
    assert "agentsec capability impact" in guide
    assert "agentsec capability impact" in guide
    assert "agentsec capability rules list" in guide
    assert "not implemented" not in guide


def test_documented_replay_cases_exist() -> None:
    """The four copyable PoC scenarios remain available in the fixture corpus."""

    for relative_path in (
        "testdata/safe/minimal-agent",
        "testdata/risky/shell-secret-network",
        "testdata/prompt-injection/ignore-scanner",
        "testdata/malformed/invalid-utf8",
    ):
        case_root = REPOSITORY_ROOT / relative_path
        assert case_root.is_dir()
        assert (case_root / "case.json").is_file()
