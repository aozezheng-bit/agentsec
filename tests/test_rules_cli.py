"""Release-surface tests for `agentsec rules list`."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from agentsec.cli import app, run_cli
from agentsec.rules import (
    BUILTIN_MARKDOWN_RULE_COUNT,
    BUILTIN_MARKDOWN_RULE_IDS,
    builtin_markdown_rules,
)
from agentsec.versioning import RULE_PACK_VERSION

runner = CliRunner()


def test_root_help_exposes_the_required_rules_command() -> None:
    """The final Phase 1 command surface includes deterministic Rule discovery."""

    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "rules" in result.stdout


def test_rules_list_outputs_the_complete_stable_rule_pack() -> None:
    """Users can inspect every production Rule ID, category, and title."""

    result = runner.invoke(app, ["rules", "list"])

    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    assert lines[0] == (
        f"Rule Pack {RULE_PACK_VERSION}: "
        f"{BUILTIN_MARKDOWN_RULE_COUNT} deterministic Markdown rules"
    )
    assert lines[1] == "RULE_ID\tCATEGORY\tTITLE"
    rows = [line.split("\t", maxsplit=2) for line in lines[2:]]
    rules = builtin_markdown_rules()
    assert [row[0] for row in rows] == list(BUILTIN_MARKDOWN_RULE_IDS)
    assert [row[1] for row in rows] == [rule.metadata.category.value for rule in rules]
    assert [row[2] for row in rows] == [rule.metadata.title for rule in rules]


def test_installed_runner_executes_rules_list_successfully(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The installed/module entry-point path exposes the same Rule inventory."""

    assert run_cli(["rules", "list"]) == 0
    captured = capsys.readouterr()
    assert "Rule Pack" in captured.out
    assert captured.err == ""


def test_rules_list_can_render_the_complete_chinese_inventory() -> None:
    """Chinese users can inspect all stable IDs with reviewed local labels."""

    result = runner.invoke(app, ["rules", "list", "--language", "zh"])

    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    assert lines[0] == (
        f"规则包 {RULE_PACK_VERSION}："
        f"{BUILTIN_MARKDOWN_RULE_COUNT} 条确定性 Markdown 安全规则"
    )
    assert lines[1] == "规则ID\t风险类别\t中文标题"
    rows = [line.split("\t", maxsplit=2) for line in lines[2:]]
    assert [row[0] for row in rows] == list(BUILTIN_MARKDOWN_RULE_IDS)
    assert all(row[1] for row in rows)
    assert all(row[2] for row in rows)
    assert any("人工审批" in row[2] for row in rows)
    assert any("命令执行" in row[2] for row in rows)
