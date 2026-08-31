"""CLI delivery for the reviewed deterministic Rule Pack inventory."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

import typer

from agentsec.rules import builtin_markdown_rules
from agentsec.rules.localization import chinese_category_label, chinese_rule_title
from agentsec.versioning import RULE_PACK_VERSION


class RuleListLanguage(StrEnum):
    """Supported deterministic Rule inventory display languages."""

    ENGLISH = "en"
    CHINESE = "zh"


RuleLanguageOption = Annotated[
    RuleListLanguage,
    typer.Option(
        "--language",
        "-l",
        help="Rule inventory display language: en or zh.",
        case_sensitive=False,
    ),
]


def register_rules_commands(application: typer.Typer) -> None:
    """Register the required Phase 1 `rules list` command group."""

    rules_application = typer.Typer(
        help="Inspect the built-in deterministic security Rule Pack.",
        add_completion=False,
        no_args_is_help=True,
        rich_markup_mode="rich",
        context_settings={"help_option_names": ["-h", "--help"]},
    )

    @rules_application.command("list")
    def list_rules(
        language: RuleLanguageOption = RuleListLanguage.ENGLISH,
    ) -> None:
        """List stable Rule IDs, categories, and localized titles."""

        rules = builtin_markdown_rules()
        if language is RuleListLanguage.CHINESE:
            typer.echo(
                f"规则包 {RULE_PACK_VERSION}：{len(rules)} 条确定性 Markdown 安全规则"
            )
            typer.echo("规则ID\t风险类别\t中文标题")
            for rule in rules:
                metadata = rule.metadata
                typer.echo(
                    f"{metadata.rule_id}\t"
                    f"{chinese_category_label(metadata.category)}\t"
                    f"{chinese_rule_title(metadata.rule_id)}"
                )
            return

        typer.echo(
            f"Rule Pack {RULE_PACK_VERSION}: {len(rules)} deterministic Markdown rules"
        )
        typer.echo("RULE_ID\tCATEGORY\tTITLE")
        for rule in rules:
            metadata = rule.metadata
            typer.echo(
                f"{metadata.rule_id}\t{metadata.category.value}\t{metadata.title}"
            )

    application.add_typer(rules_application, name="rules")
