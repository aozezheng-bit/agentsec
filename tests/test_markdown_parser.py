"""Tests for safe, source-backed CommonMark block parsing."""

from __future__ import annotations

from pathlib import Path
from typing import Never

import pytest

from agentsec.parsers import (
    MarkdownBlock,
    MarkdownBlockKind,
    MarkdownItParser,
    MarkdownParseError,
)


def test_parses_required_blocks_with_exact_source_ranges() -> None:
    """Headings, paragraphs, list items and code retain 1-based line evidence."""

    content = (
        "# Heading *one*\n"
        "\n"
        "Paragraph **bold**\n"
        "continued.\n"
        "\n"
        "- first item\n"
        "- second item\n"
        "  - nested item\n"
        "\n"
        "```python extra\n"
        'print("hello")\n'
        "```\n"
        "\n"
        "    indented()\n"
    )

    document = MarkdownItParser().parse(content)

    assert document.source_line_count == 14
    assert [block.kind for block in document.blocks] == [
        MarkdownBlockKind.HEADING,
        MarkdownBlockKind.PARAGRAPH,
        MarkdownBlockKind.LIST_ITEM,
        MarkdownBlockKind.LIST_ITEM,
        MarkdownBlockKind.LIST_ITEM,
        MarkdownBlockKind.FENCED_CODE,
        MarkdownBlockKind.INDENTED_CODE,
    ]

    heading = document.blocks[0]
    assert (heading.start_line, heading.end_line) == (1, 1)
    assert heading.raw_text == "# Heading *one*\n"
    assert heading.text == "Heading one"
    assert heading.heading_level == 1
    assert heading.heading_path == ("Heading one",)

    paragraph = document.blocks[1]
    assert (paragraph.start_line, paragraph.end_line) == (3, 4)
    assert paragraph.raw_text == "Paragraph **bold**\ncontinued.\n"
    assert paragraph.text == "Paragraph bold\ncontinued."
    assert paragraph.heading_path == ("Heading one",)

    first_item, second_item, nested_item = document.blocks[2:5]
    assert first_item.text == "first item"
    assert first_item.ordered is False
    assert first_item.list_depth == 1
    assert (first_item.start_line, first_item.end_line) == (6, 6)
    assert second_item.text == "second item"
    assert second_item.list_depth == 1
    assert (second_item.start_line, second_item.end_line) == (7, 9)
    assert nested_item.text == "nested item"
    assert nested_item.list_depth == 2
    assert (nested_item.start_line, nested_item.end_line) == (8, 9)

    fence = document.blocks[5]
    assert (fence.start_line, fence.end_line) == (10, 12)
    assert fence.text == 'print("hello")\n'
    assert fence.fence_info == "python extra"
    assert fence.raw_text.startswith("```python extra\n")

    indented = document.blocks[6]
    assert (indented.start_line, indented.end_line) == (14, 14)
    assert indented.text == "indented()\n"


def test_heading_hierarchy_is_attached_to_following_blocks() -> None:
    """Heading paths provide deterministic section context without a tree API."""

    content = (
        "# Root\n\n"
        "## Child\n\n"
        "Child paragraph.\n\n"
        "### Grandchild\n\n"
        "Nested paragraph.\n\n"
        "# Reset\n\n"
        "Reset paragraph.\n"
    )

    document = MarkdownItParser().parse(content)

    assert [block.heading_path for block in document.blocks] == [
        ("Root",),
        ("Root", "Child"),
        ("Root", "Child"),
        ("Root", "Child", "Grandchild"),
        ("Root", "Child", "Grandchild"),
        ("Reset",),
        ("Reset",),
    ]


def test_ordered_and_nested_list_metadata_is_preserved() -> None:
    """Rules can distinguish ordered list structure without reparsing raw text."""

    content = "1. first\n2. second\n   - nested\n"

    document = MarkdownItParser().parse(content)

    assert [
        (block.text, block.ordered, block.list_depth) for block in document.blocks
    ] == [
        ("first", True, 1),
        ("second", True, 1),
        ("nested", False, 2),
    ]


def test_unclosed_fence_is_treated_as_data_to_end_of_document() -> None:
    """Tolerated malformed Markdown remains bounded source-backed input."""

    content = "# Heading\n\n```shell\necho never-execute\n"

    document = MarkdownItParser().parse(content)

    fence = document.blocks[1]
    assert fence.kind is MarkdownBlockKind.FENCED_CODE
    assert (fence.start_line, fence.end_line) == (3, 4)
    assert fence.text == "echo never-execute\n"
    assert fence.fence_info == "shell"


def test_empty_markdown_produces_an_empty_document() -> None:
    """An empty, valid collected asset does not become a parse failure."""

    document = MarkdownItParser().parse("")

    assert document.source_line_count == 0
    assert document.blocks == ()


def test_parser_never_executes_code_or_html(tmp_path: Path) -> None:
    """Executable-looking source stays inert while its text is extracted."""

    marker = tmp_path / "must-not-exist"
    content = (
        "<script>dangerous()</script>\n\n"
        "```python\n"
        f"from pathlib import Path; Path({str(marker)!r}).touch()\n"
        "```\n"
    )

    document = MarkdownItParser().parse(content)

    assert not marker.exists()
    assert document.blocks[0].kind is MarkdownBlockKind.PARAGRAPH
    assert "<script>" in document.blocks[0].raw_text
    assert document.blocks[1].kind is MarkdownBlockKind.FENCED_CODE


def test_links_remain_unfetched_input_for_later_reference_extraction() -> None:
    """P1-09 extracts visible text but does not access or classify link targets."""

    content = "Read [the policy](https://invalid.example/never-fetch).\n"

    document = MarkdownItParser().parse(content)

    assert document.blocks[0].text == "Read the policy."
    assert "https://invalid.example/never-fetch" in document.blocks[0].raw_text


def test_block_model_rejects_incoherent_kind_metadata() -> None:
    """Internal parser output cannot silently carry contradictory metadata."""

    with pytest.raises(ValueError, match="heading block requires"):
        MarkdownBlock(
            kind=MarkdownBlockKind.HEADING,
            start_line=1,
            end_line=1,
            raw_text="# Heading\n",
            text="Heading",
        )

    with pytest.raises(ValueError, match="list item requires"):
        MarkdownBlock(
            kind=MarkdownBlockKind.LIST_ITEM,
            start_line=1,
            end_line=1,
            raw_text="- item\n",
            text="item",
        )


def test_parser_wraps_internal_exceptions_without_source_disclosure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected dependency failures become fixed safe parser errors."""

    parser = MarkdownItParser()
    secret = "dependency-secret-marker"

    def fail_parse(content: str) -> Never:
        raise RuntimeError(f"{secret}: {content}")

    monkeypatch.setattr(parser._parser, "parse", fail_parse)

    with pytest.raises(MarkdownParseError) as error:
        parser.parse("untrusted source")

    assert str(error.value) == "Markdown parsing failed safely."
    assert secret not in str(error.value)
    assert "untrusted source" not in str(error.value)
