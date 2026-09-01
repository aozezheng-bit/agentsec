"""Tests for safe YAML frontmatter and non-dereferencing references."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.parsers import (
    FrontmatterField,
    FrontmatterIssueCode,
    FrontmatterStatus,
    MarkdownBlockKind,
    MarkdownFrontmatter,
    MarkdownItParser,
    ReferenceKind,
    ReferenceTargetKind,
)


def test_valid_frontmatter_is_removed_from_commonmark_blocks() -> None:
    """Frontmatter fields retain evidence without becoming false headings."""

    path = (
        Path(__file__).parents[1]
        / "testdata"
        / "safe"
        / "nested-skill"
        / "skills"
        / "review"
        / "SKILL.md"
    )

    document = MarkdownItParser().parse(path.read_text(encoding="utf-8"))

    frontmatter = document.frontmatter
    assert frontmatter is not None
    assert frontmatter.status is FrontmatterStatus.VALID
    assert (frontmatter.start_line, frontmatter.end_line) == (1, 4)
    assert frontmatter.raw_text.startswith("---\nname: safe-review\n")
    assert frontmatter.issue_code is None
    assert [(field.name, field.value) for field in frontmatter.fields] == [
        ("name", "safe-review"),
        (
            "description",
            "Review supplied text and report evidence-backed observations.",
        ),
    ]
    assert [(field.start_line, field.end_line) for field in frontmatter.fields] == [
        (2, 2),
        (3, 3),
    ]
    assert [block.kind for block in document.blocks] == [
        MarkdownBlockKind.HEADING,
        MarkdownBlockKind.LIST_ITEM,
        MarkdownBlockKind.LIST_ITEM,
        MarkdownBlockKind.LIST_ITEM,
    ]
    assert document.blocks[0].start_line == 6
    assert document.blocks[0].text == "Safe Review"


def test_nested_frontmatter_values_are_frozen_with_field_ranges() -> None:
    """Safe JSON-like YAML values become deterministic immutable tuples."""

    content = (
        "---\n"
        "name: release-agent\n"
        "tools:\n"
        "  - shell\n"
        "  - network\n"
        "controls:\n"
        "  approval: true\n"
        "  retries: 2\n"
        "...\n"
        "# Release\n"
    )

    document = MarkdownItParser().parse(content)

    assert document.frontmatter is not None
    assert document.frontmatter.status is FrontmatterStatus.VALID
    fields = {field.name: field for field in document.frontmatter.fields}
    assert fields["tools"].value == ("shell", "network")
    assert (fields["tools"].start_line, fields["tools"].end_line) == (3, 5)
    assert fields["controls"].value == (("approval", True), ("retries", 2))
    assert (fields["controls"].start_line, fields["controls"].end_line) == (6, 8)
    assert document.blocks[0].start_line == 10


def test_unclosed_frontmatter_is_malformed_but_remaining_markdown_is_recovered() -> (
    None
):
    """Missing delimiters remain visible data without making coverage incomplete."""

    path = (
        Path(__file__).parents[1]
        / "testdata"
        / "malformed"
        / "unclosed-frontmatter"
        / "AGENTS.md"
    )

    document = MarkdownItParser().parse(path.read_text(encoding="utf-8"))

    assert document.frontmatter is not None
    assert document.frontmatter.status is FrontmatterStatus.MALFORMED
    assert document.frontmatter.issue_code is FrontmatterIssueCode.UNCLOSED
    assert document.frontmatter.fields == ()
    assert (document.frontmatter.start_line, document.frontmatter.end_line) == (1, 7)
    assert [
        (block.kind, block.start_line, block.end_line) for block in document.blocks
    ] == [
        (MarkdownBlockKind.PARAGRAPH, 2, 3),
        (MarkdownBlockKind.HEADING, 5, 5),
        (MarkdownBlockKind.PARAGRAPH, 7, 7),
    ]


@pytest.mark.parametrize(
    ("body", "expected_issue"),
    [
        ("name: [\n", FrontmatterIssueCode.INVALID_YAML),
        ("- one\n- two\n", FrontmatterIssueCode.NON_MAPPING),
        ("name: a\nname: b\n", FrontmatterIssueCode.DUPLICATE_KEY),
        ("created: 2026-08-18\n", FrontmatterIssueCode.UNSUPPORTED_VALUE),
        ("1: value\n", FrontmatterIssueCode.UNSUPPORTED_VALUE),
        ("items: &items [one]\ncopy: *items\n", FrontmatterIssueCode.UNSAFE_YAML),
        ("value: !!str tagged\n", FrontmatterIssueCode.UNSAFE_YAML),
    ],
)
def test_invalid_or_unsafe_frontmatter_is_preserved_without_partial_fields(
    body: str,
    expected_issue: FrontmatterIssueCode,
) -> None:
    """Unsupported YAML features are classified and never partially trusted."""

    content = f"---\n{body}---\n# After\n"

    document = MarkdownItParser().parse(content)

    assert document.frontmatter is not None
    assert document.frontmatter.status is FrontmatterStatus.MALFORMED
    assert document.frontmatter.issue_code is expected_issue
    assert document.frontmatter.fields == ()
    assert document.blocks[0].kind is MarkdownBlockKind.HEADING
    assert document.blocks[0].text == "After"


def test_python_yaml_tag_is_not_executed(tmp_path: Path) -> None:
    """Explicit object tags are rejected before SafeLoader construction."""

    marker = tmp_path / "must-not-exist"
    content = (
        "---\n"
        f"payload: !!python/object/apply:os.system ['touch {marker}']\n"
        "---\n"
        "# Safe remainder\n"
    )

    document = MarkdownItParser().parse(content)

    assert not marker.exists()
    assert document.frontmatter is not None
    assert document.frontmatter.issue_code is FrontmatterIssueCode.UNSAFE_YAML
    assert document.blocks[0].text == "Safe remainder"


def test_links_images_autolinks_and_definitions_are_source_backed() -> None:
    """All supported reference constructs retain target, label, type and lines."""

    content = (
        "# References\n"
        "\n"
        'See [policy](docs/policy.md "Policy") and\n'
        "![diagram](images/flow.png).\n"
        "\n"
        "Visit <https://example.invalid/security>.\n"
        "\n"
        '[unused]: ../shared/approval.md "Approval"\n'
    )

    document = MarkdownItParser().parse(content)

    assert [reference.kind for reference in document.references] == [
        ReferenceKind.LINK,
        ReferenceKind.IMAGE,
        ReferenceKind.LINK,
        ReferenceKind.DEFINITION,
    ]
    policy, image, web, definition = document.references
    assert (policy.target, policy.target_kind, policy.label, policy.title) == (
        "docs/policy.md",
        ReferenceTargetKind.RELATIVE_PATH,
        "policy",
        "Policy",
    )
    assert (policy.start_line, policy.end_line) == (3, 4)
    assert policy.heading_path == ("References",)
    assert image.target == "images/flow.png"
    assert image.kind is ReferenceKind.IMAGE
    assert image.label == "diagram"
    assert (image.start_line, image.end_line) == (3, 4)
    assert web.target_kind is ReferenceTargetKind.EXTERNAL_URL
    assert (web.start_line, web.end_line) == (6, 6)
    assert definition.target == "../shared/approval.md"
    assert definition.target_kind is ReferenceTargetKind.RELATIVE_PATH
    assert definition.label == "UNUSED"
    assert definition.title == "Approval"
    assert (definition.start_line, definition.end_line) == (8, 8)
    assert definition.raw_text == '[unused]: ../shared/approval.md "Approval"\n'


def test_reference_targets_are_classified_without_dereferencing() -> None:
    """Static URI/path categories support later rules without filesystem access."""

    content = (
        "[web](https://example.invalid) "
        "[protocol](//example.invalid/path) "
        "[mail](mailto:security@example.invalid) "
        "[anchor](#approval) "
        "[absolute](/etc/passwd) "
        "[relative](../policy.md) "
        "[uri](custom:capability) "
        "[javascript](javascript:alert(1)) "
        "[empty]()\n"
    )

    document = MarkdownItParser().parse(content)

    assert [
        (reference.label, reference.target_kind) for reference in document.references
    ] == [
        ("web", ReferenceTargetKind.EXTERNAL_URL),
        ("protocol", ReferenceTargetKind.EXTERNAL_URL),
        ("mail", ReferenceTargetKind.EMAIL),
        ("anchor", ReferenceTargetKind.ANCHOR),
        ("absolute", ReferenceTargetKind.ABSOLUTE_PATH),
        ("relative", ReferenceTargetKind.RELATIVE_PATH),
        ("uri", ReferenceTargetKind.URI),
        ("javascript", ReferenceTargetKind.URI),
        ("empty", ReferenceTargetKind.EMPTY),
    ]


def test_code_block_targets_are_not_interpreted_as_references() -> None:
    """Link-looking text inside code remains code data, not an active reference."""

    content = (
        "```markdown\n"
        "[do not follow](https://example.invalid/code)\n"
        "```\n"
        "\n"
        "`[also inert](secret.md)`\n"
    )

    document = MarkdownItParser().parse(content)

    assert document.references == ()


def test_frontmatter_models_reject_incoherent_status_and_ranges() -> None:
    """Internal metadata cannot mix valid fields with malformed status."""

    field = FrontmatterField(
        name="name",
        value="agent",
        start_line=2,
        end_line=2,
        raw_text="name: agent\n",
    )

    with pytest.raises(ValueError, match="valid frontmatter cannot"):
        MarkdownFrontmatter(
            status=FrontmatterStatus.VALID,
            start_line=1,
            end_line=3,
            raw_text="---\nname: agent\n---\n",
            fields=(field,),
            issue_code=FrontmatterIssueCode.INVALID_YAML,
        )

    with pytest.raises(ValueError, match="malformed frontmatter requires"):
        MarkdownFrontmatter(
            status=FrontmatterStatus.MALFORMED,
            start_line=1,
            end_line=1,
            raw_text="---\n",
        )
