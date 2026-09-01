"""P2-01 deterministic JSON, YAML, and TOML parser contracts."""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

import pytest

from agentsec.parsers import (
    JsonStructuredParser,
    StructuredDataFormat,
    StructuredNodeKind,
    StructuredParseError,
    StructuredParseIssueCode,
    StructuredParseLimits,
    StructuredParser,
    TomlStructuredParser,
    YamlStructuredParser,
    format_structured_path,
)


def _parse_with_interface(
    parser: StructuredParser,
    content: str,
) -> StructuredDataFormat:
    """Exercise every adapter through the same deep-module interface."""

    return parser.parse(content).format


@pytest.mark.parametrize(
    ("parser", "content", "expected"),
    [
        (JsonStructuredParser(), '{"enabled": true}', StructuredDataFormat.JSON),
        (YamlStructuredParser(), "enabled: true\n", StructuredDataFormat.YAML),
        (TomlStructuredParser(), "enabled = true\n", StructuredDataFormat.TOML),
    ],
)
def test_structured_parsers_share_one_small_interface(
    parser: StructuredParser,
    content: str,
    expected: StructuredDataFormat,
) -> None:
    assert _parse_with_interface(parser, content) is expected


def test_format_structured_path_handles_keys_and_indexes() -> None:
    assert format_structured_path(()) == "$"
    assert format_structured_path(("tools", 0, "name")) == "$.tools[0].name"
    assert format_structured_path(("a.b", "", 2)) == '$["a.b"][""][2]'


def test_json_parser_preserves_nested_types_paths_and_lines() -> None:
    content = (
        "{\n"
        '  "agent": {\n'
        '    "name": "release",\n'
        '    "tools": ["shell", "filesystem"]\n'
        "  },\n"
        '  "approval": false,\n'
        '  "retries": 3,\n'
        '  "ratio": 0.5,\n'
        '  "optional": null\n'
        "}\n"
    )

    document = JsonStructuredParser().parse(content)

    assert document.source_line_count == 10
    assert document.node_at(()) is not None
    assert document.node_at(("agent",)) is not None
    assert document.node_at(("agent", "name")).value == "release"  # type: ignore[union-attr]
    assert document.node_at(("agent", "name")).start_line == 3  # type: ignore[union-attr]
    assert document.node_at(("agent", "tools", 1)).value == "filesystem"  # type: ignore[union-attr]
    assert document.node_at(("approval",)).kind is StructuredNodeKind.BOOLEAN  # type: ignore[union-attr]
    assert document.node_at(("retries",)).kind is StructuredNodeKind.INTEGER  # type: ignore[union-attr]
    assert document.node_at(("ratio",)).kind is StructuredNodeKind.FLOAT  # type: ignore[union-attr]
    assert document.node_at(("optional",)).kind is StructuredNodeKind.NULL  # type: ignore[union-attr]


def test_json_parser_rejects_duplicate_keys_at_the_duplicate_line() -> None:
    content = '{\n  "name": "first",\n  "name": "second"\n}\n'

    with pytest.raises(StructuredParseError) as captured:
        JsonStructuredParser().parse(content)

    assert captured.value.code is StructuredParseIssueCode.DUPLICATE_KEY
    assert captured.value.line == 3
    assert "first" not in str(captured.value)
    assert "second" not in str(captured.value)


@pytest.mark.parametrize(
    ("limits", "content", "code"),
    [
        (
            StructuredParseLimits(max_depth=1),
            '{"outer": {"inner": true}}',
            StructuredParseIssueCode.DEPTH_EXCEEDED,
        ),
        (
            StructuredParseLimits(max_nodes=2),
            '{"one": 1, "two": 2}',
            StructuredParseIssueCode.NODE_LIMIT_EXCEEDED,
        ),
        (
            StructuredParseLimits(max_scalar_characters=3),
            '{"name": "long"}',
            StructuredParseIssueCode.SCALAR_TOO_LARGE,
        ),
    ],
)
def test_json_parser_enforces_resource_limits(
    limits: StructuredParseLimits,
    content: str,
    code: StructuredParseIssueCode,
) -> None:
    with pytest.raises(StructuredParseError) as captured:
        JsonStructuredParser(limits).parse(content)

    assert captured.value.code is code


def test_json_parser_is_deterministic_and_rejects_trailing_content() -> None:
    parser = JsonStructuredParser()
    content = '{"a": [1, 2], "b": "x"}\n'

    assert parser.parse(content) == parser.parse(content)
    with pytest.raises(StructuredParseError) as captured:
        parser.parse(content + "true")
    assert captured.value.code is StructuredParseIssueCode.MALFORMED


def test_yaml_parser_preserves_nested_types_paths_and_lines() -> None:
    content = (
        "agent:\n"
        "  name: release\n"
        "  tools:\n"
        "    - shell\n"
        "    - filesystem\n"
        "approval: false\n"
        "released: 2026-08-20\n"
    )

    document = YamlStructuredParser().parse(content)

    assert document.source_line_count == 7
    assert document.node_at(("agent",)).start_line == 1  # type: ignore[union-attr]
    assert document.node_at(("agent", "name")).value == "release"  # type: ignore[union-attr]
    assert document.node_at(("agent", "tools", 0)).start_line == 4  # type: ignore[union-attr]
    assert document.node_at(("approval",)).kind is StructuredNodeKind.BOOLEAN  # type: ignore[union-attr]
    released = document.node_at(("released",))
    assert released is not None
    assert released.kind is StructuredNodeKind.DATE
    assert released.value == date(2026, 8, 20)


def test_yaml_parser_rejects_duplicate_keys_aliases_and_explicit_tags() -> None:
    parser = YamlStructuredParser()

    with pytest.raises(StructuredParseError) as duplicate:
        parser.parse("name: first\nname: second\n")
    assert duplicate.value.code is StructuredParseIssueCode.DUPLICATE_KEY
    assert duplicate.value.line == 2

    with pytest.raises(StructuredParseError) as alias:
        parser.parse("value: &shared 1\ncopy: *shared\n")
    assert alias.value.code is StructuredParseIssueCode.ALIAS_NOT_ALLOWED

    with pytest.raises(StructuredParseError) as tag:
        parser.parse("value: !!python/object/apply:os.system ['touch marker']\n")
    assert tag.value.code is StructuredParseIssueCode.UNSAFE_TAG
    assert "touch marker" not in str(tag.value)


def test_yaml_parser_does_not_execute_unsafe_python_tags(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    content = f"!!python/object/apply:pathlib.Path.touch ['{marker}']\n"

    with pytest.raises(StructuredParseError):
        YamlStructuredParser().parse(content)

    assert not marker.exists()


def test_yaml_parser_rejects_non_string_keys_and_multiple_documents() -> None:
    parser = YamlStructuredParser()

    with pytest.raises(StructuredParseError) as key_error:
        parser.parse("1: value\n")
    assert key_error.value.code is StructuredParseIssueCode.UNSUPPORTED_KEY

    with pytest.raises(StructuredParseError) as multiple:
        parser.parse("name: one\n---\nname: two\n")
    assert multiple.value.code is StructuredParseIssueCode.MALFORMED


def test_yaml_parser_enforces_depth_node_and_scalar_limits() -> None:
    with pytest.raises(StructuredParseError) as depth:
        YamlStructuredParser(StructuredParseLimits(max_depth=1)).parse(
            "outer:\n  inner:\n    value: true\n"
        )
    assert depth.value.code is StructuredParseIssueCode.DEPTH_EXCEEDED

    with pytest.raises(StructuredParseError) as nodes:
        YamlStructuredParser(StructuredParseLimits(max_nodes=2)).parse(
            "one: 1\ntwo: 2\n"
        )
    assert nodes.value.code is StructuredParseIssueCode.NODE_LIMIT_EXCEEDED

    with pytest.raises(StructuredParseError) as scalar:
        YamlStructuredParser(StructuredParseLimits(max_scalar_characters=3)).parse(
            "name: long\n"
        )
    assert scalar.value.code is StructuredParseIssueCode.SCALAR_TOO_LARGE


def test_toml_parser_preserves_tables_arrays_dates_and_lines() -> None:
    content = (
        'title = "release"\n'
        "released = 2026-08-20\n"
        "\n"
        "[agent]\n"
        'name = "release"\n'
        'tools = ["shell", "filesystem"]\n'
        "\n"
        "[[servers]]\n"
        'name = "one"\n'
        "[[servers]]\n"
        'name = "two"\n'
    )

    document = TomlStructuredParser().parse(content)

    assert document.source_line_count == 11
    assert document.node_at(("title",)).start_line == 1  # type: ignore[union-attr]
    released = document.node_at(("released",))
    assert released is not None
    assert released.kind is StructuredNodeKind.DATE
    assert released.value == date(2026, 8, 20)
    assert document.node_at(("agent",)).start_line == 4  # type: ignore[union-attr]
    assert document.node_at(("agent", "tools", 1)).value == "filesystem"  # type: ignore[union-attr]
    assert document.node_at(("servers", 0, "name")).start_line == 9  # type: ignore[union-attr]
    assert document.node_at(("servers", 1, "name")).start_line == 11  # type: ignore[union-attr]


def test_toml_parser_maps_multiline_and_quoted_dotted_keys() -> None:
    content = (
        '"agent.config".name = "release"\ndescription = """\nline one\nline two\n"""\n'
    )

    document = TomlStructuredParser().parse(content)

    assert document.node_at(("agent.config", "name")).start_line == 1  # type: ignore[union-attr]
    description = document.node_at(("description",))
    assert description is not None
    assert description.start_line == 2
    assert description.end_line == 5
    assert description.value == "line one\nline two\n"


def test_toml_parser_rejects_duplicates_nonfinite_values_and_malformed_input() -> None:
    parser = TomlStructuredParser()

    with pytest.raises(StructuredParseError) as duplicate:
        parser.parse("name = 'one'\nname = 'two'\n")
    assert duplicate.value.code is StructuredParseIssueCode.DUPLICATE_KEY
    assert duplicate.value.line == 2

    with pytest.raises(StructuredParseError) as nonfinite:
        parser.parse("ratio = inf\n")
    assert nonfinite.value.code is StructuredParseIssueCode.UNSUPPORTED_VALUE

    with pytest.raises(StructuredParseError) as malformed:
        parser.parse("name = [\n")
    assert malformed.value.code is StructuredParseIssueCode.MALFORMED


def test_toml_parser_enforces_depth_node_and_scalar_limits() -> None:
    with pytest.raises(StructuredParseError) as depth:
        TomlStructuredParser(StructuredParseLimits(max_depth=1)).parse(
            "[outer.inner]\nvalue = true\n"
        )
    assert depth.value.code is StructuredParseIssueCode.DEPTH_EXCEEDED

    with pytest.raises(StructuredParseError) as nodes:
        TomlStructuredParser(StructuredParseLimits(max_nodes=2)).parse(
            "one = 1\ntwo = 2\n"
        )
    assert nodes.value.code is StructuredParseIssueCode.NODE_LIMIT_EXCEEDED

    with pytest.raises(StructuredParseError) as scalar:
        TomlStructuredParser(StructuredParseLimits(max_scalar_characters=3)).parse(
            'name = "long"\n'
        )
    assert scalar.value.code is StructuredParseIssueCode.SCALAR_TOO_LARGE


def test_empty_yaml_and_toml_documents_are_valid_and_empty() -> None:
    assert YamlStructuredParser().parse("\n# comment\n").nodes == ()
    assert TomlStructuredParser().parse("\n# comment\n").nodes == ()


def test_toml_datetime_values_remain_typed() -> None:
    document = TomlStructuredParser().parse("when = 2026-08-20T10:30:00Z\n")
    node = document.node_at(("when",))

    assert node is not None
    assert node.kind is StructuredNodeKind.DATETIME
    assert isinstance(node.value, datetime)
