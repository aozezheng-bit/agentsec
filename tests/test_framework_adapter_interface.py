"""P2-03 Framework Adapter seam and neutral-model contract tests."""

from __future__ import annotations

import hashlib
from dataclasses import fields
from pathlib import Path

import pytest

from agentsec.frameworks import (
    FrameworkAdapter,
    FrameworkAdapterError,
    FrameworkAdapterMetadata,
    FrameworkAsset,
    FrameworkAssetFormat,
    FrameworkAssetLocator,
    FrameworkAssetRecord,
    FrameworkAssetRole,
    FrameworkAssetScope,
    FrameworkInspectionIssue,
    FrameworkInspectionIssueCode,
    FrameworkInspectionLimits,
    FrameworkInspectionRequest,
    FrameworkInspectionResult,
)
from agentsec.parsers import (
    MarkdownItParser,
    McpConfigurationParser,
    PrefixRulesParser,
    TomlStructuredParser,
)


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _markdown_record(
    path: str = "AGENTS.md",
    *,
    precedence_rank: int = 10,
) -> FrameworkAssetRecord:
    content = "# Agent\n\nReview changes locally.\n"
    document = MarkdownItParser().parse(content)
    return FrameworkAssetRecord(
        asset=FrameworkAsset(
            locator=FrameworkAssetLocator(
                scope=FrameworkAssetScope.PROJECT,
                root_id="project",
                path=path,
            ),
            format=FrameworkAssetFormat.MARKDOWN,
            roles=frozenset({FrameworkAssetRole.AGENT_INSTRUCTIONS}),
            content_sha256=_sha256(content),
            size_bytes=len(content.encode("utf-8")),
            line_count=len(content.splitlines()),
            precedence_rank=precedence_rank,
        ),
        document=document,
    )


def _rules_record() -> FrameworkAssetRecord:
    content = 'prefix_rule(pattern=["git", "status"], decision="allow")\n'
    document = PrefixRulesParser().parse(content)
    return FrameworkAssetRecord(
        asset=FrameworkAsset(
            locator=FrameworkAssetLocator(
                scope=FrameworkAssetScope.PROJECT,
                root_id="project",
                path=".codex/rules/default.rules",
            ),
            format=FrameworkAssetFormat.RULES,
            roles=frozenset({FrameworkAssetRole.PREFIX_RULES}),
            content_sha256=_sha256(content),
            size_bytes=len(content.encode("utf-8")),
            line_count=len(content.splitlines()),
            precedence_rank=20,
        ),
        document=document,
    )


def _mcp_record() -> FrameworkAssetRecord:
    content = '[mcp_servers.docs]\ncommand = "example-server"\n'
    document = TomlStructuredParser().parse(content)
    mcp = McpConfigurationParser().parse(document)
    return FrameworkAssetRecord(
        asset=FrameworkAsset(
            locator=FrameworkAssetLocator(
                scope=FrameworkAssetScope.USER,
                root_id="user",
                path=".codex/config.toml",
            ),
            format=FrameworkAssetFormat.TOML,
            roles=frozenset(
                {
                    FrameworkAssetRole.FRAMEWORK_CONFIG,
                    FrameworkAssetRole.MCP_CONFIG,
                }
            ),
            content_sha256=_sha256(content),
            size_bytes=len(content.encode("utf-8")),
            line_count=len(content.splitlines()),
            precedence_rank=5,
        ),
        document=document,
        mcp_configuration=mcp,
    )


def _complete_result(
    metadata: FrameworkAdapterMetadata,
) -> FrameworkInspectionResult:
    assets = tuple(
        sorted(
            (_rules_record(), _markdown_record(), _mcp_record()),
            key=lambda record: record.asset.locator,
        )
    )
    return FrameworkInspectionResult(
        metadata=metadata,
        assets=assets,
        issues=(),
        discovered_assets=len(assets),
        skipped_assets=0,
        complete=True,
    )


class _CodexLikeAdapter:
    metadata = FrameworkAdapterMetadata(
        framework_id="codex",
        display_name="Codex",
        adapter_version="0.1.0",
    )

    def inspect(
        self,
        request: FrameworkInspectionRequest,
    ) -> FrameworkInspectionResult:
        del request
        return _complete_result(self.metadata)


class _OtherFrameworkAdapter:
    metadata = FrameworkAdapterMetadata(
        framework_id="other_agent",
        display_name="Other Agent",
        adapter_version="0.1.0",
    )

    def inspect(
        self,
        request: FrameworkInspectionRequest,
    ) -> FrameworkInspectionResult:
        del request
        return FrameworkInspectionResult(
            metadata=self.metadata,
            assets=(_markdown_record(),),
            issues=(),
            discovered_assets=1,
            skipped_assets=0,
            complete=True,
        )


def test_two_adapters_satisfy_the_same_real_protocol() -> None:
    adapters: tuple[FrameworkAdapter, ...] = (
        _CodexLikeAdapter(),
        _OtherFrameworkAdapter(),
    )
    request = FrameworkInspectionRequest(project_root=Path("/workspace/project"))

    assert all(isinstance(adapter, FrameworkAdapter) for adapter in adapters)
    results = tuple(adapter.inspect(request) for adapter in adapters)
    assert tuple(result.metadata.framework_id for result in results) == (
        "codex",
        "other_agent",
    )
    assert all(result.complete for result in results)


def test_framework_adapter_interface_has_one_deep_inspection_method() -> None:
    public_methods = {
        name
        for name, value in FrameworkAdapter.__dict__.items()
        if callable(value) and not name.startswith("_")
    }

    assert public_methods == {"inspect"}
    assert tuple(field.name for field in fields(FrameworkInspectionRequest)) == (
        "project_root",
        "user_home",
        "working_directory",
        "limits",
    )


def test_framework_metadata_and_limits_are_strict() -> None:
    metadata = FrameworkAdapterMetadata(
        framework_id="codex",
        display_name="Codex",
        adapter_version="0.1.0",
    )
    limits = FrameworkInspectionLimits(
        max_file_size_bytes=2_000,
        max_depth=10,
        max_assets=50,
    )

    assert metadata.framework_id == "codex"
    assert limits.max_assets == 50

    with pytest.raises(ValueError):
        FrameworkAdapterMetadata("Codex!", "Codex", "0.1.0")
    with pytest.raises(ValueError):
        FrameworkAdapterMetadata("codex", "", "0.1.0")
    with pytest.raises(ValueError):
        FrameworkAdapterMetadata("codex", "Codex", "dev")
    with pytest.raises(ValueError):
        FrameworkInspectionLimits(max_assets=0)
    with pytest.raises(TypeError):
        FrameworkInspectionRequest(
            project_root=Path("/workspace/project"),
            working_directory="subdirectory",  # type: ignore[arg-type]
        )


def test_framework_asset_locator_is_portable_and_path_safe() -> None:
    locator = FrameworkAssetLocator(
        scope=FrameworkAssetScope.PLUGIN,
        root_id="plugin:example",
        path="plugin/config.toml",
    )

    assert locator.path == "plugin/config.toml"
    with pytest.raises(ValueError):
        FrameworkAssetLocator(
            scope=FrameworkAssetScope.PROJECT,
            root_id="project",
            path="../outside.toml",
        )
    with pytest.raises(ValueError):
        FrameworkAssetLocator(
            scope=FrameworkAssetScope.PROJECT,
            root_id="",
            path="AGENTS.md",
        )


@pytest.mark.parametrize(
    ("format", "roles"),
    [
        (
            FrameworkAssetFormat.JSON,
            frozenset({FrameworkAssetRole.AGENT_INSTRUCTIONS}),
        ),
        (
            FrameworkAssetFormat.MARKDOWN,
            frozenset({FrameworkAssetRole.PREFIX_RULES}),
        ),
        (
            FrameworkAssetFormat.RULES,
            frozenset({FrameworkAssetRole.MCP_CONFIG}),
        ),
        (
            FrameworkAssetFormat.MARKDOWN,
            frozenset(
                {
                    FrameworkAssetRole.AGENT_INSTRUCTIONS,
                    FrameworkAssetRole.FRAMEWORK_CONFIG,
                }
            ),
        ),
    ],
)
def test_framework_asset_rejects_role_and_format_leakage(
    format: FrameworkAssetFormat,
    roles: frozenset[FrameworkAssetRole],
) -> None:
    with pytest.raises(ValueError):
        FrameworkAsset(
            locator=FrameworkAssetLocator(
                scope=FrameworkAssetScope.PROJECT,
                root_id="project",
                path="asset.txt",
            ),
            format=format,
            roles=roles,
            content_sha256="a" * 64,
            size_bytes=1,
            line_count=1,
            precedence_rank=0,
        )


def test_framework_asset_record_requires_matching_parser_output() -> None:
    markdown = _markdown_record()
    rules = _rules_record()

    with pytest.raises(TypeError):
        FrameworkAssetRecord(
            asset=markdown.asset,
            document=rules.document,
        )
    with pytest.raises(ValueError):
        FrameworkAssetRecord(
            asset=_mcp_record().asset,
            document=_mcp_record().document,
            mcp_configuration=None,
        )


def test_framework_record_requires_matching_line_count() -> None:
    record = _markdown_record()
    invalid_asset = FrameworkAsset(
        locator=record.asset.locator,
        format=record.asset.format,
        roles=record.asset.roles,
        content_sha256=record.asset.content_sha256,
        size_bytes=record.asset.size_bytes,
        line_count=record.asset.line_count + 1,
        precedence_rank=record.asset.precedence_rank,
    )

    with pytest.raises(ValueError):
        FrameworkAssetRecord(asset=invalid_asset, document=record.document)


def test_complete_result_is_ordered_unique_and_counted() -> None:
    metadata = _CodexLikeAdapter.metadata
    result = _complete_result(metadata)

    assert result.inspected_assets == 3
    assert result.discovered_assets == 3
    assert result.skipped_assets == 0
    assert result.complete is True
    assert [record.asset.locator for record in result.assets] == sorted(
        record.asset.locator for record in result.assets
    )


def test_incomplete_result_requires_sorted_unique_coverage_issues() -> None:
    issue = FrameworkInspectionIssue(
        code=FrameworkInspectionIssueCode.PARSE_ERROR,
        root_id="project",
        path=".codex/config.toml",
    )
    result = FrameworkInspectionResult(
        metadata=_CodexLikeAdapter.metadata,
        assets=(),
        issues=(issue,),
        discovered_assets=1,
        skipped_assets=1,
        complete=False,
    )

    assert result.complete is False
    with pytest.raises(ValueError):
        FrameworkInspectionResult(
            metadata=_CodexLikeAdapter.metadata,
            assets=(),
            issues=(),
            discovered_assets=1,
            skipped_assets=1,
            complete=True,
        )
    with pytest.raises(ValueError):
        FrameworkInspectionResult(
            metadata=_CodexLikeAdapter.metadata,
            assets=(),
            issues=(issue, issue),
            discovered_assets=2,
            skipped_assets=2,
            complete=False,
        )


def test_framework_result_rejects_unsorted_or_duplicate_assets() -> None:
    first = _markdown_record("z/AGENTS.md")
    second = _markdown_record("a/AGENTS.md")

    with pytest.raises(ValueError):
        FrameworkInspectionResult(
            metadata=_CodexLikeAdapter.metadata,
            assets=(first, second),
            issues=(),
            discovered_assets=2,
            skipped_assets=0,
            complete=True,
        )
    with pytest.raises(ValueError):
        FrameworkInspectionResult(
            metadata=_CodexLikeAdapter.metadata,
            assets=(first, first),
            issues=(),
            discovered_assets=2,
            skipped_assets=0,
            complete=True,
        )


def test_framework_adapter_error_does_not_require_scanned_content() -> None:
    error = FrameworkAdapterError("framework inspection failed safely")

    assert str(error) == "framework inspection failed safely"
