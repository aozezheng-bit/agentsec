"""Structural and behavioral tests for the untrusted AgentSec fixture corpus."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import TypedDict, cast

import pytest

from agentsec.application import AssessmentRequest, CollectionAssessmentEngine
from agentsec.collectors import MarkdownAssetCollector
from agentsec.config import default_project_config
from agentsec.domain import CoverageIssueCode, FindingCategory
from agentsec.parsers import ObfuscationKind
from agentsec.reporting import SecretRedactor
from agentsec.rules import (
    BUILTIN_MARKDOWN_RULE_IDS,
    builtin_markdown_rules,
)

TESTDATA_ROOT = Path(__file__).parents[1] / "testdata"
REQUIRED_CATEGORIES = {"safe", "risky", "prompt-injection", "malformed"}
SUPPORTED_ASSET_NAMES = {"AGENTS.md", "AGENTS.override.md", "SKILL.md"}
EXPECTED_CASE_KEYS = {"case_id", "category", "purpose", "assets", "expected"}
EXPECTED_RESULT_KEYS = {"coverage", "signals", "rule_ids"}
CATEGORY_MINIMUMS = {
    "safe": 8,
    "risky": 15,
    "prompt-injection": 5,
    "malformed": 5,
}
CASE_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
URL_HOST_PATTERN = re.compile(r"https?://([^/\s`]+)", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")
OBFUSCATION_SIGNALS = {item.value for item in ObfuscationKind}
ALLOWED_SIGNALS = (
    {item.value for item in FindingCategory}
    | {item.value for item in CoverageIssueCode}
    | OBFUSCATION_SIGNALS
    | {"empty_content", "unclosed_code_fence"}
)
RULE_CATEGORY_BY_ID = {
    rule.metadata.rule_id: rule.metadata.category.value
    for rule in builtin_markdown_rules()
}


class ExpectedCase(TypedDict):
    """Expected behavior recorded by a fixture manifest."""

    coverage: str
    signals: list[str]
    rule_ids: list[str]


class CaseManifest(TypedDict):
    """Minimal typed representation of `case.json`."""

    case_id: str
    category: str
    purpose: str
    assets: list[str]
    expected: ExpectedCase


def case_manifests() -> list[tuple[Path, CaseManifest]]:
    """Load fixture manifests without importing or executing fixture content."""

    loaded: list[tuple[Path, CaseManifest]] = []
    for path in sorted(TESTDATA_ROOT.glob("*/*/case.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        loaded.append((path, cast(CaseManifest, payload)))
    return loaded


def test_required_fixture_categories_and_target_distribution_exist() -> None:
    """The P1-28 corpus contains 30-50 balanced reusable test cases."""

    categories = {path.name for path in TESTDATA_ROOT.iterdir() if path.is_dir()}
    manifests = case_manifests()
    counts = Counter(manifest["category"] for _, manifest in manifests)

    assert categories >= REQUIRED_CATEGORIES
    assert 30 <= len(manifests) <= 50
    assert all(
        counts[category] >= minimum for category, minimum in CATEGORY_MINIMUMS.items()
    )


def test_case_manifests_are_strict_unique_and_complete() -> None:
    """Every case has stable identity, declared assets and expected behavior."""

    manifests = case_manifests()
    case_ids = [manifest["case_id"] for _, manifest in manifests]

    assert len(case_ids) == len(set(case_ids))

    for manifest_path, manifest in manifests:
        category = manifest_path.parents[1].name
        case_directory = manifest_path.parent
        expected_case_id = f"{category}-{case_directory.name}"
        expected = manifest["expected"]

        assert set(manifest) == EXPECTED_CASE_KEYS
        assert set(expected) == EXPECTED_RESULT_KEYS
        assert manifest["case_id"] == expected_case_id
        assert CASE_ID_PATTERN.fullmatch(manifest["case_id"])
        assert manifest["category"] == category
        assert manifest["purpose"].strip()
        assert manifest["assets"]
        assert manifest["assets"] == sorted(set(manifest["assets"]))
        assert expected["coverage"] in {"complete", "incomplete"}
        assert len(expected["signals"]) == len(set(expected["signals"]))
        assert set(expected["signals"]) <= ALLOWED_SIGNALS
        assert expected["rule_ids"] == sorted(set(expected["rule_ids"]))
        assert set(expected["rule_ids"]) <= set(BUILTIN_MARKDOWN_RULE_IDS)

        if category == "safe":
            assert expected == {
                "coverage": "complete",
                "signals": [],
                "rule_ids": [],
            }
        elif category in {"risky", "prompt-injection"}:
            assert expected["coverage"] == "complete"
            assert expected["rule_ids"]
        else:
            assert category == "malformed"
            assert expected["signals"]
            if expected["coverage"] == "incomplete":
                assert expected["rule_ids"] == []

        for asset in manifest["assets"]:
            path = PurePosixPath(asset)
            assert not path.is_absolute()
            assert ".." not in path.parts
            assert path.name in SUPPORTED_ASSET_NAMES
            assert (case_directory / path).is_file()


def test_rule_expectations_cover_every_builtin_id_and_category() -> None:
    """The corpus contains an isolated positive Case for all 15 production Rules."""

    manifests = [
        manifest
        for _, manifest in case_manifests()
        if manifest["category"] in {"risky", "prompt-injection"}
    ]
    observed_ids = {
        rule_id
        for manifest in manifests
        for rule_id in manifest["expected"]["rule_ids"]
    }
    isolated_ids = {
        manifest["expected"]["rule_ids"][0]
        for manifest in manifests
        if len(manifest["expected"]["rule_ids"]) == 1
    }

    assert observed_ids == set(BUILTIN_MARKDOWN_RULE_IDS)
    assert isolated_ids == set(BUILTIN_MARKDOWN_RULE_IDS)

    for manifest in manifests:
        signals = set(manifest["expected"]["signals"])
        for rule_id in manifest["expected"]["rule_ids"]:
            if rule_id == "MD-OBFUSC-001":
                assert signals & OBFUSCATION_SIGNALS
            else:
                assert RULE_CATEGORY_BY_ID[rule_id] in signals


def test_manifest_coverage_matches_the_real_collection_and_parser_pipeline() -> None:
    """Every Case's declared coverage is replayable without executing its content."""

    engine = CollectionAssessmentEngine(MarkdownAssetCollector())
    config = default_project_config()

    for manifest_path, manifest in case_manifests():
        assessment = engine.assess(
            AssessmentRequest(
                project_root=manifest_path.parent,
                config=config,
                config_path=None,
            )
        )
        expected_complete = manifest["expected"]["coverage"] == "complete"

        assert assessment.coverage.complete is expected_complete, manifest_path
        assert assessment.coverage.discovered_assets == len(manifest["assets"])
        if expected_complete:
            assert (
                sorted(asset.path for asset in assessment.assets) == manifest["assets"]
            )
            assert assessment.coverage.skipped_assets == 0
        else:
            assert assessment.coverage.skipped_assets > 0
            assert assessment.coverage.issues


def test_fixture_tree_contains_no_symlinks_or_executable_files() -> None:
    """Untrusted fixtures remain inert data with no traversal or executable payload."""

    symlinks = [path for path in TESTDATA_ROOT.rglob("*") if path.is_symlink()]
    unexpected_files = [
        path
        for path in TESTDATA_ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() not in {".md", ".json"}
    ]

    assert symlinks == []
    assert unexpected_files == []


def test_invalid_utf8_fixtures_are_intentionally_not_decodable() -> None:
    """Both malformed encoding cases are bytes-only input, not executable data."""

    paths = (
        TESTDATA_ROOT / "malformed" / "invalid-utf8" / "AGENTS.md",
        TESTDATA_ROOT / "malformed" / "invalid-utf8-truncated" / "AGENTS.md",
    )

    for path in paths:
        with pytest.raises(UnicodeDecodeError):
            path.read_text(encoding="utf-8")


def test_fixture_assets_contain_no_secret_values_or_non_example_hosts() -> None:
    """The corpus uses synthetic text and reserved example domains only."""

    redactor = SecretRedactor()
    invalid_utf8_cases = {"invalid-utf8", "invalid-utf8-truncated"}

    for manifest_path, manifest in case_manifests():
        for relative_path in manifest["assets"]:
            path = manifest_path.parent / relative_path
            if path.parent.name in invalid_utf8_cases:
                continue
            text = path.read_text(encoding="utf-8")

            assert redactor.redact(text) == text, path
            assert EMAIL_PATTERN.search(text) is None, path
            for host in URL_HOST_PATTERN.findall(text):
                assert host.lower().endswith(".invalid"), path
