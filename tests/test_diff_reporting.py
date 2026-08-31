"""Tests for Diff redaction, escaping, and deterministic text/JSON rendering."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from agentsec.application import (
    BaselineCreationRequest,
    CollectionBaselineCreator,
    CollectionProjectDiffEngine,
    ProjectDiffRequest,
)
from agentsec.baselines import GitProvenance, encode_baseline_json
from agentsec.collectors import MarkdownAssetCollector
from agentsec.config import default_project_config
from agentsec.domain import CoverageIssue, CoverageIssueCode, ScanCoverage
from agentsec.reporting import (
    DiffErrorView,
    DiffJsonRenderer,
    DiffTextRenderer,
    SecretRedactor,
    escape_untrusted_text,
    sanitize_untrusted_text,
)


class NoGitProvenanceProvider:
    """Keep rendering tests independent from host repository state."""

    def inspect(
        self,
        project_root: Path,
        *,
        excluded_paths: tuple[Path, ...] = (),
    ) -> GitProvenance:
        return GitProvenance(commit=None, dirty=None)


def make_result(tmp_path: Path, before: str, after: str):  # type: ignore[no-untyped-def]
    """Create one complete project Diff result for renderer tests."""

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text(before, encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    config = default_project_config()
    baseline = CollectionBaselineCreator(
        MarkdownAssetCollector(),
        provenance_provider=NoGitProvenanceProvider(),
        clock=lambda: datetime(2026, 8, 18, 17, 0, tzinfo=UTC),
    ).create(
        BaselineCreationRequest(
            project_root=project,
            config=config,
            config_path=None,
            output_path=baseline_path,
        )
    )
    baseline_path.write_text(encode_baseline_json(baseline), encoding="utf-8")
    (project / "AGENTS.md").write_text(after, encoding="utf-8")
    return CollectionProjectDiffEngine(MarkdownAssetCollector()).compare(
        ProjectDiffRequest(
            project_root=project,
            config=config,
            config_path=None,
            baseline_path=baseline_path,
        )
    )


def test_secret_redactor_covers_assignments_authorization_urls_and_keys() -> None:
    """Common credential shapes are replaced without retaining their values."""

    redactor = SecretRedactor()
    cases = {
        "token: agentsec-test-token-value\n": "token: <redacted>\n",
        '"api_key" = "agentsec-test-api-value"\n': '"api_key" = <redacted>\n',
        "Authorization: Bearer agentsec-test-bearer-value\n": (
            "Authorization: Bearer <redacted>\n"
        ),
        "https://user:agentsec-test-password@example.invalid/path\n": (
            "https://user:<redacted>@example.invalid/path\n"
        ),
        "-----BEGIN TEST PRIVATE KEY-----\n": "<redacted>\n",
    }

    for source, expected in cases.items():
        assert redactor.redact(source) == expected
        assert "agentsec-test" not in redactor.redact(source)


def test_escape_untrusted_text_handles_terminal_and_unicode_controls() -> None:
    """ANSI, newlines, zero-width, bidi controls, tabs, and slashes become literals."""

    source = "a\\b\n\t\x1b\u200b\u202e"

    escaped = escape_untrusted_text(source)

    assert escaped == "a\\\\b\\n\\t\\u001b\\u200b\\u202e"
    assert "\x1b" not in escaped
    assert "\u200b" not in escaped


def test_sanitize_redacts_before_escaping() -> None:
    """A secret containing control characters cannot evade the assignment rule."""

    source = "token=agentsec-test-secret\x1b[31m\n"

    sanitized = sanitize_untrusted_text(source)

    assert sanitized == "token=<redacted>\\n"
    assert "agentsec-test-secret" not in sanitized
    assert "\x1b" not in sanitized


def test_text_renderer_never_emits_raw_secret_or_control_characters(
    tmp_path: Path,
) -> None:
    """Terminal output contains escaped redacted line evidence only."""

    secret_before = "agentsec-test-before-secret"
    secret_after = "agentsec-test-after-secret"
    result = make_result(
        tmp_path,
        f"token: {secret_before}\n",
        f"token: {secret_after}\x1b[31m\u200b\u202e\n",
    )

    rendered = DiffTextRenderer().render(result)

    assert secret_before not in rendered
    assert secret_after not in rendered
    assert "\x1b" not in rendered
    assert "\u200b" not in rendered
    assert "\u202e" not in rendered
    assert "token: <redacted>\\n" in rendered


def test_json_renderer_is_deterministic_valid_and_sanitized(tmp_path: Path) -> None:
    """Machine output parses consistently and contains no raw control or secret text."""

    result = make_result(
        tmp_path,
        "password=agentsec-test-before\n",
        "password=agentsec-test-after\x1b[2J\n",
    )
    renderer = DiffJsonRenderer()

    first = renderer.render(result)
    second = renderer.render(result)
    payload = json.loads(first)

    assert first == second
    assert payload["format"] == "agentsec-diff"
    assert payload["format_version"] == "0.1.0"
    assert payload["status"] == "complete"
    texts = [
        line["text"]
        for change in payload["changes"]
        for hunk in change["text_diff"]["hunks"]
        for line in hunk["lines"]
    ]
    assert texts == ["password=<redacted>\\n", "password=<redacted>\\n"]
    assert "agentsec-test" not in first
    assert "\x1b" not in first


def test_error_renderers_escape_coverage_paths() -> None:
    """Coverage error paths cannot inject terminal controls or invalid JSON."""

    coverage = ScanCoverage(
        discovered_assets=1,
        scanned_assets=0,
        skipped_assets=1,
        complete=False,
        issues=(
            CoverageIssue(
                code=CoverageIssueCode.UNREADABLE,
                message="Safe message.",
                asset_path="bad\x1b[31m/AGENTS.md",
            ),
        ),
    )
    view = DiffErrorView(
        code="incomplete_current_coverage",
        message="Current collection incomplete.",
        exit_code=2,
        coverage=coverage,
    )

    text = DiffTextRenderer().render_error(view)
    json_text = DiffJsonRenderer().render_error(view)
    payload = json.loads(json_text)

    assert "\x1b" not in text
    assert "\\u001b" in text
    assert payload["coverage"]["issues"][0]["path"] == "bad\\u001b[31m/AGENTS.md"


def test_diff_text_and_json_share_hardened_redaction(tmp_path: Path) -> None:
    """Provider headers and URL query credentials are safe in both Diff formats."""

    before_secret = "before-header-value"
    after_secret = "after-query-value"
    result = make_result(
        tmp_path,
        f"X-API-Key: {before_secret}\n",
        (f"https://example.invalid/hook?access_token={after_secret}&mode=test\n"),
    )

    text = DiffTextRenderer().render(result)
    json_text = DiffJsonRenderer().render(result)

    for secret in (before_secret, after_secret):
        assert secret not in text
        assert secret not in json_text
    assert "X-API-Key: <redacted>\\n" in text
    assert "access_token=<redacted>&mode=test\\n" in text
    assert "<redacted>" in json_text
