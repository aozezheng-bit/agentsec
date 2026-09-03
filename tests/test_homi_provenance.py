"""Tests for Homi package/build provenance and fingerprint output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.cli.app import create_app
from agentsec.frameworks import (
    HOMI_BUILD_COMMIT_ENVIRONMENT,
    HOMI_BUILD_COMMIT_UNAVAILABLE,
    HOMI_BUILD_PROVENANCE_VERSION,
    build_homi_build_provenance,
    encode_homi_build_provenance_json,
    render_homi_build_provenance_text,
)

runner = CliRunner()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _workspace(path: Path) -> None:
    _write(path / "AGENTS.md", "Read files safely.\n")
    _write(path / "SOUL.md", "Be helpful.\n")
    _write(path / "IDENTITY.md", "Name: Demo\n")
    _write(path / "USER.md", "Name:\n")
    _write(path / "TOOLS.md", "Local notes:\n")
    _write(path / "HEARTBEAT.md", "# Keep this file empty\n")


def test_homi_build_provenance_is_deterministic_and_value_minimized() -> None:
    first = build_homi_build_provenance(pilot_format_version="0.2.0")
    second = build_homi_build_provenance(pilot_format_version="0.2.0")

    assert first == second
    assert first.schema_version == HOMI_BUILD_PROVENANCE_VERSION
    assert first.build_commit == HOMI_BUILD_COMMIT_UNAVAILABLE
    assert first.build_commit_source == "unavailable"
    assert len(first.implementation_digest) == 64
    assert len(first.package_digest) == 64
    assert first.implementation_file_count >= 10
    assert first.package_file_count >= first.implementation_file_count
    assert encode_homi_build_provenance_json(first) == (
        encode_homi_build_provenance_json(second)
    )


def test_homi_build_provenance_accepts_only_safe_commit_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(HOMI_BUILD_COMMIT_ENVIRONMENT, "ABCDEF1234567")
    valid = build_homi_build_provenance(pilot_format_version="0.2.0")
    assert valid.build_commit == "abcdef1234567"
    assert valid.build_commit_source == "environment"

    monkeypatch.setenv(HOMI_BUILD_COMMIT_ENVIRONMENT, "not-a-commit-secret-value")
    invalid = build_homi_build_provenance(pilot_format_version="0.2.0")
    assert invalid.build_commit == HOMI_BUILD_COMMIT_UNAVAILABLE
    assert invalid.build_commit_source == "unavailable"
    assert "not-a-commit-secret-value" not in encode_homi_build_provenance_json(invalid)


def test_homi_fingerprint_cli_supports_json_and_text(tmp_path: Path) -> None:
    json_result = runner.invoke(create_app(), ["homi", "fingerprint"])
    assert json_result.exit_code == 0, json_result.output
    payload = json.loads(json_result.stdout)
    assert payload["schema_version"] == HOMI_BUILD_PROVENANCE_VERSION
    assert payload["package_version"] == "0.4.0"
    assert len(payload["package_digest"]) == 64

    text_result = runner.invoke(
        create_app(), ["homi", "fingerprint", "--format", "text"]
    )
    assert text_result.exit_code == 0, text_result.output
    assert "AgentSec Homi Build Fingerprint" in text_result.stdout
    assert payload["package_digest"] in text_result.stdout

    output = tmp_path / "fingerprint.json"
    file_result = runner.invoke(
        create_app(), ["homi", "fingerprint", "--output", str(output)]
    )
    assert file_result.exit_code == 0, file_result.output
    assert json.loads(output.read_text(encoding="utf-8")) == payload


def test_homi_report_writes_build_fingerprint_sidecar(
    tmp_path: Path,
) -> None:
    target = tmp_path / "workspace"
    target.mkdir()
    _workspace(target)
    output = tmp_path / "output"
    result = runner.invoke(
        create_app(),
        [
            "homi",
            "report",
            str(target),
            "--output-dir",
            str(output),
            "--language",
            "zh",
        ],
    )
    assert result.exit_code == 0, result.output

    pilot_payload = json.loads(
        (output / "homi-pilot-report.json").read_text(encoding="utf-8")
    )
    assert "build_provenance" not in pilot_payload
    provenance = json.loads(
        (output / "homi-build-fingerprint.json").read_text(encoding="utf-8")
    )
    assert provenance["schema_version"] == HOMI_BUILD_PROVENANCE_VERSION
    assert len(provenance["package_digest"]) == 64


def test_homi_provenance_text_is_human_readable() -> None:
    provenance = build_homi_build_provenance(pilot_format_version="0.2.0")
    text = render_homi_build_provenance_text(provenance)
    assert "Package version: 0.4.0" in text
    assert f"Implementation digest: {provenance.implementation_digest}" in text
    assert f"Package digest: {provenance.package_digest}" in text
