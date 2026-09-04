"""RISK-02 Homi template/latent/active/unknown state tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotReport,
    HomiPilotRequest,
    HomiRiskState,
    HomiRiskStateEntry,
    HomiRiskStateScope,
    build_homi_risk_state_report,
    encode_homi_risk_state_json,
    export_homi_risk_state_json_schema,
)
from agentsec.frameworks.homi import HomiFileState
from agentsec.frameworks.homi_profile import HomiCapabilityState


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _report(tmp_path: Path) -> HomiPilotReport:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write(
        workspace / "AGENTS.md",
        "Read files. Search the web. Long-term memory uses daily notes.\n"
        "Update memory when something matters.\n",
    )
    _write(workspace / "SOUL.md", "Be helpful. Have opinions.\n")
    _write(workspace / "IDENTITY.md", "Name: Demo\n")
    _write(workspace / "USER.md", "# About Your Human\nContext:\n")
    _write(workspace / "TOOLS.md", "## Local Notes\n## Examples\n")
    _write(
        workspace / "HEARTBEAT.md",
        "# Keep this file empty to skip heartbeat API calls.\n"
        "# Add tasks below when you want the agent to check something periodically.\n",
    )
    return DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id="risk-state-test",
            project_name="Risk state test",
            owner="security",
            target_root=workspace,
            output_root=tmp_path / "output",
        )
    )


def test_risk_state_distinguishes_files_and_signals(tmp_path: Path) -> None:
    report = _report(tmp_path)
    state_report = build_homi_risk_state_report(report)

    entries = {(item.scope, item.item_id): item for item in state_report.entries}
    assert entries[(HomiRiskStateScope.FILE, "AGENTS.md")].state is HomiRiskState.ACTIVE
    assert (
        entries[(HomiRiskStateScope.FILE, "HEARTBEAT.md")].state
        is HomiRiskState.TEMPLATE
    )
    assert (
        entries[(HomiRiskStateScope.CAPABILITY, "external_network_read")].state
        is HomiRiskState.ACTIVE
    )
    assert (
        entries[(HomiRiskStateScope.CAPABILITY, "persistent_memory")].state
        is HomiRiskState.LATENT
    )
    assert (
        entries[(HomiRiskStateScope.CAPABILITY, "oauth_access")].state
        is HomiRiskState.UNKNOWN
    )
    assert (
        entries[(HomiRiskStateScope.PERSONA, "opinionated")].state
        is HomiRiskState.LATENT
    )

    counts = dict(state_report.counts)
    assert counts[HomiRiskState.TEMPLATE] >= 1
    assert counts[HomiRiskState.LATENT] >= 1
    assert counts[HomiRiskState.ACTIVE] >= 1
    assert counts[HomiRiskState.UNKNOWN] >= 1
    assert counts[HomiRiskState.RUNTIME_ATTESTED] == 0
    assert state_report.file_count == 6
    assert state_report.signal_count == len(state_report.entries) - 6
    payload = json.loads(encode_homi_risk_state_json(state_report))
    assert payload["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
    }
    assert payload["basis"]


def test_missing_file_is_unknown_not_active_or_safe(tmp_path: Path) -> None:
    report = _report(tmp_path)
    # HomiPilotFileSummary is immutable; construct a replacement report only
    # through the public report object to keep this test value-minimized.
    from dataclasses import replace

    missing_tools = type(report.files[0])(
        name="TOOLS.md",
        state=HomiFileState.MISSING,
        content_sha256=None,
        size_bytes=None,
        line_count=None,
        issue_codes=(),
    )
    files = tuple(
        sorted(
            tuple(item for item in report.files if item.name != "TOOLS.md")
            + (missing_tools,),
            key=lambda item: item.name,
        )
    )
    replacement = replace(report, files=files)
    state_report = build_homi_risk_state_report(replacement)
    tools = next(
        item
        for item in state_report.entries
        if item.scope is HomiRiskStateScope.FILE and item.item_id == "TOOLS.md"
    )
    assert tools.state is HomiRiskState.UNKNOWN
    assert tools.rationale_code == "missing_file_coverage"


def test_state_contract_rejects_false_runtime_attestation() -> None:
    with pytest.raises(ValueError, match="runtime_attested"):
        HomiRiskStateEntry(
            scope=HomiRiskStateScope.CAPABILITY,
            item_id="example",
            declared_state=HomiCapabilityState.PRESENT.value,
            state=HomiRiskState.RUNTIME_ATTESTED,
            rationale_code="static",
            confidence="B",
            method="static_declaration",
            source_paths=("AGENTS.md",),
        )


def test_state_schema_export_is_strict_and_deterministic(tmp_path: Path) -> None:
    first = export_homi_risk_state_json_schema(tmp_path)
    first_text = first.read_text(encoding="utf-8")
    second = export_homi_risk_state_json_schema(tmp_path)
    assert first == second
    assert first_text == second.read_text(encoding="utf-8")
    payload = json.loads(first_text)
    assert payload["properties"]["format"]["const"] == "agentsec-homi-risk-state"
    assert payload["properties"]["counts"]["required"] == [
        "template",
        "latent",
        "active",
        "runtime_attested",
        "unknown",
    ]
