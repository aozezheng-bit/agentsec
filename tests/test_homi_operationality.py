"""Tests for the report-only Homi Operationality sidecar."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.frameworks import (
    HomiOperationality,
    build_homi_operationality_report,
    encode_homi_operationality_json,
)
from agentsec.frameworks.homi_pilot import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotReport,
    HomiPilotRequest,
)


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _report(tmp_path: Path) -> HomiPilotReport:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write(workspace / "AGENTS.md", "Read files and update memory.md.\n")
    _write(workspace / "SOUL.md", "Be helpful. This file is yours to evolve.\n")
    _write(workspace / "IDENTITY.md", "Name: Demo\n")
    _write(workspace / "USER.md", "Update this as you go. Context:\n")
    _write(workspace / "TOOLS.md", "SSH home-server\n")
    _write(
        workspace / "HEARTBEAT.md",
        "```markdown\n"
        "# Keep this file empty to skip heartbeat API calls.\n"
        "# Add tasks below when you want the agent to check something periodically.\n"
        "```\n",
    )
    return DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id="operationality-test",
            project_name="Operationality test",
            owner="security",
            target_root=workspace,
            output_root=tmp_path / "output",
        )
    )


def test_operationality_preserves_static_and_runtime_boundaries(tmp_path: Path) -> None:
    report = _report(tmp_path)
    operationality = build_homi_operationality_report(report)

    by_signal = {item.signal_id: item for item in operationality.entries}
    assert by_signal["heartbeat_schedule"].operationality is HomiOperationality.TEMPLATE
    assert by_signal["workspace_read"].operationality is HomiOperationality.ACTIVE
    assert (
        by_signal["user_profile_persistence"].operationality
        is HomiOperationality.LATENT
    )
    counts = dict(operationality.counts)
    assert counts[HomiOperationality.TEMPLATE] >= 1
    assert counts[HomiOperationality.LATENT] >= 1
    assert counts[HomiOperationality.ACTIVE] >= 1
    assert counts[HomiOperationality.RUNTIME_ATTESTED] == 0
    assert sum(counts.values()) == len(operationality.entries)
    payload = operationality.to_dict()
    assert payload["runtime_verified"] is False
    assert payload["report_only"] is True
    assert payload["ci_blocked"] is False
    assert payload["source_report_sha256"]


def test_operationality_sidecar_json_is_deterministic_and_has_independent_confidence(
    tmp_path: Path,
) -> None:
    report = _report(tmp_path)
    first = encode_homi_operationality_json(build_homi_operationality_report(report))
    second = encode_homi_operationality_json(build_homi_operationality_report(report))

    assert first == second
    payload = json.loads(first)
    assert all("confidence" in item for item in payload["entries"])
    assert all("operationality" in item for item in payload["entries"])
    assert all(item["runtime_verified"] is False for item in payload["entries"])
