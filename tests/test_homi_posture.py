"""Tests for potential-impact/current-posture separation."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.frameworks import (
    HOMI_POSTURE_FORMAT,
    HomiCurrentPosture,
    build_homi_posture_report,
    encode_homi_posture_json,
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
    _write(
        workspace / "AGENTS.md",
        """# Workspace
Read files and update memory.md.
Search the web and check calendars.
Long-term memory uses daily notes and continuity.
Update memory when something matters.
Skills provide your tools.
When in doubt, ask before external actions.
""",
    )
    _write(
        workspace / "SOUL.md",
        """# Soul
Be resourceful before asking and come back with answers.
This file is yours to evolve.
""",
    )
    _write(
        workspace / "IDENTITY.md",
        """Name: HomiClaw
Creature: AI assistant
Fill this in during your first conversation. Make it yours.
""",
    )
    _write(
        workspace / "USER.md",
        """# About Your Human
Update this as you go. Build this over time.
Timezone:
Context:
""",
    )
    _write(workspace / "TOOLS.md", "SSH home-server\nPreferred voice: Nova\n")
    _write(
        workspace / "HEARTBEAT.md",
        "- Search the web for urgent notifications.\n",
    )
    return DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id="posture-test",
            project_name="Posture test",
            owner="security",
            target_root=workspace,
            output_root=tmp_path / "output",
        )
    )


def _template_only_risk_report(tmp_path: Path) -> HomiPilotReport:
    workspace = tmp_path / "template-workspace"
    workspace.mkdir()
    _write(
        workspace / "AGENTS.md",
        "Long-term memory uses daily notes and continuity.\n"
        "Update memory when something matters.\n",
    )
    _write(workspace / "SOUL.md", "Be helpful.\n")
    _write(workspace / "IDENTITY.md", "Name: Demo\n")
    _write(
        workspace / "USER.md",
        "# About Your Human\nUpdate this as you go. Build this over time.\n"
        "Timezone:\nContext:\n",
    )
    _write(workspace / "TOOLS.md", "Local notes only.\n")
    _write(workspace / "HEARTBEAT.md", "# Keep this file empty\n")
    return DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id="template-posture-test",
            project_name="Template posture test",
            owner="security",
            target_root=workspace,
            output_root=tmp_path / "template-output",
        )
    )


def test_posture_separates_potential_impact_from_unverified_current_state(
    tmp_path: Path,
) -> None:
    report = _report(tmp_path)
    posture = build_homi_posture_report(report)

    assert posture.format == HOMI_POSTURE_FORMAT
    assert posture.potential_impact_score == 8.0
    assert posture.current_posture_score is None
    assert posture.current_posture is HomiCurrentPosture.ACTIVE_UNVERIFIED
    assert posture.runtime_verified is False
    assert posture.report_only is True
    assert posture.ci_blocked is False
    assert posture.findings
    assert all(item.current_posture_score is None for item in posture.findings)
    assert all(item.runtime_verified is False for item in posture.findings)


def test_posture_json_is_bound_to_the_exact_pilot_report(tmp_path: Path) -> None:
    report = _report(tmp_path)
    posture = build_homi_posture_report(report)
    payload = json.loads(encode_homi_posture_json(posture))

    assert payload["source_report_sha256"]
    assert payload["source_report_format"] == report.format
    assert payload["potential_impact_score"] == 8.0
    assert payload["current_posture_score"] is None
    assert payload["scoring_basis"]["current_posture"]
    assert payload["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
    }


def test_template_only_finding_does_not_raise_calibrated_current_score(
    tmp_path: Path,
) -> None:
    posture = build_homi_posture_report(_template_only_risk_report(tmp_path))

    assert posture.raw_potential_impact_score == 8.0
    assert posture.potential_impact_score == 0.0
    assert posture.raw_finding_count == 1
    assert posture.suppressed_finding_count == 1
    assert posture.findings == ()
    assert posture.current_posture is HomiCurrentPosture.NOT_ESTABLISHED
    assert posture.current_posture_score is None
