"""Tests for calibrated Homi combination Finding decisions."""

from __future__ import annotations

from pathlib import Path

from agentsec.frameworks import (
    HomiCalibrationDisposition,
    build_homi_calibration_report,
)
from agentsec.frameworks.homi_pilot import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotReport,
    HomiPilotRequest,
)


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _report(tmp_path: Path, *, explicit_control: bool) -> HomiPilotReport:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    control = (
        "Update AGENTS.md, TOOLS.md, and HEARTBEAT.md when lessons matter.\n"
        if explicit_control
        else "Read these instructions carefully.\n"
    )
    _write(
        workspace / "AGENTS.md",
        control
        + "Long-term memory uses daily notes and continuity.\n"
        + "Update memory when something matters.\n",
    )
    _write(workspace / "SOUL.md", "This file is yours to evolve.\n")
    _write(
        workspace / "IDENTITY.md",
        "Fill this in during your first conversation. Make it yours.\n",
    )
    _write(
        workspace / "USER.md",
        "# About Your Human\nUpdate this as you go. Build this over time.\n"
        "Timezone:\nContext:\n",
    )
    _write(workspace / "TOOLS.md", "Local notes only.\n")
    _write(workspace / "HEARTBEAT.md", "# Keep this file empty\n")
    return DeterministicHomiReportOnlyPilot().run(
        HomiPilotRequest(
            pilot_id="calibration-test",
            project_name="Calibration test",
            owner="security",
            target_root=workspace,
            output_root=tmp_path / "output",
        )
    )


def test_template_user_profile_is_suppressed_but_other_findings_are_preserved(
    tmp_path: Path,
) -> None:
    report = _report(tmp_path, explicit_control=True)
    calibrated = build_homi_calibration_report(report)

    decisions = {item.rule_id: item for item in calibrated.decisions}
    assert (
        decisions["HOMI-COMB-003"].disposition is HomiCalibrationDisposition.SUPPRESSED
    )
    assert decisions["HOMI-COMB-003"].rationale_code == "user-profile-template-only"
    assert decisions["HOMI-COMB-004"].disposition is HomiCalibrationDisposition.RETAINED
    assert calibrated.original_finding_count == 2
    assert calibrated.suppressed_finding_count == 1
    assert len(calibrated.retained_findings) == 1
    assert calibrated.report_only is True
    assert calibrated.runtime_verified is False
    assert calibrated.ci_blocked is False


def test_placeholder_self_modification_is_suppressed_without_control_signal(
    tmp_path: Path,
) -> None:
    report = _report(tmp_path, explicit_control=False)
    calibrated = build_homi_calibration_report(report)

    decisions = {item.rule_id: item for item in calibrated.decisions}
    assert (
        decisions["HOMI-COMB-004"].disposition is HomiCalibrationDisposition.SUPPRESSED
    )
    assert decisions["HOMI-COMB-004"].rationale_code == "persona-identity-template-only"
