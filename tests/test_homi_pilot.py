"""P2-HOMI-06 real-project report-only Pilot tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiPilotError,
    HomiPilotLanguage,
    HomiPilotRequest,
    HomiPilotStatus,
    encode_homi_pilot_json,
    render_homi_pilot_text,
)

_SECRET_MARKER = "homi-pilot-secret-marker"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _complete_workspace(project: Path) -> None:
    _write(
        project / "AGENTS.md",
        """# Workspace
Read files and update memory.md.
Search the web and check calendars.
Long-term memory uses daily notes and continuity.
Update memory when something matters.
Skills provide your tools.
""",
    )
    _write(
        project / "SOUL.md",
        """# Soul
Be resourceful before asking and come back with answers.
This file is yours to evolve.
""",
    )
    _write(
        project / "IDENTITY.md",
        """Name: HomiClaw
Creature: AI assistant
Fill this in during your first conversation. Make it yours.
""",
    )
    _write(
        project / "USER.md",
        """# About Your Human
Update this as you go. Build this over time.
Timezone:
Context:
""",
    )
    _write(
        project / "TOOLS.md",
        f"""# Local Notes
SSH
home-server → 192.0.2.10, user: example
Preferred voice: Nova
password: {_SECRET_MARKER}
""",
    )
    _write(project / "HEARTBEAT.md", "- Search the web for urgent notifications.\n")


def _request(target: Path, output: Path) -> HomiPilotRequest:
    return HomiPilotRequest(
        pilot_id="homi-real-project-pilot",
        project_name="External Homi Example",
        owner="security-team",
        target_root=target,
        output_root=output,
        reviewer_ids=("reviewer-a",),
    )


def test_real_project_pilot_is_complete_but_never_acceptance_ready(
    tmp_path: Path,
) -> None:
    target = tmp_path / "external-homi"
    target.mkdir()
    _complete_workspace(target)

    report = DeterministicHomiReportOnlyPilot().run(_request(target, tmp_path / "out"))

    assert report.status is HomiPilotStatus.COMPLETE
    assert report.profile_complete is True
    assert report.inspection_complete is True
    assert report.acceptance_ready is False
    assert report.report_only is True
    assert report.runtime_verified is False
    assert report.ci_blocked is False
    assert report.adapter_version == "0.2.0"
    assert report.profile_model_version == "0.2.0"
    assert report.format_version == "0.2.0"
    assert len(report.combination_result.findings) == 5
    assert len(report.simulation_result.steps) == 5
    assert _SECRET_MARKER not in encode_homi_pilot_json(report)
    assert str(target) not in encode_homi_pilot_json(report)
    assert _SECRET_MARKER not in render_homi_pilot_text(report)
    assert "acceptance_ready=false" in render_homi_pilot_text(report)
    assert "不可用于验收" in render_homi_pilot_text(
        report, language=HomiPilotLanguage.ZH
    )


def test_run_and_write_creates_controlled_non_clobbering_artifacts(
    tmp_path: Path,
) -> None:
    target = tmp_path / "external-homi"
    target.mkdir()
    _complete_workspace(target)
    output = tmp_path / "pilot-output"
    request = _request(target, output)

    report = DeterministicHomiReportOnlyPilot().run_and_write(request)

    assert report.status is HomiPilotStatus.COMPLETE
    json_path = output / "homi-pilot-report.json"
    text_path = output / "homi-pilot-report.md"
    assert json_path.is_file()
    assert text_path.is_file()
    before = json_path.read_text(encoding="utf-8")
    with pytest.raises(HomiPilotError, match="already exist"):
        DeterministicHomiReportOnlyPilot().run_and_write(request)
    assert json_path.read_text(encoding="utf-8") == before


def test_partial_external_workspace_remains_honest(tmp_path: Path) -> None:
    target = tmp_path / "external-homi"
    target.mkdir()
    _write(target / "AGENTS.md", "Search the web.\n")

    report = DeterministicHomiReportOnlyPilot().run(_request(target, tmp_path / "out"))

    assert report.status is HomiPilotStatus.PARTIAL
    assert report.profile_complete is False
    assert report.acceptance_ready is False
    assert report.simulation_result.complete is False
    assert report.combination_result.findings == ()
    assert any(item.state.value == "missing" for item in report.files)


def test_pilot_rejects_symlink_or_overlapping_output_roots(tmp_path: Path) -> None:
    target = tmp_path / "external-homi"
    target.mkdir()
    _complete_workspace(target)
    link = tmp_path / "target-link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(HomiPilotError, match="symbolic link"):
        DeterministicHomiReportOnlyPilot().run(_request(link, tmp_path / "out"))

    with pytest.raises(HomiPilotError, match="outside"):
        DeterministicHomiReportOnlyPilot().run(
            _request(target, target / "pilot-output")
        )


def test_pilot_request_reviewer_ids_are_deterministic() -> None:
    with pytest.raises(ValueError, match="sorted and unique"):
        HomiPilotRequest(
            pilot_id="homi-pilot",
            project_name="Project",
            owner="Owner",
            target_root=Path("/tmp/target"),
            output_root=Path("/tmp/output"),
            reviewer_ids=("reviewer-b", "reviewer-a"),
        )
