"""P2-HOMI-07 Homi CLI packaging tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentsec.cli.app import create_app

_SECRET_MARKER = "homi-cli-secret-marker"
runner = CliRunner()


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


def test_homi_scan_json_output_is_report_only(tmp_path: Path) -> None:
    workspace = tmp_path / "homi-agent"
    workspace.mkdir()
    _complete_workspace(workspace)
    output = tmp_path / "reports" / "scan.json"

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "scan",
            str(workspace),
            "--format",
            "json",
            "--output",
            str(output),
            "--project-name",
            "CLI Demo",
            "--reviewer-id",
            "reviewer-a",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["format"] == "agentsec-homi-report-only-pilot"
    assert payload["report_only"] is True
    assert payload["runtime_verified"] is False
    assert payload["ci_blocked"] is False
    assert payload["acceptance_ready"] is False
    assert payload["format_version"] == "0.2.0"
    assert payload["adapter_version"] == "0.2.0"
    assert payload["profile_model_version"] == "0.2.0"
    assert _SECRET_MARKER not in output.read_text(encoding="utf-8")


def test_homi_simulate_supports_bounded_scenario_selection_and_chinese_text(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "homi-agent"
    workspace.mkdir()
    _complete_workspace(workspace)
    output = tmp_path / "reports" / "simulation.json"

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "simulate",
            str(workspace),
            "--format",
            "json",
            "--language",
            "zh",
            "--scenario",
            "HOMI-SIM-001,HOMI-SIM-005",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["format"] == "agentsec-homi-safe-simulation"
    assert len(payload["scenarios"]) == 2
    assert payload["executed"] is False
    assert payload["side_effects"] is False
    assert payload["runtime_verified"] is False


def test_homi_report_writes_paired_artifacts_and_no_clobber(tmp_path: Path) -> None:
    workspace = tmp_path / "homi-agent"
    workspace.mkdir()
    _complete_workspace(workspace)
    output_dir = tmp_path / "reports"

    first = runner.invoke(
        create_app(),
        ["homi", "report", str(workspace), "--output-dir", str(output_dir)],
    )
    assert first.exit_code == 0, first.output
    assert (output_dir / "homi-pilot-report.json").is_file()
    assert (output_dir / "homi-pilot-report.md").is_file()
    html = output_dir / "homi-pilot-report.html"
    assert html.is_file()
    html_text = html.read_text(encoding="utf-8")
    assert "<!doctype html>" in html_text
    assert "Homi" in html_text
    assert _SECRET_MARKER not in html_text

    second = runner.invoke(
        create_app(),
        ["homi", "report", str(workspace), "--output-dir", str(output_dir)],
    )
    assert second.exit_code == 4

    forced = runner.invoke(
        create_app(),
        [
            "homi",
            "report",
            str(workspace),
            "--output-dir",
            str(output_dir),
            "--force",
        ],
    )
    assert forced.exit_code == 0, forced.output


def test_homi_partial_scan_returns_incomplete_without_risk_blocking(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "homi-agent"
    workspace.mkdir()
    _write(workspace / "AGENTS.md", "Search the web.\n")
    output = tmp_path / "reports" / "partial.json"

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "scan",
            str(workspace),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["status"] == "partial"
    assert payload["acceptance_ready"] is False


def test_homi_cli_rejects_output_inside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "homi-agent"
    workspace.mkdir()
    _complete_workspace(workspace)

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "scan",
            str(workspace),
            "--output",
            str(workspace / "report.json"),
        ],
    )

    assert result.exit_code == 3
    assert "outside" in result.output


def test_homi_cli_rejects_unknown_scenario(tmp_path: Path) -> None:
    workspace = tmp_path / "homi-agent"
    workspace.mkdir()
    _complete_workspace(workspace)

    result = runner.invoke(
        create_app(),
        ["homi", "simulate", str(workspace), "--scenario", "HOMI-SIM-999"],
    )

    assert result.exit_code == 3
    assert "HOMI-SIM-001" in result.output


def test_homi_report_can_disable_html_explicitly(tmp_path: Path) -> None:
    workspace = tmp_path / "homi-agent"
    workspace.mkdir()
    _complete_workspace(workspace)
    output_dir = tmp_path / "reports"

    result = runner.invoke(
        create_app(),
        [
            "homi",
            "report",
            str(workspace),
            "--output-dir",
            str(output_dir),
            "--no-html",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / "homi-pilot-report.json").is_file()
    assert (output_dir / "homi-pilot-report.md").is_file()
    assert not (output_dir / "homi-pilot-report.html").exists()


def test_homi_diff_reports_capability_and_finding_delta(tmp_path: Path) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    before = report_dir / "before.json"
    after = report_dir / "after.json"
    workspace_dir = tmp_path / "workspaces"
    workspace_dir.mkdir()
    workspace_before = workspace_dir / "before-workspace"
    workspace_after = workspace_dir / "after-workspace"
    workspace_before.mkdir()
    workspace_after.mkdir()
    _complete_workspace(workspace_before)
    _complete_workspace(workspace_after)
    (workspace_after / "AGENTS.md").write_text(
        (workspace_after / "AGENTS.md").read_text(encoding="utf-8")
        + "\nSending emails requires explicit approval.\n",
        encoding="utf-8",
    )

    for workspace, path in ((workspace_before, before), (workspace_after, after)):
        result = runner.invoke(
            create_app(),
            ["homi", "scan", str(workspace), "--format", "json", "--output", str(path)],
        )
        assert result.exit_code == 0, result.output

    output = report_dir / "diff.json"
    result = runner.invoke(
        create_app(),
        [
            "homi",
            "diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["format"] == "agentsec-homi-capability-diff"
    assert payload["capability_change_summary"]["added"] >= 1
    assert "external_message_send" in {
        item["signal_id"] for item in payload["capability_changes"]
    }
    assert payload["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
    }


def test_homi_diff_html_is_self_contained(tmp_path: Path) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    before = report_dir / "before.json"
    after = report_dir / "after.json"
    workspace_dir = tmp_path / "workspaces"
    workspace_dir.mkdir()
    workspace_before = workspace_dir / "before-workspace"
    workspace_after = workspace_dir / "after-workspace"
    workspace_before.mkdir()
    workspace_after.mkdir()
    _complete_workspace(workspace_before)
    _complete_workspace(workspace_after)
    for workspace, path in ((workspace_before, before), (workspace_after, after)):
        result = runner.invoke(
            create_app(),
            ["homi", "scan", str(workspace), "--format", "json", "--output", str(path)],
        )
        assert result.exit_code == 0, result.output
    output = report_dir / "diff.html"
    result = runner.invoke(
        create_app(),
        [
            "homi",
            "diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--format",
            "html",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    text = output.read_text(encoding="utf-8")
    assert "<!doctype html>" in text
    assert "runtime_verified=false" in text
