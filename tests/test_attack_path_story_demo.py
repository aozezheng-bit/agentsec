"""P3-AG-07 Attack Path Story Demo tests."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPOSITORY_ROOT / "scripts" / "run-attack-path-demo.sh"
PRESENTER = REPOSITORY_ROOT / "scripts" / "demo-attack-path.sh"


def _run(script: Path, output: Path) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHON"] = str(REPOSITORY_ROOT / ".venv" / "bin" / "python")
    return subprocess.run(
        [str(script), "--output-dir", str(output), "--no-pause"]
        if script == PRESENTER
        else [str(script), "--output-dir", str(output)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_story_runner_produces_a_small_three_outcome_report(tmp_path: Path) -> None:
    output = tmp_path / "story"
    result = _run(RUNNER, output)

    assert result.returncode == 0, result.stderr
    assert "Attack Path Story Demo" in result.stdout
    assert "Evidence associations: 3" in result.stdout
    assert "report-only" in result.stdout
    expected = {
        "graph.json",
        "findings.json",
        "semantic-result.json",
        "semantic-evidence.json",
        "association-report.json",
        "association-report.txt",
        "story-summary.json",
    }
    assert {item.name for item in output.iterdir()} == expected
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in output.iterdir())

    report = cast(
        dict[str, Any],
        json.loads((output / "association-report.json").read_text(encoding="utf-8")),
    )
    summary = cast(
        dict[str, Any],
        json.loads((output / "story-summary.json").read_text(encoding="utf-8")),
    )
    assert report["path_count"] == 1
    assert report["association_count"] == 3
    assert summary["relations"] == {
        "duplicates": 1,
        "partially_supports": 1,
        "unmatched": 1,
    }
    assert report["report_only"] is True
    assert report["blocks"] is False
    assert report["runtime_verified"] is False
    assert "example.invalid" not in (output / "association-report.txt").read_text(
        encoding="utf-8"
    )


def test_presenter_wrapper_is_noninteractive_with_no_pause(tmp_path: Path) -> None:
    output = tmp_path / "presenter"
    result = _run(PRESENTER, output)

    assert result.returncode == 0, result.stderr
    assert "Collect inert Homi workspace" in result.stdout
    assert "Exact, partial, and unmatched" in result.stdout
    assert "Management close" in result.stdout
    assert "Press Enter" not in result.stdout
    assert (output / "association-report.txt").is_file()


def test_story_demo_rejects_nonempty_output_directory(tmp_path: Path) -> None:
    output = tmp_path / "nonempty"
    output.mkdir()
    (output / "existing.txt").write_text("do not clobber", encoding="utf-8")
    result = _run(RUNNER, output)

    assert result.returncode == 2
    assert "empty" in result.stderr
    assert (output / "existing.txt").read_text(encoding="utf-8") == "do not clobber"
