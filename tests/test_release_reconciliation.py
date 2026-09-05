"""P3-REL-01 current source and candidate artifact reconciliation tests."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "reconcile-candidate-artifacts.py"
PRESERVED = ROOT / "dist" / "0.4.0"


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_reconciliation_builds_current_candidate_without_mutating_preserved(
    tmp_path: Path,
) -> None:
    preserved_before = {
        path.name: _sha256(path) for path in PRESERVED.iterdir() if path.is_file()
    }
    output = tmp_path / "candidate"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--output-dir", str(output)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "reconciled"
    assert report["task_id"] == "P3-REL-03"
    assert report["format_version"] == "0.2.0"
    assert report["package_version"] == "0.4.0"
    assert report["preserved_candidate_unchanged"] is True
    assert report["candidate_artifacts_differ_from_preserved"] is True
    assert report["artifact_checks"]["checks"]
    assert all(report["artifact_checks"]["checks"].values())
    expected_content_checks = {
        "wheel_content_match": True,
        "sdist_content_match": True,
        "schema_content_match": True,
        "metadata_content_match": True,
        "mismatched_wheel_files": [],
        "mismatched_sdist_files": [],
        "mismatched_sdist_schema_files": [],
        "mismatched_sdist_metadata_files": [],
    }
    assert report["content_checks"] == expected_content_checks
    assert report["artifact_checks"]["content_checks"] == expected_content_checks
    assert report["installed_cli_smoke"] == {
        "version": True,
        "root_help": True,
        "attack_graph_help": True,
        "score_help": True,
        "attack_graph_json": True,
        "score_attack_path_context": True,
        "homi_context_risk": True,
        "homi_directional_drift": True,
        "homi_html_report": True,
    }
    assert report["reproducible_build"]["byte_identical"] is True
    assert (output / "reconciliation-report.json").is_file()
    assert (output / "reconciliation-report.md").is_file()
    assert (output / "SHA256SUMS").is_file()
    assert all(
        (output / name).is_file()
        for name in (
            "agentsec-0.4.0-py3-none-any.whl",
            "agentsec-0.4.0.tar.gz",
        )
    )

    preserved_after = {
        path.name: _sha256(path) for path in PRESERVED.iterdir() if path.is_file()
    }
    assert preserved_after == preserved_before


def test_reconciliation_refuses_to_overwrite_preserved_candidate(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--output-dir", str(PRESERVED)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "must not overwrite preserved candidate" in result.stderr


def _build_candidate(output: Path) -> tuple[Path, Path]:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--output-dir", str(output)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return output / "agentsec-0.4.0-py3-none-any.whl", output / "agentsec-0.4.0.tar.gz"


def _verification_namespace() -> dict[str, Any]:
    namespace = runpy.run_path(str(SCRIPT))
    return namespace


def test_byte_level_reconciliation_rejects_tampered_wheel(tmp_path: Path) -> None:
    wheel, sdist = _build_candidate(tmp_path / "candidate")
    tampered = tmp_path / "tampered.whl"
    with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(tampered, "w") as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == "agentsec/api.py":
                content += b"# tampered\n"
            target.writestr(info, content)

    namespace = _verification_namespace()
    verify = namespace["_verify_artifacts"]
    error_type = namespace["ReconciliationError"]
    with pytest.raises(error_type, match="do not match source"):
        verify(tampered, sdist, "0.4.0")


def test_byte_level_reconciliation_rejects_tampered_schema(tmp_path: Path) -> None:
    wheel, sdist = _build_candidate(tmp_path / "candidate")
    tampered = tmp_path / "tampered.tar.gz"
    changed = False
    with (
        tarfile.open(sdist, "r:gz") as source,
        tarfile.open(tampered, "w:gz") as target,
    ):
        for member in source.getmembers():
            content = None
            if member.isfile():
                stream = source.extractfile(member)
                assert stream is not None
                with stream:
                    content = stream.read()
            if member.isfile() and member.name.endswith(".schema.json") and not changed:
                assert content is not None
                content += b"\n"
                member.size = len(content)
                changed = True
            target.addfile(member, BytesIO(content) if content is not None else None)
    assert changed

    namespace = _verification_namespace()
    verify = namespace["_verify_artifacts"]
    error_type = namespace["ReconciliationError"]
    with pytest.raises(error_type, match="do not match source"):
        verify(wheel, tampered, "0.4.0")
