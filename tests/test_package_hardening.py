"""P2-EXIT-07 package API and supply-chain hardening tests."""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

from agentsec.versioning import PACKAGE_VERSION

ROOT = Path(__file__).resolve().parents[1]


def test_clean_process_imports_policy_and_supported_api() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import agentsec.policy; "
                "from agentsec.api import AgentAnalysisPipeline, "
                "DeterministicHomiReportOnlyPilot, OfflineFixtureSemanticProvider, "
                "SemanticAnalysisContract, SemanticEvaluationHarness, "
                "SemanticShadowInvocationAdapter; "
                "assert AgentAnalysisPipeline and DeterministicHomiReportOnlyPilot "
                "and OfflineFixtureSemanticProvider and SemanticAnalysisContract "
                "and SemanticEvaluationHarness and SemanticShadowInvocationAdapter"
            ),
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_py_typed_is_packaged_by_project_configuration() -> None:
    assert (ROOT / "src" / "agentsec" / "py.typed").is_file()
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert 'agentsec = ["py.typed", "templates/*.html"]' in pyproject
    assert "include src/agentsec/py.typed" in manifest


def test_lockfiles_sbom_and_license_inventory_match() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify-package-hardening.py"],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout
    sbom = json.loads((ROOT / "supply-chain" / "sbom.cdx.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    inventory = json.loads(
        (ROOT / "supply-chain" / "license-inventory.json").read_text()
    )
    assert inventory["package_version"] == PACKAGE_VERSION
    assert inventory["components"]


def test_build_provenance_is_explicitly_non_claiming() -> None:
    payload = json.loads((ROOT / "supply-chain" / "build-provenance.json").read_text())

    assert payload["package"] == "agentsec"
    assert payload["source_date_epoch_required"] is True
    assert payload["artifact_signature"] == "not_claimed"
    assert payload["slsa_provenance"] == "not_claimed"
    assert "setuptools==84.0.0" in payload["build_requirements"]


def test_reproducible_build_verifier_exposes_fixed_epoch_contract() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify-reproducible-build.py", "--help"],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "SOURCE_DATE_EPOCH" in result.stdout


def test_external_reviewer_pack_is_excluded_from_general_sdist() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "prune pilots/external-homi-demo/final-pilot/reviewer-pack" in manifest
    assert "prune pilots/external-homi-demo/final-pilot/human-evidence" in manifest


def test_current_wheel_contains_py_typed_and_curated_api(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            ".",
            "-w",
            str(wheel_dir),
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    wheels = tuple(wheel_dir.glob("agentsec-*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        assert "agentsec/py.typed" in names
        assert "agentsec/api.py" in names
        assert "agentsec/exit_codes.py" in names
