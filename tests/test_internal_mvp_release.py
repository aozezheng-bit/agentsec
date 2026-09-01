"""P2-32 AgentSec 0.3.0 local internal MVP artifact acceptance tests."""

from __future__ import annotations

import hashlib
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath

from agentsec.calibration.pilot_tuning import RuleScoreCalibrationReport
from agentsec.pilot import PilotReport
from agentsec.versioning import RISK_MODEL_VERSION, RULE_PACK_VERSION

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.3.0"
RELEASE_DIR = ROOT / "dist" / VERSION


def _artifacts() -> tuple[Path, Path, Path]:
    wheels = tuple(RELEASE_DIR.glob(f"agentsec-{VERSION}-*.whl"))
    sdists = tuple(RELEASE_DIR.glob(f"agentsec-{VERSION}.tar.gz"))
    checksums = tuple(RELEASE_DIR.glob("SHA256SUMS"))
    assert len(wheels) == len(sdists) == len(checksums) == 1
    return wheels[0], sdists[0], checksums[0]


def test_internal_mvp_version_and_calibration_decision_are_frozen() -> None:
    # The frozen 0.3.0 artifacts below are validated independently of the
    # live package version, which has advanced to the 0.4.0 development line.
    assert RULE_PACK_VERSION == "0.3.1"
    assert RISK_MODEL_VERSION == "0.4.0"

    pilot = PilotReport.model_validate_json(
        (ROOT / "pilots/internal-release-agent/results/pilot-report.json").read_text(
            encoding="utf-8"
        )
    )
    calibration = RuleScoreCalibrationReport.model_validate_json(
        (
            ROOT / "calibration/pilot-rule-score/rule-score-calibration-report.json"
        ).read_text(encoding="utf-8")
    )
    assert pilot.status == "complete" and pilot.metrics.passed_cases == 8
    assert calibration.status == "complete"
    assert calibration.decision.current_rule_pack_version == "0.3.0"
    assert calibration.decision.internal_mvp_ready is True
    assert calibration.decision.publish_rule_changes is False
    assert calibration.decision.publish_score_changes is False


def test_internal_mvp_artifacts_have_exact_set_and_checksums() -> None:
    wheel, sdist, checksum_path = _artifacts()
    entries: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, separator, filename = line.partition("  ")
        assert separator == "  "
        assert len(digest) == 64
        assert PurePosixPath(filename).name == filename
        entries[filename] = digest

    assert set(entries) == {wheel.name, sdist.name}
    for artifact in (wheel, sdist):
        assert (
            hashlib.sha256(artifact.read_bytes()).hexdigest() == entries[artifact.name]
        )


def test_internal_mvp_wheel_contains_current_policy_and_calibration_modules() -> None:
    wheel, _, _ = _artifacts()
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        required = {
            "agentsec/calibration/pilot_tuning.py",
            "agentsec/fail_on.py",
            "agentsec/organization_policy.py",
            "agentsec/pilot.py",
            "agentsec/policy/ci_enforcement.py",
            "agentsec/reporting/sarif.py",
            "agentsec/risk/scoring_replay.py",
        }
        assert required <= names
        metadata_name = next(name for name in names if name.endswith("METADATA"))
        entry_name = next(name for name in names if name.endswith("entry_points.txt"))
        metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
        assert metadata["Version"] == VERSION
        assert "agentsec = agentsec.cli:main" in archive.read(entry_name).decode(
            "utf-8"
        )


def test_internal_mvp_sdist_contains_release_ci_pilot_and_calibration_evidence() -> (
    None
):
    _, sdist, _ = _artifacts()
    required = {
        ".github/workflows/agentsec.yml",
        ".github/workflows/agentsec-pilot.yml",
        "docs/releases/0.3.0.md",
        "docs/releases/0.3.0-known-limitations.md",
        "docs/releases/0.3.0-acceptance.md",
        "policies/organization-policy-enforce-example.yaml",
        "pilots/internal-release-agent/pilot.yaml",
        "pilots/internal-release-agent/results/pilot-report.json",
        "calibration/pilot-rule-score/rule-score-calibration-report.json",
        "schemas/pilot/pilot-report.schema.json",
        "schemas/calibration/rule-score-calibration-report.schema.json",
        "scripts/run-agentsec-ci.sh",
        "scripts/run-pilot.py",
        "scripts/run-rule-score-calibration.py",
    }
    with tarfile.open(sdist, "r:gz") as archive:
        names = set(archive.getnames())
        for suffix in required:
            assert any(name.endswith(f"/{suffix}") for name in names), suffix


def test_internal_mvp_release_docs_preserve_security_boundaries() -> None:
    paths = (
        ROOT / "docs/releases/0.3.0.md",
        ROOT / "docs/releases/0.3.0-known-limitations.md",
        ROOT / "docs/releases/0.3.0-acceptance.md",
    )
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths).lower()

    assert "--fail-on critical" in text
    assert "runtime" in text and "does not prove" in text
    assert "not a git repository" in text
    assert "remote" in text
    assert "global" in text and "safety" in text
    assert "automatic rule" in text


def test_internal_mvp_reports_are_secret_value_free() -> None:
    paths = (
        ROOT / "pilots/internal-release-agent/results/pilot-report.json",
        ROOT / "calibration/pilot-rule-score/rule-score-calibration-report.json",
    )
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)

    assert "EXAMPLE_DEPLOY_TOKEN_DO_NOT_USE" not in text
    assert "synthetic-demo-token" not in text
    assert "https://" not in text
    assert "excerpt" not in text
