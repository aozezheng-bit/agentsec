"""P3-REL-04 release manifest and provenance bundle tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentsec.release_bundle import (
    ReleaseBundleValidationError,
    validate_provenance_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "dist" / "candidates" / "0.4.0-p3-rel-01"
SCRIPT = ROOT / "scripts" / "build-release-provenance-bundle.py"
BUNDLE = CANDIDATE / "provenance-bundle.json"
MANIFEST = CANDIDATE / "release-manifest.json"
CHECKSUMS = CANDIDATE / "PROVENANCE-SHA256SUMS"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_release_manifest_and_bundle_validate() -> None:
    bundle = validate_provenance_bundle(ROOT, BUNDLE)

    assert bundle["format"] == "agentsec-provenance-bundle"
    assert bundle["format_version"] == "0.1.0"
    assert bundle["task_id"] == "P3-REL-04"
    assert bundle["claims"] == {
        "artifact_signature": "not_claimed",
        "slsa_provenance": "not_claimed",
        "remote_publication": "not_claimed",
        "runtime_attestation": "not_claimed",
    }
    assert bundle["integrity"]["self_digest_excluded"] is True
    assert MANIFEST.is_file()
    assert CHECKSUMS.is_file()


def test_release_bundle_generation_is_deterministic() -> None:
    before = {_path.name: _sha256(_path) for _path in (MANIFEST, BUNDLE, CHECKSUMS)}
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--force"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    after = {_path.name: _sha256(_path) for _path in (MANIFEST, BUNDLE, CHECKSUMS)}
    assert after == before
    validate_provenance_bundle(ROOT, BUNDLE)


def test_tampered_release_manifest_fails_closed() -> None:
    original = MANIFEST.read_bytes()
    try:
        payload = json.loads(original)
        payload["source_inventory"]["sha256"] = "0" * 64
        MANIFEST.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(ReleaseBundleValidationError):
            validate_provenance_bundle(ROOT, BUNDLE)
    finally:
        MANIFEST.write_bytes(original)


def test_preserved_candidate_cannot_receive_release_bundle() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--candidate-dir",
            "dist/0.4.0",
            "--reconciliation-report",
            "dist/0.4.0/reconciliation-report.json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "preserved candidate" in result.stderr
