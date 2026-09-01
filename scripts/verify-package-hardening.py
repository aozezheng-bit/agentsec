"""Verify P2-EXIT-07 package API and supply-chain evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _lock_entries(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r "):
            entries.update(_lock_entries(path.parent / line[3:].strip()))
            continue
        if line.startswith("-"):
            continue
        name, version = line.split("==", 1)
        entries[name.casefold().replace("_", "-")] = version
    return entries


def main() -> int:
    py_typed = ROOT / "src" / "agentsec" / "py.typed"
    if not py_typed.is_file():
        raise SystemExit("py.typed is missing")

    runtime_lock = ROOT / "requirements" / "runtime.lock"
    dev_lock = ROOT / "requirements" / "dev.lock"
    lock_hashes = ROOT / "supply-chain" / "lockfiles.sha256"
    for path in (runtime_lock, dev_lock, lock_hashes):
        if not path.is_file():
            raise SystemExit(f"supply-chain evidence is missing: {path}")
    expected_hashes = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (runtime_lock, dev_lock)
    }
    observed_hashes: dict[str, str] = {}
    for line in lock_hashes.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        digest, relative = line.split(None, 1)
        observed_hashes[relative] = digest
    if observed_hashes != expected_hashes:
        raise SystemExit("lockfile hashes are stale or incomplete")

    runtime = _lock_entries(runtime_lock)
    development = _lock_entries(dev_lock)
    for name, version in runtime.items():
        if development.get(name) != version:
            raise SystemExit(
                f"development lock does not constrain runtime package: {name}"
            )

    sbom = json.loads(
        (ROOT / "supply-chain" / "sbom.cdx.json").read_text(encoding="utf-8")
    )
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise SystemExit("SBOM is not CycloneDX 1.5")
    sbom_components = {
        item["name"].casefold().replace("_", "-"): item["version"]
        for item in sbom["components"]
    }
    expected_components = dict(runtime)
    expected_components.update(development)
    expected_components["agentsec"] = "0.4.0"
    if sbom_components != expected_components:
        raise SystemExit("SBOM components do not match locked package inventory")

    inventory = json.loads(
        (ROOT / "supply-chain" / "license-inventory.json").read_text(encoding="utf-8")
    )
    inventory_components = {
        item["name"].casefold().replace("_", "-"): item["version"]
        for item in inventory["components"]
    }
    if inventory_components != expected_components:
        raise SystemExit("license inventory does not match locked package inventory")

    subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import agentsec.policy; "
                "from agentsec.api import AgentAnalysisPipeline, "
                "DeterministicHomiReportOnlyPilot, OfflineFixtureSemanticProvider, "
                "SemanticAnalysisContract, SemanticEvaluationHarness, "
                "SemanticShadowInvocationAdapter; "
                "from agentsec.release_bundle import validate_provenance_bundle; "
                "from agentsec.semantic import SemanticGateQualificationRunner; "
                "assert AgentAnalysisPipeline and DeterministicHomiReportOnlyPilot "
                "and OfflineFixtureSemanticProvider and SemanticAnalysisContract "
                "and SemanticEvaluationHarness and SemanticShadowInvocationAdapter "
                "and validate_provenance_bundle and SemanticGateQualificationRunner"
            ),
        ],
        cwd=ROOT,
        check=True,
    )
    print("P2-EXIT-07 package API and supply-chain evidence: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
