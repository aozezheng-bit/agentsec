#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_executable="${PYTHON:-$repository_root/.venv/bin/python}"
dist_root="$repository_root/dist"

if [[ ! -x "$python_executable" ]]; then
  echo "Python executable not found: $python_executable" >&2
  exit 2
fi

release_version="$(
  PYTHONPATH="$repository_root/src" "$python_executable" - <<'PY'
from agentsec.versioning import PACKAGE_VERSION
print(PACKAGE_VERSION)
PY
)"
if [[ "$release_version" == "0.2.0" && -f "$repository_root/src/agentsec/change_impact/models.py" ]]; then
  echo "P2-13 source development is not releasable as Package 0.2.0." >&2
  echo "Choose a new reviewed package version before rebuilding distribution artifacts." >&2
  exit 4
fi
release_dir="$dist_root/$release_version"
if [[ -e "$release_dir" ]]; then
  echo "Release directory already exists: $release_dir" >&2
  echo "Preserving existing artifacts; choose an explicit reviewed cleanup before rebuilding." >&2
  exit 4
fi

mkdir -p "$dist_root"
build_dir="$(mktemp -d "$dist_root/.build-$release_version.XXXXXX")"
cleanup() {
  if [[ -d "$build_dir" ]]; then
    rm -rf "$build_dir"
  fi
}
trap cleanup EXIT

cd "$repository_root"
"$python_executable" -m pip wheel . \
  --no-deps \
  --no-build-isolation \
  --wheel-dir "$build_dir"

PYTHONPATH="$repository_root/src" "$python_executable" - "$build_dir" <<'PY'
from pathlib import Path
from setuptools import build_meta
import sys

filename = build_meta.build_sdist(sys.argv[1])
print(f"Built {filename}")
PY

RELEASE_VERSION="$release_version" "$python_executable" - "$build_dir" <<'PY'
from __future__ import annotations

import hashlib
import os
import tarfile
import zipfile
from pathlib import Path
import sys

release_version = os.environ["RELEASE_VERSION"]
build_dir = Path(sys.argv[1])
artifacts = sorted(
    path
    for path in build_dir.iterdir()
    if path.is_file() and path.name != "SHA256SUMS"
)
wheels = [path for path in artifacts if path.suffix == ".whl"]
sdists = [path for path in artifacts if path.name.endswith(".tar.gz")]
if len(wheels) != 1:
    raise SystemExit("release build must produce exactly one wheel")
if len(sdists) != 1:
    raise SystemExit("release build must produce exactly one sdist")

wheel = wheels[0]
with zipfile.ZipFile(wheel) as archive:
    names = set(archive.namelist())
    required = {
        "agentsec/__init__.py",
        "agentsec/application/agent_analysis.py",
        "agentsec/application/attack_graph.py",
        "agentsec/application/capability_impact.py",
        "agentsec/artifacts/storage.py",
        "agentsec/artifacts/association_inputs.py",
        "agentsec/attack_graph/__init__.py",
        "agentsec/attack_graph/association.py",
        "agentsec/attack_graph/calibration.py",
        "agentsec/attack_graph/report.py",
        "agentsec/cli/attack_graph.py",
        "agentsec/capability_rules/builtin.py",
        "agentsec/cli/app.py",
        "agentsec/cli/capability.py",
        "agentsec/cli/manifest.py",
        "agentsec/manifests/models.py",
        "agentsec/organization_policy.py",
        "agentsec/pilot.py",
        "agentsec/calibration/pilot_tuning.py",
        "agentsec/reporting/capability_assessment_json.py",
        "agentsec/reporting/capability_impact.py",
        "agentsec/reporting/sarif.py",
        "agentsec/risk/attack_path_score.py",
        "agentsec/release_bundle.py",
        "agentsec/semantic/gate_definition.py",
    }
    if not required <= names:
        missing = sorted(required - names)
        raise SystemExit(f"wheel is missing required package files: {missing}")
    metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
    entry_name = next(
        name for name in names if name.endswith(".dist-info/entry_points.txt")
    )
    metadata = archive.read(metadata_name).decode("utf-8")
    entry_points = archive.read(entry_name).decode("utf-8")
    if f"Version: {release_version}" not in metadata:
        raise SystemExit("wheel metadata version does not match source version")
    if "agentsec = agentsec.cli:main" not in entry_points:
        raise SystemExit("wheel console script is missing")

sdist = sdists[0]
with tarfile.open(sdist, "r:gz") as archive:
    names = set(archive.getnames())
    required_suffixes = {
        "LICENSE",
        "README.md",
        "CHANGELOG.md",
        f"docs/releases/{release_version}.md",
        f"docs/releases/{release_version}-known-limitations.md",
        f"docs/releases/{release_version}-acceptance.md",
        "schemas/manifest/agent-manifest.schema.json",
        "schemas/capability-diff/capability-diff.schema.json",
        "schemas/capability-assessment/capability-assessment.schema.json",
        "schemas/capability-change-impact/capability-change-impact.schema.json",
        "schemas/attack-graph/attack-path-report.schema.json",
        "schemas/attack-graph/attack-path-evidence-association-report.schema.json",
        "schemas/attack-graph/attack-path-calibration-report.schema.json",
        "schemas/score-context/attack-path-score-context.schema.json",
        "docs/tasks/P3-AG-09-attack-path-score-integration.md",
        "scripts/reconcile-candidate-artifacts.py",
        "scripts/build-release-provenance-bundle.py",
        "docs/tasks/P3-REL-04-release-manifest-provenance-bundle-hardening.md",
        "docs/tasks/P3-18-semantic-gate-definition-controlled-qualification.md",
        "schemas/semantic-analysis/semantic-gate-candidate.schema.json",
        "schemas/semantic-analysis/semantic-gate-qualification-report.schema.json",
        "scripts/create-semantic-gate-candidate.py",
        "scripts/run-semantic-gate-qualification.py",
        "demos/capability-drift-agent/risky-drift/.codex/config.toml",
        "demos/capability-drift-agent/expected/risky-drift.assessment.json",
        "demos/capability-drift-agent/expected/risky-drift.assessment.txt",
        "demos/capability-drift-agent/expected/checksums.sha256",
        "demos/capability-drift-agent-zh/risky-drift/.codex/config.toml",
        "demos/capability-drift-agent-zh/expected/risky-drift.assessment.json",
        "demos/capability-drift-agent-zh/expected/risky-drift.assessment.txt",
        "demos/capability-drift-agent-zh/expected/checksums.sha256",
        "scripts/run-capability-demo.sh",
        "scripts/run-agentsec-ci.sh",
        "scripts/run-pilot.py",
        "scripts/run-rule-score-calibration.py",
        "scripts/verify-release-install.sh",
        "policies/organization-policy-enforce-example.yaml",
        "pilots/internal-release-agent/pilot.yaml",
        "pilots/internal-release-agent/results/pilot-report.json",
        "calibration/pilot-rule-score/rule-score-calibration-report.json",
        "schemas/pilot/pilot-report.schema.json",
        "schemas/calibration/rule-score-calibration-report.schema.json",
        ".github/workflows/agentsec.yml",
        ".github/workflows/agentsec-pilot.yml",
        "tests/test_internal_mvp_release.py",
    }
    for suffix in required_suffixes:
        if not any(name.endswith(suffix) for name in names):
            raise SystemExit(f"sdist is missing {suffix}")

lines = []
for path in artifacts:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {path.name}")
(build_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
for line in lines:
    print(line)
PY

mv "$build_dir" "$release_dir"
trap - EXIT
printf 'Release artifacts created: %s\n' "$release_dir"
