#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_python="${PYTHON_BASE:-$repository_root/.venv/bin/python}"
release_version="$(
  PYTHONPATH="$repository_root/src" "$base_python" - <<'PY'
from agentsec.versioning import PACKAGE_VERSION
print(PACKAGE_VERSION)
PY
)"
release_dir="$repository_root/dist/$release_version"
wheel="$(find "$release_dir" -maxdepth 1 -type f -name "agentsec-$release_version-*.whl" -print -quit)"

if [[ ! -x "$base_python" ]]; then
  echo "Python executable not found: $base_python" >&2
  exit 2
fi
if [[ -z "$wheel" ]]; then
  echo "AgentSec $release_version wheel not found; run scripts/build-release.sh first." >&2
  exit 2
fi

venv_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentsec-release-install.XXXXXX")"
trap 'rm -rf "$venv_dir"' EXIT

dependency_site_packages="$($base_python - <<'PY'
import site

paths = site.getsitepackages()
if not paths:
    raise SystemExit("base Python does not expose a dependency site-packages path")
print(paths[0])
PY
)"
"$base_python" -m venv "$venv_dir"
verification_site_packages="$($venv_dir/bin/python - <<'PY'
import site

paths = site.getsitepackages()
if not paths:
    raise SystemExit("verification Python does not expose a site-packages path")
print(paths[0])
PY
)"
printf '%s\n' "$dependency_site_packages" \
  > "$verification_site_packages/agentsec-offline-dependencies.pth"
"$venv_dir/bin/python" -m pip install \
  --no-cache-dir \
  --no-index \
  --no-deps \
  --ignore-installed \
  "$wheel"

version_output="$($venv_dir/bin/agentsec version)"
if [[ "$version_output" != "agentsec $release_version" ]]; then
  echo "Installed version mismatch: $version_output" >&2
  exit 1
fi

"$venv_dir/bin/agentsec" rules list >/dev/null
"$venv_dir/bin/agentsec" capability rules list >/dev/null
"$venv_dir/bin/agentsec" scan \
  "$repository_root/testdata/safe/minimal-agent" \
  --format json \
  > "$venv_dir/safe-scan.json"
"$venv_dir/bin/agentsec" scan \
  "$repository_root/demos/release-agent/risky-drift" \
  --format sarif \
  > "$venv_dir/risky.sarif"
set +e
"$venv_dir/bin/agentsec" scan \
  "$repository_root/demos/release-agent/risky-drift" \
  --policy "$repository_root/policies/organization-policy-enforce-example.yaml" \
  --format json \
  > "$venv_dir/risky-policy.json"
policy_exit=$?
"$venv_dir/bin/agentsec" scan \
  "$repository_root/demos/release-agent/risky-drift" \
  --policy "$repository_root/policies/ci/organization-policy-active-waiver.yaml" \
  --format json \
  > "$venv_dir/waived-policy.json"
waiver_exit=$?
set -e
if [[ "$policy_exit" -ne 1 || "$waiver_exit" -ne 0 ]]; then
  echo "Installed Organization Policy/Waiver smoke test failed." >&2
  exit 1
fi
"$venv_dir/bin/agentsec" manifest \
  "$repository_root/demos/capability-drift-agent/baseline" \
  --agent-id release-agent \
  --format json \
  > "$venv_dir/baseline.manifest.json"
"$venv_dir/bin/agentsec" manifest \
  "$repository_root/demos/capability-drift-agent/risky-drift" \
  --agent-id release-agent \
  --format json \
  > "$venv_dir/risky.manifest.json"
"$venv_dir/bin/agentsec" capability assess \
  "$repository_root/demos/capability-drift-agent/risky-drift" \
  --agent-id release-agent \
  --format json \
  > "$venv_dir/risky.assessment.json"
"$venv_dir/bin/agentsec" capability diff \
  --before "$venv_dir/baseline.manifest.json" \
  --after "$venv_dir/risky.manifest.json" \
  --format json \
  > "$venv_dir/risky.diff.json"

"$venv_dir/bin/python" - "$release_version" "$venv_dir" <<'PY'
import importlib.metadata
import json
from pathlib import Path
import sys

import agentsec

release_version = sys.argv[1]
root = Path(sys.argv[2])
assert importlib.metadata.version("agentsec") == release_version
assert agentsec.__file__ is not None
assert Path(agentsec.__file__).resolve().is_relative_to(root.resolve())
scan = json.loads((root / "safe-scan.json").read_text(encoding="utf-8"))
manifest = json.loads((root / "baseline.manifest.json").read_text(encoding="utf-8"))
assessment = json.loads((root / "risky.assessment.json").read_text(encoding="utf-8"))
diff = json.loads((root / "risky.diff.json").read_text(encoding="utf-8"))
sarif = json.loads((root / "risky.sarif").read_text(encoding="utf-8"))
policy = json.loads((root / "risky-policy.json").read_text(encoding="utf-8"))
waived = json.loads((root / "waived-policy.json").read_text(encoding="utf-8"))
assert scan["format"] == "agentsec-assessment" and scan["status"] == "complete"
assert manifest["schema_version"] == "0.3.0"
assert assessment["format"] == "agentsec-capability-assessment"
assert assessment["status"] == "complete" and assessment["summary"]["findings"] == 17
assert assessment["policy"]["ci_blocking_enabled"] is False
assert diff["schema_version"] == "0.1.0" and diff["complete"] is True
assert diff["added_count"] > 0
assert sarif["version"] == "2.1.0" and sarif["runs"]
assert policy["decision"]["exit_code"] == 1
assert policy["decision"]["blocking_finding_ids"]
assert waived["decision"]["exit_code"] == 0
assert waived["decision"]["waived_finding_ids"]
print("Non-editable offline wheel installation verified")
PY
