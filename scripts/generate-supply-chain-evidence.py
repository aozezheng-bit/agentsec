"""Generate deterministic lockfile, license, and CycloneDX evidence."""

from __future__ import annotations

import hashlib
import json
import re
from importlib.metadata import PackageNotFoundError, metadata
from pathlib import Path

from agentsec.versioning import PACKAGE_VERSION

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_LOCK_FILES = (
    _REPOSITORY_ROOT / "requirements" / "runtime.lock",
    _REPOSITORY_ROOT / "requirements" / "dev.lock",
)
_OUTPUT = _REPOSITORY_ROOT / "supply-chain"
_FALLBACK_LICENSES = {
    "agentsec": "LicenseRef-Proprietary",
    "annotated-doc": "MIT",
    "annotated-types": "MIT",
    "build": "MIT",
    "click": "BSD-3-Clause",
    "librt": "MIT",
    "markdown-it-py": "MIT",
    "mdurl": "MIT",
    "mypy": "MIT",
    "mypy-extensions": "MIT",
    "packaging": "Apache-2.0 OR BSD-2-Clause",
    "pathspec": "MPL-2.0",
    "pip": "MIT",
    "pluggy": "MIT",
    "pydantic": "MIT",
    "pydantic-core": "MIT",
    "pygments": "BSD-2-Clause",
    "pyyaml": "MIT",
    "rich": "MIT",
    "ruff": "MIT",
    "setuptools": "MIT",
    "shellingham": "ISC",
    "typer": "MIT",
    "typing-extensions": "PSF-2.0",
    "typing-inspection": "MIT",
    "types-pyyaml": "MIT",
    "wheel": "MIT",
}


def _parse_lock(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9_.+-]*)", line)
        if match is None:
            raise ValueError(f"unsupported lock entry in {path.name}: {line}")
        result[match.group(1).casefold().replace("_", "-")] = match.group(2)
    return result


def _license_for(package: str) -> str:
    key = package.casefold().replace("_", "-")
    if key in _FALLBACK_LICENSES:
        return _FALLBACK_LICENSES[key]
    try:
        package_metadata = metadata(package)
    except PackageNotFoundError:
        return "LicenseRef-ReviewRequired"
    classifiers = package_metadata.get_all("Classifier") or []
    for item in classifiers:
        if item.startswith("License :: OSI Approved :: "):
            return item.removeprefix("License :: OSI Approved :: ")
    value = package_metadata.get("License")
    return value.strip() if value and value.strip() else "LicenseRef-ReviewRequired"


def _purl(package: str, package_version: str) -> str:
    return f"pkg:pypi/{package.casefold().replace('_', '-')}@{package_version}"


def main() -> None:
    runtime = _parse_lock(_LOCK_FILES[0])
    development = _parse_lock(_LOCK_FILES[1])
    packages = dict(runtime)
    packages.update(development)
    packages["agentsec"] = PACKAGE_VERSION
    scopes = {
        name: tuple(
            scope
            for scope, values in (("runtime", runtime), ("development", development))
            if name in values
        )
        for name in sorted(packages)
    }
    components = []
    inventory = []
    for name in sorted(packages):
        package_version = packages[name]
        license_name = _license_for(name)
        component = {
            "bom-ref": _purl(name, package_version),
            "name": name,
            "version": package_version,
            "type": "library",
            "purl": _purl(name, package_version),
            "scope": "required"
            if name in runtime or name == "agentsec"
            else "optional",
            "licenses": [{"license": {"id": license_name}}],
        }
        components.append(component)
        inventory.append(
            {
                "name": name,
                "version": package_version,
                "scopes": list(scopes[name]) or ["package"],
                "license": license_name,
                "purl": _purl(name, package_version),
            }
        )
    component_bytes = json.dumps(
        components, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hashlib.sha256(component_bytes).hexdigest()
    serial = (
        f"urn:uuid:{digest[:8]}-{digest[8:12]}-5{digest[13:16]}-"
        f"8{digest[17:20]}-{digest[20:32]}"
    )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": f"pkg:pypi/agentsec@{PACKAGE_VERSION}",
                "name": "agentsec",
                "version": PACKAGE_VERSION,
                "type": "application",
                "licenses": [{"license": {"id": "LicenseRef-Proprietary"}}],
            }
        },
        "components": components,
    }
    (_OUTPUT / "sbom.cdx.json").write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (_OUTPUT / "license-inventory.json").write_text(
        json.dumps(
            {
                "format": "agentsec-license-inventory",
                "format_version": "0.1.0",
                "package": "agentsec",
                "package_version": PACKAGE_VERSION,
                "source_lockfiles": [
                    str(path.relative_to(_REPOSITORY_ROOT)) for path in _LOCK_FILES
                ],
                "components": inventory,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    lock_lines = ["# Generated by scripts/generate-supply-chain-evidence.py"]
    for path in _LOCK_FILES:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lock_lines.append(f"{digest}  {path.relative_to(_REPOSITORY_ROOT)}")
    (_OUTPUT / "lockfiles.sha256").write_text(
        "\n".join(lock_lines) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
