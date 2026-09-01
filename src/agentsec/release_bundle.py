"""Validation helpers for the local release manifest and provenance bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from agentsec import versioning

RELEASE_MANIFEST_FORMAT = "agentsec-release-manifest"
PROVENANCE_BUNDLE_FORMAT = "agentsec-provenance-bundle"
RELEASE_MANIFEST_TASK_ID = "P3-REL-04"
PROVENANCE_BUNDLE_TASK_ID = "P3-REL-04"
PROVENANCE_CHECKSUM_FILENAME = "PROVENANCE-SHA256SUMS"
MAX_RELEASE_BUNDLE_BYTES = 1_048_576
REQUIRED_SUPPLY_CHAIN_FILES = (
    "requirements/runtime.lock",
    "requirements/dev.lock",
    "supply-chain/sbom.cdx.json",
    "supply-chain/license-inventory.json",
    "supply-chain/lockfiles.sha256",
    "supply-chain/build-provenance.json",
)

_CLAIMS = {
    "artifact_signature": "not_claimed",
    "slsa_provenance": "not_claimed",
    "remote_publication": "not_claimed",
    "runtime_attestation": "not_claimed",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def current_source_inventory(root: Path) -> tuple[int, str]:
    """Return the byte-level source inventory bound by the release manifest."""

    package_root = root / "src" / "agentsec"
    paths = [
        root / "pyproject.toml",
        root / "MANIFEST.in",
        *sorted(package_root.rglob("*.py")),
        *sorted((root / "schemas").rglob("*.json")),
    ]
    if any(not path.is_file() or path.is_symlink() for path in paths):
        raise ReleaseBundleValidationError("release source inventory is incomplete")
    records = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _sha256(path),
        }
        for path in paths
    ]
    return len(records), _canonical_hash(records)


class ReleaseBundleValidationError(ValueError):
    """Raised when a release manifest or provenance bundle fails closed."""


def _root_relative_file(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ReleaseBundleValidationError(f"{label} path is missing")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise ReleaseBundleValidationError(f"{label} path is unsafe")
    path = (root / Path(*relative.parts)).resolve(strict=True)
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ReleaseBundleValidationError(f"{label} path is outside root") from error
    if path.is_symlink() or not path.is_file():
        raise ReleaseBundleValidationError(f"{label} path is not a regular file")
    return path


def _root_relative_directory(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ReleaseBundleValidationError(f"{label} path is missing")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise ReleaseBundleValidationError(f"{label} path is unsafe")
    path = (root / Path(*relative.parts)).resolve(strict=True)
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ReleaseBundleValidationError(f"{label} path is outside root") from error
    if path.is_symlink() or not path.is_dir():
        raise ReleaseBundleValidationError(f"{label} path is not a regular directory")
    return path


def _read_json(root: Path, path: Path, label: str) -> dict[str, Any]:
    resolved = _root_relative_file(root, path.relative_to(root).as_posix(), label)
    if resolved.stat().st_size > MAX_RELEASE_BUNDLE_BYTES:
        raise ReleaseBundleValidationError(f"{label} is oversized")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseBundleValidationError(f"{label} is unreadable") from error
    if not isinstance(payload, dict):
        raise ReleaseBundleValidationError(f"{label} must be a JSON object")
    return payload


def _record(path: Path) -> dict[str, object]:
    return {"sha256": _sha256(path), "size_bytes": path.stat().st_size}


def _require_record(
    record: object, path: Path, label: str, *, expected_path: str | None = None
) -> None:
    if not isinstance(record, dict):
        raise ReleaseBundleValidationError(f"{label} record is malformed")
    if expected_path is not None and record.get("path") != expected_path:
        raise ReleaseBundleValidationError(f"{label} path binding is stale")
    if record.get("sha256") != _sha256(path):
        raise ReleaseBundleValidationError(f"{label} digest is stale")
    if record.get("size_bytes") != path.stat().st_size:
        raise ReleaseBundleValidationError(f"{label} size is stale")


def _parse_provenance_checksums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ReleaseBundleValidationError("provenance checksum line is malformed")
        digest, filename = parts
        relative = PurePosixPath(filename)
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or relative.is_absolute()
            or ".." in relative.parts
            or "." in relative.parts
            or filename in entries
        ):
            raise ReleaseBundleValidationError("provenance checksum entry is invalid")
        entries[filename] = digest
    return entries


def _validate_reconciliation_report(
    root: Path,
    report: dict[str, Any],
    report_path: Path,
    package_version: str,
    inventory_count: int,
    inventory_sha256: str,
) -> None:
    if (
        report.get("format") != "agentsec-candidate-artifact-reconciliation-report"
        or report.get("format_version") != "0.2.0"
        or report.get("task_id") != "P3-REL-03"
        or report.get("status") != "reconciled"
        or report.get("package_version") != package_version
        or report.get("source_inventory_file_count") != inventory_count
        or report.get("source_inventory_sha256") != inventory_sha256
        or report.get("report_only") is not True
        or report.get("network_accessed") is not False
        or report.get("scanned_content_executed") is not False
    ):
        raise ReleaseBundleValidationError("reconciliation report is not accepted")
    checks = report.get("artifact_checks")
    if not isinstance(checks, dict) or not isinstance(checks.get("checks"), dict):
        raise ReleaseBundleValidationError("reconciliation checks are malformed")
    if not checks["checks"] or not all(
        value is True for value in checks["checks"].values()
    ):
        raise ReleaseBundleValidationError("reconciliation checks are incomplete")
    content = report.get("content_checks")
    nested = checks.get("content_checks")
    expected_content = {
        "wheel_content_match": True,
        "sdist_content_match": True,
        "schema_content_match": True,
        "metadata_content_match": True,
        "mismatched_wheel_files": [],
        "mismatched_sdist_files": [],
        "mismatched_sdist_schema_files": [],
        "mismatched_sdist_metadata_files": [],
    }
    if content != expected_content or nested != expected_content:
        raise ReleaseBundleValidationError(
            "reconciliation byte-level evidence is invalid"
        )
    if report_path.stat().st_size > MAX_RELEASE_BUNDLE_BYTES:
        raise ReleaseBundleValidationError("reconciliation report is oversized")


def validate_provenance_bundle(root: Path, bundle_path: Path) -> dict[str, Any]:
    """Validate the complete release manifest/provenance bundle on disk."""

    root = root.resolve(strict=True)
    bundle_path = bundle_path.resolve(strict=True)
    if (
        bundle_path.is_symlink()
        or bundle_path.stat().st_size > MAX_RELEASE_BUNDLE_BYTES
    ):
        raise ReleaseBundleValidationError("provenance bundle is unsafe or oversized")
    try:
        bundle_rel = bundle_path.relative_to(root).as_posix()
    except ValueError as error:
        raise ReleaseBundleValidationError(
            "provenance bundle is outside root"
        ) from error
    bundle = _read_json(root, bundle_path, "provenance bundle")
    if (
        bundle.get("format") != PROVENANCE_BUNDLE_FORMAT
        or bundle.get("format_version") != versioning.PROVENANCE_BUNDLE_VERSION
        or bundle.get("task_id") != PROVENANCE_BUNDLE_TASK_ID
        or bundle.get("package") != "agentsec"
        or bundle.get("package_version") != versioning.PACKAGE_VERSION
    ):
        raise ReleaseBundleValidationError("provenance bundle identity is invalid")

    candidate_dir = _root_relative_directory(
        root, bundle.get("candidate_directory"), "candidate directory"
    )
    candidate_rel = candidate_dir.relative_to(root).as_posix()
    manifest_ref = bundle.get("release_manifest")
    if not isinstance(manifest_ref, dict):
        raise ReleaseBundleValidationError("release manifest binding is missing")
    manifest_path = _root_relative_file(
        root, manifest_ref.get("path"), "release manifest"
    )
    if manifest_path.parent != candidate_dir:
        raise ReleaseBundleValidationError("release manifest is outside candidate")
    manifest = _read_json(root, manifest_path, "release manifest")
    if (
        manifest.get("format") != RELEASE_MANIFEST_FORMAT
        or manifest.get("format_version") != versioning.RELEASE_MANIFEST_VERSION
        or manifest.get("task_id") != RELEASE_MANIFEST_TASK_ID
        or manifest.get("package") != "agentsec"
        or manifest.get("package_version") != versioning.PACKAGE_VERSION
        or manifest.get("candidate_directory") != candidate_rel
    ):
        raise ReleaseBundleValidationError("release manifest identity is invalid")
    _require_record(manifest_ref, manifest_path, "release manifest")

    bundle_manifest = manifest.get("provenance_bundle")
    if not isinstance(bundle_manifest, dict):
        raise ReleaseBundleValidationError(
            "release manifest provenance binding is missing"
        )
    if bundle_manifest.get("path") != bundle_rel:
        raise ReleaseBundleValidationError("release manifest bundle path is stale")
    if bundle_path.parent != candidate_dir:
        raise ReleaseBundleValidationError("provenance bundle is outside candidate")
    integrity = bundle.get("integrity")
    if not isinstance(integrity, dict):
        raise ReleaseBundleValidationError("provenance integrity is missing")
    checksum_path = _root_relative_file(
        root, integrity.get("checksum_file"), "provenance checksum"
    )
    if (
        bundle_manifest.get("checksum_path")
        != checksum_path.relative_to(root).as_posix()
    ):
        raise ReleaseBundleValidationError("release manifest checksum path is stale")

    inventory_count, inventory_sha256 = current_source_inventory(root)
    source_inventory = manifest.get("source_inventory")
    if not isinstance(source_inventory, dict):
        raise ReleaseBundleValidationError("source inventory is missing")
    if (
        source_inventory.get("file_count") != inventory_count
        or source_inventory.get("sha256") != inventory_sha256
        or bundle.get("source_inventory") != source_inventory
    ):
        raise ReleaseBundleValidationError("source inventory binding is stale")

    reconciliation_ref = manifest.get("reconciliation_report")
    if not isinstance(reconciliation_ref, dict):
        raise ReleaseBundleValidationError("reconciliation binding is missing")
    reconciliation_path = _root_relative_file(
        root, reconciliation_ref.get("path"), "reconciliation report"
    )
    if reconciliation_path.parent != candidate_dir:
        raise ReleaseBundleValidationError("reconciliation report is outside candidate")
    reconciliation = _read_json(root, reconciliation_path, "reconciliation report")
    _require_record(reconciliation_ref, reconciliation_path, "reconciliation report")
    _validate_reconciliation_report(
        root,
        reconciliation,
        reconciliation_path,
        versioning.PACKAGE_VERSION,
        inventory_count,
        inventory_sha256,
    )
    if bundle.get("reconciliation_report") != reconciliation_ref:
        raise ReleaseBundleValidationError("bundle reconciliation binding is stale")

    artifact_ref = manifest.get("artifacts")
    if not isinstance(artifact_ref, dict):
        raise ReleaseBundleValidationError("artifact manifest is missing")
    expected_artifact_names = {
        f"agentsec-{versioning.PACKAGE_VERSION}-py3-none-any.whl",
        f"agentsec-{versioning.PACKAGE_VERSION}.tar.gz",
    }
    if set(artifact_ref) != expected_artifact_names:
        raise ReleaseBundleValidationError("artifact manifest is incomplete")
    actual_artifacts: dict[str, Path] = {}
    for name, record in artifact_ref.items():
        path = _root_relative_file(root, f"{candidate_rel}/{name}", "artifact")
        _require_record(record, path, f"artifact {name}")
        actual_artifacts[name] = path
    if bundle.get("artifacts") != {
        name: _record(path) for name, path in sorted(actual_artifacts.items())
    }:
        raise ReleaseBundleValidationError("bundle artifact binding is stale")

    checksum_ref = manifest.get("artifact_checksum_file")
    if not isinstance(checksum_ref, dict):
        raise ReleaseBundleValidationError("artifact checksum binding is missing")
    artifact_checksum_path = _root_relative_file(
        root, checksum_ref.get("path"), "artifact checksum"
    )
    if artifact_checksum_path.parent != candidate_dir:
        raise ReleaseBundleValidationError("artifact checksum is outside candidate")
    _require_record(checksum_ref, artifact_checksum_path, "artifact checksum")
    try:
        artifact_checksums = _parse_provenance_checksums(artifact_checksum_path)
    except (OSError, UnicodeError) as error:
        raise ReleaseBundleValidationError("artifact checksum is unreadable") from error
    expected_artifact_checksums = {
        name: _sha256(path) for name, path in actual_artifacts.items()
    }
    if artifact_checksums != expected_artifact_checksums:
        raise ReleaseBundleValidationError("artifact checksum evidence is stale")

    supply_chain = manifest.get("supply_chain")
    if not isinstance(supply_chain, dict) or not isinstance(
        supply_chain.get("files"), dict
    ):
        raise ReleaseBundleValidationError("supply-chain manifest is missing")
    if set(supply_chain["files"]) != set(REQUIRED_SUPPLY_CHAIN_FILES):
        raise ReleaseBundleValidationError("supply-chain manifest is incomplete")
    supply_files: dict[str, dict[str, object]] = {}
    for relative, record in supply_chain["files"].items():
        path = _root_relative_file(root, relative, "supply-chain evidence")
        _require_record(record, path, f"supply-chain evidence {relative}")
        supply_files[relative] = _record(path)
    bundle_supply_chain = bundle.get("supply_chain")
    if (
        not isinstance(bundle_supply_chain, dict)
        or bundle_supply_chain.get("files") != supply_files
    ):
        raise ReleaseBundleValidationError("bundle supply-chain binding is stale")

    claims = dict(_CLAIMS)
    if manifest.get("claims") != claims or bundle.get("claims") != claims:
        raise ReleaseBundleValidationError("release claims are invalid")
    expected_authority = {
        "manifest_is_evidence_only": True,
        "bundle_is_evidence_only": True,
        "grants_ci_authority": False,
        "grants_runtime_authority": False,
        "grants_publication_authority": False,
    }
    if (
        manifest.get("authority_boundary") != expected_authority
        or bundle.get("authority_boundary") != expected_authority
    ):
        raise ReleaseBundleValidationError("release authority boundary is invalid")
    expected_build = {
        "backend": "setuptools.build_meta",
        "source_date_epoch": 0,
        "reproducible_build": True,
        "network_accessed": False,
        "scanned_content_executed": False,
        "runtime_verified": False,
    }
    if manifest.get("build") != expected_build or bundle.get("build") != expected_build:
        raise ReleaseBundleValidationError("release build contract is invalid")

    files = bundle.get("files")
    if not isinstance(files, dict):
        raise ReleaseBundleValidationError("provenance file inventory is missing")
    report_markdown_path = reconciliation_path.with_suffix(".md")
    expected_files: dict[str, Path] = {
        artifact_checksum_path.relative_to(root).as_posix(): artifact_checksum_path,
        reconciliation_path.relative_to(root).as_posix(): reconciliation_path,
        report_markdown_path.relative_to(root).as_posix(): report_markdown_path,
        manifest_path.relative_to(root).as_posix(): manifest_path,
        **{
            path.relative_to(root).as_posix(): path
            for path in actual_artifacts.values()
        },
        **{
            relative: _root_relative_file(root, relative, "supply-chain evidence")
            for relative in supply_files
        },
    }
    if set(files) != set(expected_files):
        raise ReleaseBundleValidationError("provenance file inventory is incomplete")
    for relative, path in expected_files.items():
        _require_record(files[relative], path, f"provenance file {relative}")

    if (
        not isinstance(integrity, dict)
        or integrity.get("self_digest_excluded") is not True
    ):
        raise ReleaseBundleValidationError(
            "provenance self-integrity contract is invalid"
        )
    checksum_entries = _parse_provenance_checksums(checksum_path)
    expected_checksum_entries = {
        **{relative: str(record["sha256"]) for relative, record in files.items()},
        bundle_rel: _sha256(bundle_path),
    }
    if checksum_entries != expected_checksum_entries:
        raise ReleaseBundleValidationError("provenance checksum bundle is stale")
    return bundle


__all__ = [
    "MAX_RELEASE_BUNDLE_BYTES",
    "PROVENANCE_BUNDLE_FORMAT",
    "PROVENANCE_BUNDLE_TASK_ID",
    "PROVENANCE_CHECKSUM_FILENAME",
    "REQUIRED_SUPPLY_CHAIN_FILES",
    "RELEASE_MANIFEST_FORMAT",
    "RELEASE_MANIFEST_TASK_ID",
    "ReleaseBundleValidationError",
    "current_source_inventory",
    "validate_provenance_bundle",
]
