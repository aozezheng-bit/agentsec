#!/usr/bin/env python3
"""Build a deterministic release manifest and provenance bundle for a Candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec import versioning  # noqa: E402

DEFAULT_CANDIDATE = ROOT / "dist" / "candidates" / "0.4.0-p3-rel-01"
DEFAULT_RECONCILIATION = DEFAULT_CANDIDATE / "reconciliation-report.json"
MANIFEST_NAME = "release-manifest.json"
BUNDLE_NAME = "provenance-bundle.json"
CHECKSUM_NAME = "PROVENANCE-SHA256SUMS"
SUPPLY_CHAIN_FILES = (
    "requirements/runtime.lock",
    "requirements/dev.lock",
    "supply-chain/sbom.cdx.json",
    "supply-chain/license-inventory.json",
    "supply-chain/lockfiles.sha256",
    "supply-chain/build-provenance.json",
)


class ReleaseBundleBuildError(RuntimeError):
    """Safe release bundle failure without source-content output."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root.resolve()).as_posix()
    except (OSError, RuntimeError, ValueError) as error:
        raise ReleaseBundleBuildError(
            "release evidence path is outside repository"
        ) from error


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ReleaseBundleBuildError(f"{label} is missing or unsafe")
    return path


def _load_json(path: Path, label: str) -> dict[str, Any]:
    _regular_file(path, label)
    if path.stat().st_size > 1_048_576:
        raise ReleaseBundleBuildError(f"{label} is oversized")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseBundleBuildError(f"{label} is unreadable") from error
    if not isinstance(payload, dict):
        raise ReleaseBundleBuildError(f"{label} must be a JSON object")
    return payload


def _parse_artifact_checksums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ReleaseBundleBuildError("artifact checksum entry is malformed")
        digest, filename = parts
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or PurePosixPath(filename).name != filename
            or filename in entries
        ):
            raise ReleaseBundleBuildError("artifact checksum entry is invalid")
        entries[filename] = digest
    return entries


def _current_inventory(root: Path) -> tuple[int, str]:
    paths = [
        root / "pyproject.toml",
        root / "MANIFEST.in",
        *sorted((root / "src" / "agentsec").rglob("*.py")),
        *sorted((root / "schemas").rglob("*.json")),
    ]
    if any(not path.is_file() or path.is_symlink() for path in paths):
        raise ReleaseBundleBuildError("release source inventory is incomplete")
    records = [
        {"path": _relative(root, path), "sha256": _sha256(path)} for path in paths
    ]
    encoded = json.dumps(
        records, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return len(records), hashlib.sha256(encoded).hexdigest()


def _verify_reconciliation(
    root: Path, path: Path, payload: dict[str, Any]
) -> tuple[int, str]:
    inventory_count, inventory_sha256 = _current_inventory(root)
    if (
        payload.get("format") != "agentsec-candidate-artifact-reconciliation-report"
        or payload.get("format_version") != "0.2.0"
        or payload.get("task_id") != "P3-REL-03"
        or payload.get("status") != "reconciled"
        or payload.get("package_version") != versioning.PACKAGE_VERSION
        or payload.get("source_inventory_file_count") != inventory_count
        or payload.get("source_inventory_sha256") != inventory_sha256
        or payload.get("report_only") is not True
        or payload.get("network_accessed") is not False
        or payload.get("scanned_content_executed") is not False
    ):
        raise ReleaseBundleBuildError("reconciliation report is stale or invalid")
    artifact_checks = payload.get("artifact_checks")
    if not isinstance(artifact_checks, dict):
        raise ReleaseBundleBuildError("reconciliation artifact checks are missing")
    checks = artifact_checks.get("checks")
    if (
        not isinstance(checks, dict)
        or not checks
        or not all(value is True for value in checks.values())
    ):
        raise ReleaseBundleBuildError("reconciliation artifact checks are incomplete")
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
    if payload.get("content_checks") != expected_content:
        raise ReleaseBundleBuildError("reconciliation content checks are invalid")
    if artifact_checks.get("content_checks") != expected_content:
        raise ReleaseBundleBuildError(
            "nested reconciliation content checks are invalid"
        )
    if path.stat().st_size > 1_048_576:
        raise ReleaseBundleBuildError("reconciliation report is oversized")
    return inventory_count, inventory_sha256


def _record(path: Path) -> dict[str, object]:
    return {"sha256": _sha256(path), "size_bytes": path.stat().st_size}


def build_bundle(
    repository_root: Path,
    candidate_directory: Path,
    reconciliation_report: Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    root = repository_root.resolve(strict=True)
    candidate = candidate_directory.resolve(strict=True)
    if candidate == (root / "dist" / versioning.PACKAGE_VERSION).resolve():
        raise ReleaseBundleBuildError(
            "release bundle must not modify preserved candidate"
        )
    if candidate.is_symlink() or not candidate.is_dir():
        raise ReleaseBundleBuildError("candidate directory is missing or unsafe")
    candidate_rel = _relative(root, candidate)
    report = reconciliation_report.resolve(strict=True)
    if report.parent != candidate:
        raise ReleaseBundleBuildError("reconciliation report must be inside candidate")
    report_payload = _load_json(report, "reconciliation report")
    inventory_count, inventory_sha256 = _verify_reconciliation(
        root, report, report_payload
    )

    artifacts: dict[str, Path] = {}
    for name in (
        f"agentsec-{versioning.PACKAGE_VERSION}-py3-none-any.whl",
        f"agentsec-{versioning.PACKAGE_VERSION}.tar.gz",
    ):
        artifacts[name] = _regular_file(candidate / name, f"candidate artifact {name}")
    artifact_checksums_path = _regular_file(
        candidate / "SHA256SUMS", "artifact checksums"
    )
    if _parse_artifact_checksums(artifact_checksums_path) != {
        name: _sha256(path) for name, path in artifacts.items()
    }:
        raise ReleaseBundleBuildError("candidate artifact checksums are stale")

    supply_chain: dict[str, dict[str, object]] = {}
    for relative in SUPPLY_CHAIN_FILES:
        path = _regular_file(root / Path(*PurePosixPath(relative).parts), relative)
        supply_chain[relative] = _record(path)

    manifest_path = candidate / MANIFEST_NAME
    bundle_path = candidate / BUNDLE_NAME
    checksum_path = candidate / CHECKSUM_NAME
    if not force and any(
        path.exists() for path in (manifest_path, bundle_path, checksum_path)
    ):
        raise ReleaseBundleBuildError("release bundle files already exist; use --force")

    claims = {
        "artifact_signature": "not_claimed",
        "slsa_provenance": "not_claimed",
        "remote_publication": "not_claimed",
        "runtime_attestation": "not_claimed",
    }
    authority_boundary = {
        "manifest_is_evidence_only": True,
        "bundle_is_evidence_only": True,
        "grants_ci_authority": False,
        "grants_runtime_authority": False,
        "grants_publication_authority": False,
    }
    manifest = {
        "format": "agentsec-release-manifest",
        "format_version": versioning.RELEASE_MANIFEST_VERSION,
        "task_id": "P3-REL-04",
        "package": "agentsec",
        "package_version": versioning.PACKAGE_VERSION,
        "candidate_directory": candidate_rel,
        "artifacts": {name: _record(path) for name, path in sorted(artifacts.items())},
        "artifact_checksum_file": {
            "path": _relative(root, artifact_checksums_path),
            **_record(artifact_checksums_path),
        },
        "reconciliation_report": {
            "path": _relative(root, report),
            "format": report_payload["format"],
            "format_version": report_payload["format_version"],
            "task_id": report_payload["task_id"],
            **_record(report),
        },
        "source_inventory": {
            "file_count": inventory_count,
            "sha256": inventory_sha256,
        },
        "supply_chain": {"files": supply_chain},
        "provenance_bundle": {
            "path": _relative(root, bundle_path),
            "checksum_path": _relative(root, checksum_path),
        },
        "build": {
            "backend": "setuptools.build_meta",
            "source_date_epoch": 0,
            "reproducible_build": True,
            "network_accessed": False,
            "scanned_content_executed": False,
            "runtime_verified": False,
        },
        "claims": claims,
        "authority_boundary": authority_boundary,
    }
    _write_json(manifest_path, manifest)

    report_markdown = candidate / "reconciliation-report.md"
    _regular_file(report_markdown, "reconciliation Markdown report")
    bundle_files: dict[str, dict[str, object]] = {
        _relative(root, artifact_checksums_path): _record(artifact_checksums_path),
        _relative(root, report): _record(report),
        _relative(root, report_markdown): _record(report_markdown),
        _relative(root, manifest_path): _record(manifest_path),
        **{_relative(root, path): _record(path) for path in artifacts.values()},
        **{relative: record for relative, record in sorted(supply_chain.items())},
    }
    bundle = {
        "format": "agentsec-provenance-bundle",
        "format_version": versioning.PROVENANCE_BUNDLE_VERSION,
        "task_id": "P3-REL-04",
        "package": "agentsec",
        "package_version": versioning.PACKAGE_VERSION,
        "candidate_directory": candidate_rel,
        "release_manifest": {
            "path": _relative(root, manifest_path),
            **_record(manifest_path),
        },
        "reconciliation_report": manifest["reconciliation_report"],
        "artifacts": manifest["artifacts"],
        "source_inventory": manifest["source_inventory"],
        "supply_chain": manifest["supply_chain"],
        "files": bundle_files,
        "integrity": {
            "checksum_file": _relative(root, checksum_path),
            "self_digest_excluded": True,
        },
        "build": manifest["build"],
        "claims": claims,
        "authority_boundary": authority_boundary,
    }
    _write_json(bundle_path, bundle)

    checksum_entries = {
        **{
            relative: str(record["sha256"]) for relative, record in bundle_files.items()
        },
        _relative(root, bundle_path): _sha256(bundle_path),
    }
    checksum_path.write_text(
        "".join(
            f"{digest}  {relative}\n"
            for relative, digest in sorted(checksum_entries.items())
        ),
        encoding="utf-8",
    )
    return {
        "format": "agentsec-release-provenance-bundle-report",
        "format_version": versioning.PROVENANCE_BUNDLE_VERSION,
        "task_id": "P3-REL-04",
        "status": "created",
        "candidate_directory": candidate_rel,
        "release_manifest": {
            "path": _relative(root, manifest_path),
            **_record(manifest_path),
        },
        "provenance_bundle": {
            "path": _relative(root, bundle_path),
            **_record(bundle_path),
        },
        "provenance_checksum_file": {
            "path": _relative(root, checksum_path),
            **_record(checksum_path),
        },
        "source_inventory": manifest["source_inventory"],
        "claims": claims,
        "report_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--candidate-dir", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument(
        "--reconciliation-report", type=Path, default=DEFAULT_RECONCILIATION
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        result = build_bundle(
            args.repository_root,
            args.candidate_dir,
            args.reconciliation_report,
            force=args.force,
        )
    except (OSError, ValueError, ReleaseBundleBuildError) as error:
        print(f"P3-REL-04 failed safely: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
