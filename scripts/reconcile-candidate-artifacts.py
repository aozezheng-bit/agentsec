#!/usr/bin/env python3
"""P3-REL-03: reconcile candidate artifacts at byte-level with current source.

The command builds a fresh Wheel and sdist from the current source tree, checks
that the package contains the current Python modules and public Schemas, runs
an offline installed-CLI smoke test, and writes the result to a new candidate
目录.  It never overwrites the preserved ``dist/<version>/`` candidate.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "dist" / "candidates" / "0.4.0-p3-rel-01"
FORMAT = "agentsec-candidate-artifact-reconciliation-report"
FORMAT_VERSION = "0.2.0"
TASK_ID = "P3-REL-03"


class ReconciliationError(RuntimeError):
    """Safe candidate reconciliation failure without source-content output."""


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


def _source_package_files() -> tuple[Path, ...]:
    return tuple(
        sorted(
            path for path in (ROOT / "src" / "agentsec").rglob("*.py") if path.is_file()
        )
    )


def _source_schema_files() -> tuple[Path, ...]:
    return tuple(sorted(path for path in (ROOT / "schemas").rglob("*.json")))


def _source_inventory() -> dict[str, Any]:
    records = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": _sha256(path),
        }
        for path in (
            ROOT / "pyproject.toml",
            ROOT / "MANIFEST.in",
            *_source_package_files(),
            *_source_schema_files(),
        )
    ]
    return {
        "file_count": len(records),
        "files": records,
        "sha256": _canonical_hash(records),
    }


def _package_version() -> str:
    sys.path.insert(0, str(ROOT / "src"))
    from agentsec.versioning import PACKAGE_VERSION

    return PACKAGE_VERSION


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ReconciliationError("candidate build or smoke test failed")
    return result.stdout


def _copy_source(destination: Path) -> None:
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "build",
            "dist",
            "*.egg-info",
            "__pycache__",
            "*.pyc",
        ),
    )


def _normalize_sdist(path: Path) -> None:
    """Normalize sdist metadata for a fixed-epoch candidate artifact."""

    epoch = 0
    tar_buffer = io.BytesIO()
    with (
        tarfile.open(path, "r:gz") as source,
        tarfile.open(
            fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT
        ) as destination,
    ):
        for original in sorted(source.getmembers(), key=lambda item: item.name):
            member = copy.copy(original)
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.pax_headers = {}
            payload = source.extractfile(original) if original.isfile() else None
            destination.addfile(member, payload)
            if payload is not None:
                payload.close()
    compressed = io.BytesIO()
    with gzip.GzipFile(
        fileobj=compressed, mode="wb", mtime=epoch, filename=""
    ) as stream:
        stream.write(tar_buffer.getvalue())
    path.write_bytes(compressed.getvalue())


def _build(source: Path, output: Path) -> tuple[Path, Path]:
    output.mkdir(parents=True, exist_ok=True)
    build_environment = os.environ.copy()
    build_environment["SOURCE_DATE_EPOCH"] = "0"
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--no-index",
            "--wheel-dir",
            str(output),
        ],
        cwd=source,
        env=build_environment,
    )
    _run(
        [
            sys.executable,
            "-c",
            (
                "from setuptools.build_meta import build_sdist; "
                "import sys; build_sdist(sys.argv[1])"
            ),
            str(output),
        ],
        cwd=source,
        env=build_environment,
    )
    wheels = tuple(sorted(output.glob("*.whl")))
    sdists = tuple(sorted(output.glob("*.tar.gz")))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ReconciliationError(
            "candidate build must produce one wheel and one sdist"
        )
    return wheels[0], sdists[0]


def _wheel_names(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as archive:
        return set(archive.namelist())


def _sdist_names(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as archive:
        return set(archive.getnames())


def _wheel_files(path: Path) -> dict[str, bytes]:
    """Read regular Wheel members once, rejecting duplicate member names."""

    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ReconciliationError("candidate Wheel contains duplicate members")
        return {
            info.filename: archive.read(info) for info in infos if not info.is_dir()
        }


def _sdist_files(path: Path) -> dict[str, bytes]:
    """Read regular sdist members once, rejecting duplicate member names."""

    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise ReconciliationError("candidate sdist contains duplicate members")
        files: dict[str, bytes] = {}
        for member in members:
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise ReconciliationError("candidate sdist contains unreadable files")
            with stream:
                files[member.name] = stream.read()
        return files


def _compare_expected_files(
    archive_files: dict[str, bytes], expected: dict[str, Path]
) -> tuple[list[str], list[str]]:
    """Return missing and byte-mismatched paths without exposing file contents."""

    missing = sorted(name for name in expected if name not in archive_files)
    mismatched = sorted(
        name
        for name, source_path in expected.items()
        if name in archive_files and archive_files[name] != source_path.read_bytes()
    )
    return missing, mismatched


def _verify_artifacts(
    wheel: Path,
    sdist: Path,
    package_version: str,
) -> dict[str, Any]:
    wheel_names = _wheel_names(wheel)
    sdist_names = _sdist_names(sdist)
    wheel_prefix = f"agentsec-{package_version}/"

    source_package_paths = _source_package_files()
    source_package_names = {
        path.relative_to(ROOT / "src").as_posix() for path in source_package_paths
    }
    missing_wheel = sorted(
        name for name in source_package_names if name not in wheel_names
    )
    missing_sdist = sorted(
        f"{wheel_prefix}src/{name}"
        for name in source_package_names
        if f"{wheel_prefix}src/{name}" not in sdist_names
    )
    schema_paths = _source_schema_files()
    schema_names = {path.relative_to(ROOT).as_posix() for path in schema_paths}
    missing_sdist_schemas = sorted(
        f"{wheel_prefix}{name}"
        for name in schema_names
        if f"{wheel_prefix}{name}" not in sdist_names
    )
    required_wheel = {
        "agentsec/attack_graph/__init__.py",
        "agentsec/attack_graph/association.py",
        "agentsec/attack_graph/calibration.py",
        "agentsec/cli/attack_graph.py",
        "agentsec/risk/attack_path_score.py",
        "agentsec/semantic/gate_definition.py",
    }
    required_sdist = {
        f"{wheel_prefix}docs/tasks/P3-AG-09-attack-path-score-integration.md",
        f"{wheel_prefix}scripts/export_release_schemas.py",
        f"{wheel_prefix}scripts/reconcile-candidate-artifacts.py",
        f"{wheel_prefix}schemas/score-context/attack-path-score-context.schema.json",
        f"{wheel_prefix}schemas/semantic-analysis/semantic-gate-candidate.schema.json",
        f"{wheel_prefix}schemas/semantic-analysis/semantic-gate-qualification-report.schema.json",
        f"{wheel_prefix}docs/tasks/P3-18-semantic-gate-definition-controlled-qualification.md",
        f"{wheel_prefix}scripts/run-semantic-gate-qualification.py",
        f"{wheel_prefix}scripts/create-semantic-gate-candidate.py",
    }
    metadata_name = next(
        (name for name in wheel_names if name.endswith(".dist-info/METADATA")), None
    )
    entry_points_name = next(
        (name for name in wheel_names if name.endswith(".dist-info/entry_points.txt")),
        None,
    )
    if metadata_name is None or entry_points_name is None:
        raise ReconciliationError("candidate wheel metadata is incomplete")
    with zipfile.ZipFile(wheel) as archive:
        metadata = archive.read(metadata_name).decode("utf-8")
        entry_points = archive.read(entry_points_name).decode("utf-8")
    wheel_files = _wheel_files(wheel)
    sdist_files = _sdist_files(sdist)
    expected_wheel = {
        path.relative_to(ROOT / "src").as_posix(): path for path in source_package_paths
    }
    expected_sdist_package = {
        f"{wheel_prefix}src/{path.relative_to(ROOT / 'src').as_posix()}": path
        for path in source_package_paths
    }
    expected_sdist_schema = {
        f"{wheel_prefix}{path.relative_to(ROOT).as_posix()}": path
        for path in schema_paths
    }
    expected_sdist_metadata = {
        f"{wheel_prefix}{path.name}": path
        for path in (ROOT / "pyproject.toml", ROOT / "MANIFEST.in")
    }
    _, mismatched_wheel = _compare_expected_files(wheel_files, expected_wheel)
    _, mismatched_sdist_package = _compare_expected_files(
        sdist_files, expected_sdist_package
    )
    _, mismatched_sdist_schema = _compare_expected_files(
        sdist_files, expected_sdist_schema
    )
    missing_sdist_metadata, mismatched_sdist_metadata = _compare_expected_files(
        sdist_files, expected_sdist_metadata
    )
    mismatched_sdist = sorted(
        set(mismatched_sdist_package)
        | set(mismatched_sdist_schema)
        | set(mismatched_sdist_metadata)
    )
    content_matches = {
        "wheel_content_match": not missing_wheel and not mismatched_wheel,
        "sdist_content_match": not missing_sdist
        and not missing_sdist_schemas
        and not missing_sdist_metadata
        and not mismatched_sdist,
        "schema_content_match": not missing_sdist_schemas
        and not mismatched_sdist_schema,
        "metadata_content_match": not missing_sdist_metadata
        and not mismatched_sdist_metadata,
    }
    content_checks = {
        **content_matches,
        "mismatched_wheel_files": mismatched_wheel,
        "mismatched_sdist_files": mismatched_sdist,
        "mismatched_sdist_schema_files": mismatched_sdist_schema,
        "mismatched_sdist_metadata_files": mismatched_sdist_metadata,
    }
    checks = {
        "source_package_files_in_wheel": not missing_wheel,
        "source_package_files_in_sdist": not missing_sdist,
        "schemas_in_sdist": not missing_sdist_schemas,
        "required_attack_graph_files_in_wheel": required_wheel <= wheel_names,
        "required_reconciliation_files_in_sdist": required_sdist <= sdist_names,
        "metadata_version": f"Version: {package_version}" in metadata,
        "console_script": "agentsec = agentsec.cli:main" in entry_points,
        "wheel_content_matches_source": content_matches["wheel_content_match"],
        "sdist_content_matches_source": content_matches["sdist_content_match"],
        "schemas_match_source": content_matches["schema_content_match"],
        "metadata_matches_source": content_matches["metadata_content_match"],
    }
    if not all(checks.values()):
        raise ReconciliationError("candidate artifact contents do not match source")
    return {
        "checks": checks,
        "content_checks": content_checks,
        "missing_wheel_files": missing_wheel,
        "missing_sdist_files": missing_sdist,
        "missing_sdist_schemas": missing_sdist_schemas,
        "missing_sdist_metadata": missing_sdist_metadata,
        "mismatched_wheel_files": mismatched_wheel,
        "mismatched_sdist_files": mismatched_sdist,
        "mismatched_sdist_schema_files": mismatched_sdist_schema,
        "mismatched_sdist_metadata_files": mismatched_sdist_metadata,
        "wheel_file_count": len(wheel_names),
        "sdist_file_count": len(sdist_names),
    }


def _base_site_packages() -> Path:
    output = _run(
        [
            sys.executable,
            "-c",
            "import site; print(site.getsitepackages()[0])",
        ],
        cwd=ROOT,
    ).strip()
    path = Path(output)
    if not path.is_dir():
        raise ReconciliationError("base dependency site-packages are unavailable")
    return path


def _installed_cli_smoke(wheel: Path, package_version: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="agentsec-reconciliation-smoke-") as raw:
        root = Path(raw)
        venv_dir = root / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
        venv_python = venv_dir / "bin" / "python"
        venv_agentsec = venv_dir / "bin" / "agentsec"
        site_packages = _run(
            [str(venv_python), "-c", "import site; print(site.getsitepackages()[0])"],
            cwd=ROOT,
        ).strip()
        Path(site_packages, "agentsec-offline-dependencies.pth").write_text(
            str(_base_site_packages()) + "\n", encoding="utf-8"
        )
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env["PYTHONNOUSERSITE"] = "1"
        _run(
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--ignore-installed",
                str(wheel),
            ],
            cwd=root,
            env=env,
        )
        version = _run([str(venv_agentsec), "version"], cwd=root, env=env).strip()
        help_text = _run([str(venv_agentsec), "--help"], cwd=root, env=env)
        graph_help = _run(
            [str(venv_agentsec), "attack-graph", "--help"],
            cwd=root,
            env=env,
        )
        score_help = _run([str(venv_agentsec), "score", "--help"], cwd=root, env=env)
        if version != f"agentsec {package_version}":
            raise ReconciliationError("installed candidate version is inconsistent")
        if "attack-graph" not in help_text or "--format" not in graph_help:
            raise ReconciliationError("installed candidate Attack Graph CLI is missing")
        if "--attack-path-report" not in score_help:
            raise ReconciliationError(
                "installed candidate Score CLI is missing Attack Path input"
            )

        graph_output = root / "attack-graph.json"
        _run(
            [
                str(venv_agentsec),
                "attack-graph",
                str(ROOT / "demos" / "attack-path-story-agent"),
                "--agent-id",
                "release-agent",
                "--format",
                "json",
                "--output",
                str(graph_output),
            ],
            cwd=root,
            env=env,
        )
        graph_payload = json.loads(graph_output.read_text(encoding="utf-8"))
        if graph_payload.get("format") != "agentsec-attack-path-report":
            raise ReconciliationError(
                "installed candidate Attack Graph smoke output is invalid"
            )

        score_output = root / "score.json"
        _run(
            [
                str(venv_agentsec),
                "score",
                str(ROOT / "demos" / "capability-drift-agent" / "risky-drift"),
                "--agent-id",
                "release-agent",
                "--before",
                str(
                    ROOT
                    / "demos"
                    / "capability-drift-agent"
                    / "expected"
                    / "baseline.manifest.json"
                ),
                "--attack-path-report",
                str(
                    ROOT
                    / "calibration"
                    / "attack-path"
                    / "seed-association-report.json"
                ),
                "--format",
                "json",
                "--output",
                str(score_output),
            ],
            cwd=root,
            env=env,
        )
        score_payload = json.loads(score_output.read_text(encoding="utf-8"))
        attack_path = score_payload.get("attack_path")
        if (
            not isinstance(attack_path, dict)
            or attack_path.get("scoring_mode") != "context_only"
        ):
            raise ReconciliationError(
                "installed candidate Score Attack Path context is invalid"
            )
        return {
            "version": True,
            "root_help": True,
            "attack_graph_help": True,
            "score_help": True,
            "attack_graph_json": True,
            "score_attack_path_context": True,
        }


def _existing_candidate(path: Path) -> dict[str, Any]:
    if not path.is_dir():
        return {"present": False, "artifacts": {}}
    artifacts = {
        item.name: _sha256(item)
        for item in sorted(path.iterdir())
        if item.is_file() and item.suffix in {".whl", ".gz"}
    }
    return {"present": True, "artifacts": artifacts}


def _render_markdown(report: dict[str, Any]) -> str:
    checks = report["artifact_checks"]["checks"]
    smoke = report["installed_cli_smoke"]
    lines = [
        "# P3-REL-03 Byte-level Candidate Artifact Reconciliation",
        "",
        f"- Status: `{report['status']}`",
        f"- Package: `{report['package_version']}`",
        f"- Source inventory SHA-256: `{report['source_inventory_sha256']}`",
        f"- Candidate directory: `{report['candidate_directory']}`",
        "",
        "## Result",
        "",
        "All current `src/agentsec` Python modules, JSON Schemas, and release",
        "metadata are byte-for-byte identical to their copies in the newly built",
        "candidate artifacts. The preserved historical candidate was not",
        "overwritten.",
        "",
        "## Artifact checks",
        "",
    ]
    lines.extend(f"- {name}: `{value}`" for name, value in checks.items())
    lines.extend(
        [
            "",
            "## Byte-level content evidence",
            "",
            "- Archive member bytes are compared without printing source content.",
            "- Mismatch evidence is limited to relative member paths.",
            "",
            "## Installed CLI smoke",
            "",
        ]
    )
    lines.extend(f"- {name}: `{value}`" for name, value in smoke.items())
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "- The historical candidate remains immutable and separately addressable.",
            "- The smoke test uses `--no-index`; no network or real Provider is used.",
            "- Only inert static analysis commands are run; scanned project content "
            "is never executed.",
            "- Artifact signatures and SLSA provenance remain `not_claimed`.",
            "",
        ]
    )
    return "\n".join(lines)


def reconcile(output_directory: Path, *, force: bool = False) -> dict[str, Any]:
    package_version = _package_version()
    preserved_directory = ROOT / "dist" / package_version
    if output_directory.resolve() == preserved_directory.resolve():
        raise ReconciliationError(
            "reconciliation output must not overwrite preserved candidate"
        )
    if output_directory.exists():
        if not force:
            raise ReconciliationError(
                "reconciliation output already exists; use --force explicitly"
            )
        if not output_directory.is_dir():
            raise ReconciliationError("reconciliation output must be a directory")
        for item in output_directory.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
    output_directory.mkdir(parents=True, exist_ok=True)

    inventory = _source_inventory()
    previous = _existing_candidate(preserved_directory)
    with tempfile.TemporaryDirectory(prefix="agentsec-reconciliation-build-") as raw:
        build_root = Path(raw)
        source_a = build_root / "source-a"
        source_b = build_root / "source-b"
        _copy_source(source_a)
        _copy_source(source_b)
        output_a = build_root / "artifacts-a"
        output_b = build_root / "artifacts-b"
        wheel, sdist = _build(source_a, output_a)
        wheel_b, sdist_b = _build(source_b, output_b)
        _normalize_sdist(sdist)
        _normalize_sdist(sdist_b)
        reproducible = {
            wheel.name: _sha256(wheel) == _sha256(wheel_b),
            sdist.name: _sha256(sdist) == _sha256(sdist_b),
        }
        if not all(reproducible.values()):
            raise ReconciliationError("candidate artifacts are not reproducible")
        artifact_checks = _verify_artifacts(wheel, sdist, package_version)
        smoke = _installed_cli_smoke(wheel, package_version)
        target_wheel = output_directory / wheel.name
        target_sdist = output_directory / sdist.name
        shutil.copy2(wheel, target_wheel)
        shutil.copy2(sdist, target_sdist)

    sums = {
        target_wheel.name: _sha256(target_wheel),
        target_sdist.name: _sha256(target_sdist),
    }
    (output_directory / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())),
        encoding="utf-8",
    )
    preserved_artifacts = previous.get("artifacts", {})
    candidate_differs_from_preserved = any(
        preserved_artifacts.get(name) != digest for name, digest in sums.items()
    )
    report: dict[str, Any] = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "task_id": TASK_ID,
        "status": "reconciled",
        "package_version": package_version,
        "candidate_directory": output_directory.relative_to(ROOT).as_posix()
        if output_directory.is_relative_to(ROOT)
        else "external-output",
        "preserved_candidate_directory": preserved_directory.relative_to(
            ROOT
        ).as_posix(),
        "preserved_candidate": previous,
        "preserved_candidate_unchanged": True,
        "candidate_artifacts_differ_from_preserved": candidate_differs_from_preserved,
        "source_inventory_sha256": inventory["sha256"],
        "source_inventory_file_count": inventory["file_count"],
        "artifact_checks": artifact_checks,
        "content_checks": artifact_checks["content_checks"],
        "installed_cli_smoke": smoke,
        "reproducible_build": {
            "source_date_epoch": 0,
            "byte_identical": True,
        },
        "artifacts": {
            name: {
                "sha256": digest,
                "size_bytes": (output_directory / name).stat().st_size,
            }
            for name, digest in sorted(sums.items())
        },
        "signature": "not_claimed",
        "slsa_provenance": "not_claimed",
        "report_only": True,
        "runtime_verified": False,
        "network_accessed": False,
        "scanned_content_executed": False,
    }
    report_json = (
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    (output_directory / "reconciliation-report.json").write_text(
        report_json, encoding="utf-8"
    )
    (output_directory / "reconciliation-report.md").write_text(
        _render_markdown(report) + "\n", encoding="utf-8"
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=(
            "New candidate directory; the preserved dist/<version> directory is "
            "never overwritten."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Explicitly clear an existing reconciliation output directory.",
    )
    args = parser.parse_args()
    try:
        report = reconcile(args.output_dir.resolve(), force=args.force)
    except ReconciliationError as error:
        print(f"{TASK_ID} failed safely: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
