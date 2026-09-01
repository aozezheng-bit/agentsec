"""Build Wheel/sdist twice in isolated source trees and compare bytes."""

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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_IGNORE_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
    "__pycache__",
}


def _copy_source(destination: Path) -> None:
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(*_IGNORE_NAMES, "*.pyc"),
    )


def _run(command: list[str], *, source: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(
        command,
        cwd=source,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "reproducible build failed; install requirements/dev.lock and retry"
        )


def _build(source: Path, output: Path, epoch: str) -> None:
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = epoch
    build_probe = subprocess.run(
        [sys.executable, "-c", "import build.__main__"],
        cwd=source,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if build_probe.returncode == 0:
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--sdist",
                "--wheel",
                "--no-isolation",
                "--outdir",
                str(output),
            ],
            source=source,
            environment=environment,
        )
        return
    # Fallback keeps the verifier usable in minimal offline environments. Both
    # commands still use the pinned PEP 517 backend from pyproject.toml.
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            ".",
            "-w",
            str(output),
        ],
        source=source,
        environment=environment,
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
        source=source,
        environment=environment,
    )


def _normalize_sdist(path: Path, epoch: int) -> None:
    """Normalize setuptools tar/gzip metadata for byte-reproducible comparison."""

    buffer = io.BytesIO()
    with (
        tarfile.open(path, "r:gz") as source,
        tarfile.open(
            fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT
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
        stream.write(buffer.getvalue())
    path.write_bytes(compressed.getvalue())


def _digests(directory: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-date-epoch",
        default=os.environ.get("SOURCE_DATE_EPOCH", "0"),
        help="Fixed SOURCE_DATE_EPOCH passed to both builds.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Optional JSON report path outside the source tree.",
    )
    args = parser.parse_args()
    if not args.source_date_epoch.isdigit():
        raise SystemExit("--source-date-epoch must be a non-negative integer")

    with tempfile.TemporaryDirectory(prefix="agentsec-repro-build-") as temporary:
        root = Path(temporary)
        source_a = root / "source-a"
        source_b = root / "source-b"
        output_a = root / "artifacts-a"
        output_b = root / "artifacts-b"
        _copy_source(source_a)
        _copy_source(source_b)
        output_a.mkdir()
        output_b.mkdir()
        epoch = int(args.source_date_epoch)
        _build(source_a, output_a, args.source_date_epoch)
        _build(source_b, output_b, args.source_date_epoch)
        for directory in (output_a, output_b):
            for artifact in directory.glob("*.tar.gz"):
                _normalize_sdist(artifact, epoch)
        first = _digests(output_a)
        second = _digests(output_b)
        if first != second:
            raise SystemExit(
                json.dumps(
                    {"first": first, "second": second},
                    indent=2,
                    sort_keys=True,
                )
            )
        report = {
            "format": "agentsec-reproducible-build-report",
            "format_version": "0.1.0",
            "source_date_epoch": int(args.source_date_epoch),
            "artifacts": first,
            "byte_identical": True,
            "signature": "not_claimed",
            "slsa_provenance": "not_claimed",
        }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is None:
        print(rendered, end="")
    else:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
