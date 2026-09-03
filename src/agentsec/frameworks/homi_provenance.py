"""Build and package provenance for the Homi integration.

The Homi scanner is intentionally report-only, so it cannot infer package
identity from the workspace being scanned.  This module records the identity
of the AgentSec implementation that produced a report.  The digests are
computed from packaged resources, not from the target workspace, and no Git
commands, network access, or target execution are involved.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Final

from agentsec.versioning import (
    HOMI_BUILD_PROVENANCE_VERSION,
    PACKAGE_VERSION,
    RULE_PACK_VERSION,
)

HOMI_BUILD_DIGEST_ALGORITHM: Final[str] = "sha256"
HOMI_BUILD_COMMIT_ENVIRONMENT: Final[str] = "AGENTSEC_BUILD_COMMIT"
HOMI_BUILD_COMMIT_UNAVAILABLE: Final[str] = "unavailable"

# Keep this list deliberately narrow: it identifies the implementation that
# can change Homi findings, while package_digest below covers every shipped
# AgentSec resource.  Paths are package-relative and never refer to the target
# Homi workspace.
_HOMI_IMPLEMENTATION_PATHS: Final[tuple[str, ...]] = (
    "cli/homi.py",
    "frameworks/homi.py",
    "frameworks/homi_bundle.py",
    "frameworks/homi_combination.py",
    "frameworks/homi_calibration.py",
    "frameworks/homi_diff.py",
    "frameworks/homi_policy.py",
    "frameworks/homi_profile.py",
    "frameworks/homi_operationality.py",
    "frameworks/homi_posture.py",
    "frameworks/homi_provenance.py",
    "frameworks/homi_pilot.py",
    "frameworks/homi_simulation.py",
    "templates/homi_capability_diff.html",
    "templates/homi_combined_report.html",
    "templates/homi_pilot_report.html",
    "versioning.py",
)
_BUILD_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{7,64}$")
_ALLOWED_PACKAGE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".py", ".html", ".json", ".typed"}
)


@dataclass(frozen=True, slots=True)
class HomiBuildProvenance:
    """Machine-readable identity of the AgentSec Homi implementation."""

    schema_version: str
    digest_algorithm: str
    package_version: str
    adapter_version: str
    profile_model_version: str
    pilot_format_version: str
    combination_rule_pack_version: str
    rule_pack_version: str
    build_commit: str
    build_commit_source: str
    implementation_digest: str
    implementation_file_count: int
    package_digest: str
    package_file_count: int

    def __post_init__(self) -> None:
        _require_text(self.schema_version, "Homi build provenance schema_version")
        _require_text(self.digest_algorithm, "Homi build provenance digest_algorithm")
        if self.digest_algorithm != HOMI_BUILD_DIGEST_ALGORITHM:
            raise ValueError("Homi build provenance digest algorithm is unsupported")
        for value, label in (
            (self.package_version, "package_version"),
            (self.adapter_version, "adapter_version"),
            (self.profile_model_version, "profile_model_version"),
            (self.pilot_format_version, "pilot_format_version"),
            (
                self.combination_rule_pack_version,
                "combination_rule_pack_version",
            ),
            (self.rule_pack_version, "rule_pack_version"),
            (self.build_commit, "build_commit"),
            (self.build_commit_source, "build_commit_source"),
        ):
            _require_text(value, f"Homi build provenance {label}")
        for value, label in (
            (self.implementation_digest, "implementation_digest"),
            (self.package_digest, "package_digest"),
        ):
            _require_digest(value, f"Homi build provenance {label}")
        _require_positive_int(
            self.implementation_file_count, "implementation_file_count"
        )
        _require_positive_int(self.package_file_count, "package_file_count")

    def to_dict(self) -> dict[str, object]:
        """Return a stable, non-sensitive JSON representation."""

        return {
            "schema_version": self.schema_version,
            "digest_algorithm": self.digest_algorithm,
            "package_version": self.package_version,
            "adapter_version": self.adapter_version,
            "profile_model_version": self.profile_model_version,
            "pilot_format_version": self.pilot_format_version,
            "combination_rule_pack_version": self.combination_rule_pack_version,
            "rule_pack_version": self.rule_pack_version,
            "build_commit": self.build_commit,
            "build_commit_source": self.build_commit_source,
            "implementation_digest": self.implementation_digest,
            "implementation_file_count": self.implementation_file_count,
            "package_digest": self.package_digest,
            "package_file_count": self.package_file_count,
        }


def build_homi_build_provenance(*, pilot_format_version: str) -> HomiBuildProvenance:
    """Compute deterministic provenance for the running packaged resources."""

    from agentsec.frameworks.homi import HOMI_ADAPTER_VERSION
    from agentsec.frameworks.homi_combination import (
        HOMI_COMBINATION_RULE_PACK_VERSION,
    )
    from agentsec.frameworks.homi_profile import HOMI_PROFILE_MODEL_VERSION

    _require_text(pilot_format_version, "Homi pilot_format_version")
    package_root = files("agentsec")
    package_entries = tuple(_iter_package_entries(package_root))
    implementation_entries = tuple(
        _selected_entries(package_root, _HOMI_IMPLEMENTATION_PATHS)
    )
    if not package_entries or not implementation_entries:
        raise RuntimeError("AgentSec package resources are incomplete")

    build_commit, build_commit_source = _build_commit()
    return HomiBuildProvenance(
        schema_version=HOMI_BUILD_PROVENANCE_VERSION,
        digest_algorithm=HOMI_BUILD_DIGEST_ALGORITHM,
        package_version=PACKAGE_VERSION,
        adapter_version=HOMI_ADAPTER_VERSION,
        profile_model_version=HOMI_PROFILE_MODEL_VERSION,
        pilot_format_version=pilot_format_version,
        combination_rule_pack_version=HOMI_COMBINATION_RULE_PACK_VERSION,
        rule_pack_version=RULE_PACK_VERSION,
        build_commit=build_commit,
        build_commit_source=build_commit_source,
        implementation_digest=_digest_entries(implementation_entries),
        implementation_file_count=len(implementation_entries),
        package_digest=_digest_entries(package_entries),
        package_file_count=len(package_entries),
    )


def encode_homi_build_provenance_json(provenance: HomiBuildProvenance) -> str:
    """Encode one build fingerprint as deterministic JSON."""

    if not isinstance(provenance, HomiBuildProvenance):
        raise TypeError("Homi build provenance encoder requires HomiBuildProvenance")
    return json.dumps(provenance.to_dict(), ensure_ascii=False, indent=2) + "\n"


def render_homi_build_provenance_text(provenance: HomiBuildProvenance) -> str:
    """Render a compact human-readable build fingerprint."""

    if not isinstance(provenance, HomiBuildProvenance):
        raise TypeError("Homi build provenance renderer requires HomiBuildProvenance")
    values = provenance.to_dict()
    lines = [
        "AgentSec Homi Build Fingerprint",
        f"Package version: {values['package_version']}",
        f"Adapter version: {values['adapter_version']}",
        f"Profile model version: {values['profile_model_version']}",
        f"Pilot format version: {values['pilot_format_version']}",
        f"Combination rule pack version: {values['combination_rule_pack_version']}",
        f"Rule pack version: {values['rule_pack_version']}",
        f"Build commit: {values['build_commit']}",
        f"Build commit source: {values['build_commit_source']}",
        f"Implementation digest: {values['implementation_digest']}",
        f"Package digest: {values['package_digest']}",
        f"Implementation files: {values['implementation_file_count']}",
        f"Package files: {values['package_file_count']}",
        f"Digest algorithm: {values['digest_algorithm']}",
        f"Provenance schema: {values['schema_version']}",
    ]
    return "\n".join(lines) + "\n"


def _iter_package_entries(root: Traversable) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = []

    def visit(current: Traversable, prefix: str) -> None:
        for child in sorted(current.iterdir(), key=lambda item: item.name):
            relative = f"{prefix}/{child.name}" if prefix else child.name
            if child.is_dir():
                if child.name != "__pycache__":
                    visit(child, relative)
                continue
            if not child.is_file() or not _is_package_payload(relative):
                continue
            entries.append((relative, child.read_bytes()))

    visit(root, "")
    return entries


def _selected_entries(
    root: Traversable, paths: tuple[str, ...]
) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = []
    for relative in paths:
        current = root.joinpath(*relative.split("/"))
        if not current.is_file():
            # A missing resource is part of the digest so an incomplete or
            # stale package cannot accidentally share a healthy fingerprint.
            entries.append((relative, b"<missing-resource>"))
            continue
        entries.append((relative, current.read_bytes()))
    return entries


def _is_package_payload(relative: str) -> bool:
    path = relative.casefold()
    if "/__pycache__/" in path or path.endswith((".pyc", ".pyo")):
        return False
    return any(
        relative.casefold().endswith(suffix) for suffix in _ALLOWED_PACKAGE_SUFFIXES
    )


def _digest_entries(entries: tuple[tuple[str, bytes], ...]) -> str:
    digest = hashlib.sha256()
    for relative, content in entries:
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _build_commit() -> tuple[str, str]:
    raw = os.environ.get(HOMI_BUILD_COMMIT_ENVIRONMENT, "").strip().casefold()
    if _BUILD_COMMIT_PATTERN.fullmatch(raw) is not None:
        return raw, "environment"
    return HOMI_BUILD_COMMIT_UNAVAILABLE, "unavailable"


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")


def _require_digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")


def _require_positive_int(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")


__all__ = [
    "HOMI_BUILD_COMMIT_ENVIRONMENT",
    "HOMI_BUILD_COMMIT_UNAVAILABLE",
    "HOMI_BUILD_DIGEST_ALGORITHM",
    "HOMI_BUILD_PROVENANCE_VERSION",
    "HomiBuildProvenance",
    "build_homi_build_provenance",
    "encode_homi_build_provenance_json",
    "render_homi_build_provenance_text",
]
