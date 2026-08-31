"""Trusted CI control plane primitives (P2-EXIT-02).

Separates the scanned target root from the trust artifact root, supports
protected digest pinning for Policy and Qualification artifacts, and never
discovers trust evidence from scanned project content. This module is
import-light on purpose: it must stay loadable before the policy package.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Literal

TrustMode = Literal["repository_local", "external_trust_root"]

TRUST_MODE_REPOSITORY_LOCAL: TrustMode = "repository_local"
TRUST_MODE_EXTERNAL_TRUST_ROOT: TrustMode = "external_trust_root"
EXPECTED_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TRUST_ARTIFACT_MAX_SIZE_BYTES = 2_097_152


class TrustError(ValueError):
    """Safe trust-root, digest-pin, or trust-artifact failure."""


def ensure_safe_relative_posix_path(value: str, *, label: str) -> str:
    """Validate one relative POSIX path without empty or dot segments."""

    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in ("", ".") for part in PurePosixPath(value).parts)
    ):
        raise TrustError(f"{label} must be a safe relative POSIX path")
    return value


def resolve_trust_policy_path(
    policy_path: Path, trust_root: Path | None
) -> tuple[Path, TrustMode]:
    """Resolve the explicit Policy path against the trust root.

    Without a trust root the Policy remains repository-local lower-trust
    input. With a trust root the Policy must be a relative path that stays
    inside the trusted directory; escaping paths, symlinked roots, and
    non-directory roots are rejected.
    """

    if not isinstance(policy_path, Path):
        raise TypeError("policy path must be a Path")
    if trust_root is None:
        return policy_path, TRUST_MODE_REPOSITORY_LOCAL
    if not isinstance(trust_root, Path):
        raise TypeError("trust root must be a Path")
    if trust_root.is_symlink():
        raise TrustError("trust root must not be a symlink")
    if not trust_root.is_dir():
        raise TrustError("trust root must be an existing directory")
    try:
        base = trust_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise TrustError("trust root could not be resolved") from error
    if policy_path.is_absolute():
        raise TrustError("--policy must be relative when --trust-root is set")
    candidate = base / policy_path
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise TrustError("trusted policy is missing or unsafe") from error
    if not resolved.is_relative_to(base):
        raise TrustError("trusted policy escapes the trust root")
    return resolved, TRUST_MODE_EXTERNAL_TRUST_ROOT


def safe_file_sha256(path: Path, *, limit: int = TRUST_ARTIFACT_MAX_SIZE_BYTES) -> str:
    """Compute the SHA-256 of one bounded regular no-follow file."""

    if not isinstance(path, Path):
        raise TypeError("path must be a Path")
    if path.is_symlink() or not path.is_file():
        raise TrustError("trust artifact is missing or unsafe")
    raw = path.read_bytes()
    if len(raw) > limit:
        raise TrustError("trust artifact exceeds the bounded size limit")
    return hashlib.sha256(raw).hexdigest()


def verify_expected_sha256(actual: str, expected: str, *, label: str) -> None:
    """Fail closed when a protected digest pin does not match."""

    if not EXPECTED_SHA256_PATTERN.fullmatch(expected):
        raise TrustError(f"{label} digest pin must be 64 lowercase hex chars")
    if actual != expected:
        raise TrustError(f"{label} digest does not match the protected expectation")


def validate_expected_sha256_option(value: str, *, label: str) -> str:
    """Validate a CLI digest pin before any trust artifact is touched."""

    if not EXPECTED_SHA256_PATTERN.fullmatch(value):
        raise TrustError(f"{label} digest pin must be 64 lowercase hex chars")
    return value


__all__ = [
    "EXPECTED_SHA256_PATTERN",
    "TRUST_ARTIFACT_MAX_SIZE_BYTES",
    "TRUST_MODE_EXTERNAL_TRUST_ROOT",
    "TRUST_MODE_REPOSITORY_LOCAL",
    "TrustError",
    "ensure_safe_relative_posix_path",
    "resolve_trust_policy_path",
    "safe_file_sha256",
    "validate_expected_sha256_option",
    "verify_expected_sha256",
]
