"""Trusted issuer, signature, time, and replay controls for RISK-07.

This module validates externally-produced Runtime Attestation metadata. It never
executes a target Agent and never reads keys from a scanned workspace. HMAC is
used as a dependency-free baseline; an approved platform may replace it with a
KMS-backed asymmetric verifier in a later contract.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal

from agentsec.risk.runtime_attestation import (
    RUNTIME_REPLAY_STORE_FORMAT,
    RUNTIME_REPLAY_STORE_FORMAT_VERSION,
    RUNTIME_TRUST_REGISTRY_FORMAT,
    RUNTIME_TRUST_REGISTRY_FORMAT_VERSION,
    RUNTIME_TRUST_VERIFICATION_FORMAT,
    RUNTIME_TRUST_VERIFICATION_FORMAT_VERSION,
    RuntimeAttestation,
    RuntimeAttestationError,
    RuntimeSignatureAlgorithm,
    RuntimeTrustDecision,
    RuntimeTrustStatus,
    RuntimeVerificationStatus,
    _canonical_bytes,
    _parse_utc,
    _require_runtime_key,
    runtime_trust_verification_id,
)

_MAX_REGISTRY_BYTES = 256 * 1024
_MAX_REPLAY_STORE_BYTES = 1_048_576
_MAX_ISSUERS = 128
_MAX_REPLAY_ENTRIES = 4096
_MAX_ENV_VAR_LENGTH = 128
_ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_DEFAULT_CLOCK_SKEW_SECONDS = 60
_DEFAULT_MAX_ATTESTATION_AGE_SECONDS = 86_400


class RuntimeIssuerStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class TrustedRuntimeIssuer:
    """One trusted issuer/key binding. Secret value never enters this object."""

    issuer: str
    key_id: str
    algorithm: RuntimeSignatureAlgorithm
    secret_env_var: str
    status: RuntimeIssuerStatus = RuntimeIssuerStatus.ACTIVE
    not_before: str | None = None
    not_after: str | None = None
    max_attestation_age_seconds: int = _DEFAULT_MAX_ATTESTATION_AGE_SECONDS
    allowed_clock_skew_seconds: int = _DEFAULT_CLOCK_SKEW_SECONDS

    def __post_init__(self) -> None:
        _require_identifier(self.issuer, "trusted runtime issuer")
        _require_identifier(self.key_id, "trusted runtime key_id")
        if (
            not isinstance(self.secret_env_var, str)
            or _ENV_VAR_PATTERN.fullmatch(self.secret_env_var) is None
        ):
            raise RuntimeAttestationError("trusted runtime secret_env_var is invalid")
        if not isinstance(self.algorithm, RuntimeSignatureAlgorithm):
            raise TypeError("trusted runtime algorithm is invalid")
        if not isinstance(self.status, RuntimeIssuerStatus):
            raise TypeError("trusted runtime issuer status is invalid")
        for value, label in (
            (self.not_before, "not_before"),
            (self.not_after, "not_after"),
        ):
            if value is not None:
                _timestamp(value, label)
        if (
            self.not_before
            and self.not_after
            and _parse_utc(self.not_after) <= _parse_utc(self.not_before)
        ):
            raise RuntimeAttestationError(
                "trusted runtime not_after must be after not_before"
            )
        if not isinstance(self.max_attestation_age_seconds, int) or not (
            1 <= self.max_attestation_age_seconds <= 31_536_000
        ):
            raise RuntimeAttestationError(
                "trusted runtime max_attestation_age_seconds is invalid"
            )
        if not isinstance(self.allowed_clock_skew_seconds, int) or not (
            0 <= self.allowed_clock_skew_seconds <= 86_400
        ):
            raise RuntimeAttestationError(
                "trusted runtime allowed_clock_skew_seconds is invalid"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "issuer": self.issuer,
            "key_id": self.key_id,
            "algorithm": self.algorithm.value,
            "secret_env_var": self.secret_env_var,
            "status": self.status.value,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "max_attestation_age_seconds": self.max_attestation_age_seconds,
            "allowed_clock_skew_seconds": self.allowed_clock_skew_seconds,
        }


@dataclass(frozen=True, slots=True)
class RuntimeTrustRegistry:
    """Versioned allowlist of trusted issuer/key metadata."""

    format: Literal["agentsec-runtime-trust-registry"]
    format_version: str
    issuers: tuple[TrustedRuntimeIssuer, ...]
    report_only: Literal[True] = True
    policy_authority: Literal[False] = False
    ci_blocked: Literal[False] = False

    def __post_init__(self) -> None:
        if self.format != RUNTIME_TRUST_REGISTRY_FORMAT:
            raise RuntimeAttestationError("runtime trust registry format is invalid")
        if self.format_version != RUNTIME_TRUST_REGISTRY_FORMAT_VERSION:
            raise RuntimeAttestationError("runtime trust registry version is invalid")
        if not self.issuers or len(self.issuers) > _MAX_ISSUERS:
            raise RuntimeAttestationError(
                "runtime trust registry issuer count is invalid"
            )
        if self.issuers != tuple(
            sorted(self.issuers, key=lambda item: (item.issuer, item.key_id))
        ):
            raise RuntimeAttestationError(
                "runtime trust registry issuers must be sorted"
            )
        keys = tuple((item.issuer, item.key_id) for item in self.issuers)
        if len(keys) != len(set(keys)):
            raise RuntimeAttestationError("runtime trust registry keys must be unique")
        if (
            self.report_only is not True
            or self.policy_authority is not False
            or self.ci_blocked is not False
        ):
            raise RuntimeAttestationError("runtime trust registry authority is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "format_version": self.format_version,
            "issuers": [item.to_dict() for item in self.issuers],
            "report_only": self.report_only,
            "policy_authority": self.policy_authority,
            "ci_blocked": self.ci_blocked,
            "authority": {
                "report_only": self.report_only,
                "policy_authority": self.policy_authority,
                "ci_blocked": self.ci_blocked,
            },
        }


@dataclass(frozen=True, slots=True)
class RuntimeReplayEntry:
    """Persisted replay marker. Raw nonce and secret are never stored."""

    issuer: str
    key_id: str
    nonce_sha256: str
    attestation_sha256: str
    accepted_at: str
    expires_at: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.nonce_sha256, "nonce_sha256"),
            (self.attestation_sha256, "attestation_sha256"),
        ):
            if not _HEX64(value):
                raise RuntimeAttestationError(f"runtime replay {label} is invalid")
        _require_identifier(self.issuer, "runtime replay issuer")
        _require_identifier(self.key_id, "runtime replay key_id")
        _timestamp(self.accepted_at, "accepted_at")
        _timestamp(self.expires_at, "expires_at")
        if _parse_utc(self.expires_at) <= _parse_utc(self.accepted_at):
            raise RuntimeAttestationError(
                "runtime replay expires_at must be after accepted_at"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "issuer": self.issuer,
            "key_id": self.key_id,
            "nonce_sha256": self.nonce_sha256,
            "attestation_sha256": self.attestation_sha256,
            "accepted_at": self.accepted_at,
            "expires_at": self.expires_at,
        }


class RuntimeReplayStoreError(RuntimeAttestationError):
    """Raised when replay state cannot be safely read or persisted."""


class RuntimeReplayStore:
    """Small locked, atomic, symlink-safe replay store."""

    def __init__(self, path: Path, *, max_entries: int = _MAX_REPLAY_ENTRIES) -> None:
        if not isinstance(path, Path):
            raise TypeError("runtime replay store path must be a Path")
        if path.is_symlink():
            raise RuntimeReplayStoreError("runtime replay store cannot be a symlink")
        if (
            not isinstance(max_entries, int)
            or not 1 <= max_entries <= _MAX_REPLAY_ENTRIES
        ):
            raise RuntimeReplayStoreError("runtime replay store max_entries is invalid")
        self.path = path
        self.max_entries = max_entries

    def check_and_record(
        self,
        attestation: RuntimeAttestation,
        *,
        accepted_at: datetime,
    ) -> bool:
        if not isinstance(attestation, RuntimeAttestation):
            raise TypeError("runtime replay store requires RuntimeAttestation")
        if accepted_at.tzinfo is None:
            raise RuntimeReplayStoreError(
                "runtime replay accepted_at must be timezone-aware"
            )
        now = accepted_at.astimezone(UTC).replace(microsecond=0)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        descriptor: int | None = None
        lock_acquired = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.parent.is_symlink():
                raise RuntimeReplayStoreError(
                    "runtime replay store parent cannot be a symlink"
                )
            descriptor = os.open(
                lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)
            descriptor = None
            lock_acquired = True
            entries = self._load()
            entries = [item for item in entries if _parse_utc(item.expires_at) > now]
            nonce_hash = hashlib.sha256(attestation.nonce.encode("utf-8")).hexdigest()
            if any(
                item.issuer == attestation.issuer and item.nonce_sha256 == nonce_hash
                for item in entries
            ):
                self._write(entries)
                return False
            if len(entries) >= self.max_entries:
                raise RuntimeReplayStoreError(
                    "runtime replay store entry limit exceeded"
                )
            entries.append(
                RuntimeReplayEntry(
                    issuer=attestation.issuer,
                    key_id=attestation.key_id,
                    nonce_sha256=nonce_hash,
                    attestation_sha256=_attestation_digest(attestation),
                    accepted_at=_format_utc(now),
                    expires_at=attestation.expires_at,
                )
            )
            entries.sort(key=lambda item: (item.issuer, item.nonce_sha256))
            self._write(entries)
            return True
        except FileExistsError as error:
            raise RuntimeReplayStoreError("runtime replay store is locked") from error
        except OSError as error:
            raise RuntimeReplayStoreError(
                "runtime replay store operation failed"
            ) from error
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            if lock_acquired:
                with suppress(OSError):
                    lock_path.unlink()

    def _load(self) -> list[RuntimeReplayEntry]:
        if not self.path.exists():
            return []
        if self.path.is_symlink() or not self.path.is_file():
            raise RuntimeReplayStoreError("runtime replay store must be a regular file")
        try:
            descriptor = os.open(
                self.path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise RuntimeReplayStoreError(
                        "runtime replay store must be a regular file"
                    )
                if metadata.st_size > _MAX_REPLAY_STORE_BYTES:
                    raise RuntimeReplayStoreError(
                        "runtime replay store exceeds size limit"
                    )
                raw = os.read(descriptor, _MAX_REPLAY_STORE_BYTES + 1)
            finally:
                os.close(descriptor)
            payload = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeReplayStoreError(
                "runtime replay store JSON is invalid"
            ) from error
        if (
            not isinstance(payload, dict)
            or payload.get("format") != RUNTIME_REPLAY_STORE_FORMAT
        ):
            raise RuntimeReplayStoreError("runtime replay store format is invalid")
        if payload.get("format_version") != RUNTIME_REPLAY_STORE_FORMAT_VERSION:
            raise RuntimeReplayStoreError("runtime replay store version is invalid")
        _require_authority(payload, "runtime replay store")
        raw_entries = payload.get("entries")
        if not isinstance(raw_entries, list) or len(raw_entries) > self.max_entries:
            raise RuntimeReplayStoreError("runtime replay store entries are invalid")
        try:
            entries = [
                RuntimeReplayEntry(**item)
                for item in raw_entries
                if isinstance(item, dict)
            ]
        except (TypeError, ValueError) as error:
            raise RuntimeReplayStoreError(
                "runtime replay store entry is invalid"
            ) from error
        if len(entries) != len(raw_entries):
            raise RuntimeReplayStoreError("runtime replay store entry is invalid")
        keys = tuple((item.issuer, item.nonce_sha256) for item in entries)
        if len(keys) != len(set(keys)):
            raise RuntimeReplayStoreError("runtime replay store entries are duplicated")
        return entries

    def _write(self, entries: list[RuntimeReplayEntry]) -> None:
        payload = {
            "format": RUNTIME_REPLAY_STORE_FORMAT,
            "format_version": RUNTIME_REPLAY_STORE_FORMAT_VERSION,
            "entries": [item.to_dict() for item in entries],
            "report_only": True,
            "policy_authority": False,
            "ci_blocked": False,
            "authority": {
                "report_only": True,
                "policy_authority": False,
                "ci_blocked": False,
            },
        }
        temporary = self.path.with_name(f".{self.path.name}.tmp")
        if temporary.exists() or temporary.is_symlink():
            raise RuntimeReplayStoreError(
                "runtime replay temporary file already exists"
            )
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        except OSError as error:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            with suppress(OSError):
                temporary.unlink()
            raise RuntimeReplayStoreError(
                "runtime replay store write failed"
            ) from error


class EnvironmentRuntimeKeyResolver:
    """Resolve a trusted key only from explicitly named process environment."""

    def resolve(self, issuer: TrustedRuntimeIssuer) -> bytes:
        if not isinstance(issuer, TrustedRuntimeIssuer):
            raise TypeError("runtime key resolver requires TrustedRuntimeIssuer")
        value = os.environ.get(issuer.secret_env_var)
        if value is None:
            raise RuntimeAttestationError(
                "runtime trust key environment variable is missing"
            )
        key = value.encode("utf-8")
        _require_runtime_key(key)
        return key


class DeterministicRuntimeTrustVerifier:
    """Verify Runtime Attestation with fail-closed deterministic checks."""

    def __init__(
        self,
        key_resolver: EnvironmentRuntimeKeyResolver | None = None,
    ) -> None:
        self.key_resolver = key_resolver or EnvironmentRuntimeKeyResolver()

    def verify(
        self,
        attestation: RuntimeAttestation,
        registry: RuntimeTrustRegistry | None,
        *,
        replay_store: RuntimeReplayStore | None = None,
        now: datetime | None = None,
    ) -> RuntimeTrustDecision:
        if not isinstance(attestation, RuntimeAttestation):
            raise TypeError("runtime trust verifier requires RuntimeAttestation")
        if now is not None and now.tzinfo is None:
            raise RuntimeAttestationError(
                "runtime trust verification time must be timezone-aware"
            )
        evaluated = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
        evaluated_at = _format_utc(evaluated)
        source_digest = _attestation_digest(attestation)
        registry_digest = _registry_digest(registry) if registry is not None else None
        base: dict[str, object] = {
            "source_attestation_sha256": source_digest,
            "trust_registry_sha256": registry_digest,
            "issuer": attestation.issuer,
            "key_id": attestation.key_id,
            "signature_algorithm": attestation.signature_algorithm,
            "evaluated_at": evaluated_at,
        }

        if registry is None:
            return _decision(
                base,
                status=RuntimeTrustStatus.MISSING,
                issuer_trusted=False,
                key_trusted=False,
                signature_verified=False,
                time_valid=False,
                replay_detected=False,
                reason_codes=("trust_registry_missing",),
            )
        candidates = [
            item for item in registry.issuers if item.issuer == attestation.issuer
        ]
        if not candidates:
            return _decision(
                base,
                status=RuntimeTrustStatus.UNKNOWN_ISSUER,
                issuer_trusted=False,
                key_trusted=False,
                signature_verified=False,
                time_valid=False,
                replay_detected=False,
                reason_codes=("issuer_not_registered",),
            )
        entry = next(
            (item for item in candidates if item.key_id == attestation.key_id), None
        )
        if entry is None:
            return _decision(
                base,
                status=RuntimeTrustStatus.KEY_MISMATCH,
                issuer_trusted=True,
                key_trusted=False,
                signature_verified=False,
                time_valid=False,
                replay_detected=False,
                reason_codes=("key_id_not_registered",),
            )
        if entry.status is RuntimeIssuerStatus.REVOKED:
            return _decision(
                base,
                status=RuntimeTrustStatus.KEY_REVOKED,
                issuer_trusted=True,
                key_trusted=False,
                signature_verified=False,
                time_valid=False,
                replay_detected=False,
                reason_codes=("key_revoked",),
            )
        if entry.algorithm is not attestation.signature_algorithm:
            return _decision(
                base,
                status=RuntimeTrustStatus.UNSUPPORTED_ALGORITHM,
                issuer_trusted=True,
                key_trusted=True,
                signature_verified=False,
                time_valid=False,
                replay_detected=False,
                reason_codes=("signature_algorithm_mismatch",),
            )
        try:
            key = self.key_resolver.resolve(entry)
        except RuntimeAttestationError:
            return _decision(
                base,
                status=RuntimeTrustStatus.KEY_UNAVAILABLE,
                issuer_trusted=True,
                key_trusted=True,
                signature_verified=False,
                time_valid=False,
                replay_detected=False,
                reason_codes=("signing_key_unavailable",),
            )
        fingerprint = hashlib.sha256(key).hexdigest()
        signature_verified = hmac.compare_digest(
            attestation.signature,
            hmac.new(
                key, _attestation_signing_bytes(attestation), hashlib.sha256
            ).hexdigest(),
        )
        time_valid, time_reason = _time_valid(attestation, entry, evaluated)
        if not signature_verified:
            status = RuntimeTrustStatus.SIGNATURE_INVALID
            reasons = ("signature_invalid",)
        elif not time_valid:
            status = time_reason
            reasons = (time_reason.value,)
        elif attestation.verification_status is not RuntimeVerificationStatus.VERIFIED:
            status = RuntimeTrustStatus.UNVERIFIED_ATTESTATION
            reasons = ("attestation_declared_unverified",)
        else:
            if replay_store is None:
                return _decision(
                    base,
                    status=RuntimeTrustStatus.REPLAY_STORE_ERROR,
                    issuer_trusted=True,
                    key_trusted=True,
                    signature_verified=True,
                    time_valid=True,
                    replay_detected=False,
                    reason_codes=("replay_store_missing",),
                    key_fingerprint_sha256=fingerprint,
                )
            try:
                accepted = (
                    replay_store.check_and_record(attestation, accepted_at=evaluated)
                    if replay_store is not None
                    else False
                )
            except RuntimeReplayStoreError:
                return _decision(
                    base,
                    status=RuntimeTrustStatus.REPLAY_STORE_ERROR,
                    issuer_trusted=True,
                    key_trusted=True,
                    signature_verified=True,
                    time_valid=True,
                    replay_detected=False,
                    reason_codes=("replay_store_error",),
                    key_fingerprint_sha256=fingerprint,
                )
            if not accepted:
                status = RuntimeTrustStatus.REPLAYED
                reasons = ("nonce_replayed",)
            else:
                status = RuntimeTrustStatus.TRUSTED
                reasons = ("signature_time_and_replay_valid",)
        return _decision(
            base,
            status=status,
            issuer_trusted=True,
            key_trusted=True,
            signature_verified=signature_verified,
            time_valid=time_valid,
            replay_detected=status is RuntimeTrustStatus.REPLAYED,
            reason_codes=reasons,
            key_fingerprint_sha256=fingerprint,
        )


def build_runtime_trust_registry(
    issuers: tuple[TrustedRuntimeIssuer, ...],
) -> RuntimeTrustRegistry:
    return RuntimeTrustRegistry(
        format=RUNTIME_TRUST_REGISTRY_FORMAT,
        format_version=RUNTIME_TRUST_REGISTRY_FORMAT_VERSION,
        issuers=tuple(sorted(issuers, key=lambda item: (item.issuer, item.key_id))),
    )


def encode_runtime_trust_registry_json(registry: RuntimeTrustRegistry) -> str:
    return _encode(registry.to_dict())


def decode_runtime_trust_registry_json(payload: str) -> RuntimeTrustRegistry:
    if len(payload.encode("utf-8")) > _MAX_REGISTRY_BYTES:
        raise RuntimeAttestationError("runtime trust registry exceeds size limit")
    value = _decode(payload, "runtime trust registry")
    _require_exact_keys(
        value,
        {
            "format",
            "format_version",
            "issuers",
            "report_only",
            "policy_authority",
            "ci_blocked",
            "authority",
        },
        "runtime trust registry",
    )
    _require_authority(value, "runtime trust registry")
    raw = value.get("issuers")
    if not isinstance(raw, list):
        raise RuntimeAttestationError("runtime trust registry issuers are invalid")
    try:
        for item in raw:
            if isinstance(item, dict):
                _require_exact_keys(
                    item,
                    {
                        "issuer",
                        "key_id",
                        "algorithm",
                        "secret_env_var",
                        "status",
                        "not_before",
                        "not_after",
                        "max_attestation_age_seconds",
                        "allowed_clock_skew_seconds",
                    },
                    "runtime trust registry issuer",
                )
        issuers = tuple(
            TrustedRuntimeIssuer(
                issuer=_string(item, "issuer"),
                key_id=_string(item, "key_id"),
                algorithm=RuntimeSignatureAlgorithm(_string(item, "algorithm")),
                secret_env_var=_string(item, "secret_env_var"),
                status=RuntimeIssuerStatus(_string(item, "status")),
                not_before=_optional_string(item, "not_before"),
                not_after=_optional_string(item, "not_after"),
                max_attestation_age_seconds=_int(item, "max_attestation_age_seconds"),
                allowed_clock_skew_seconds=_int(item, "allowed_clock_skew_seconds"),
            )
            for item in raw
            if isinstance(item, dict)
        )
    except (TypeError, ValueError) as error:
        raise RuntimeAttestationError(
            "runtime trust registry issuer is invalid"
        ) from error
    if len(issuers) != len(raw):
        raise RuntimeAttestationError("runtime trust registry issuer is invalid")
    return RuntimeTrustRegistry(
        format=RUNTIME_TRUST_REGISTRY_FORMAT,
        format_version=_string(value, "format_version"),
        issuers=issuers,
    )


# Trust Verification Report is intentionally the same value object as its
# decision: one deterministic payload, one binding ID, no duplicated authority.
RuntimeTrustVerificationReport = RuntimeTrustDecision


def encode_runtime_trust_verification_json(report: RuntimeTrustDecision) -> str:
    return _encode(report.to_dict())


def decode_runtime_trust_verification_json(payload: str) -> RuntimeTrustDecision:
    if len(payload.encode("utf-8")) > _MAX_REGISTRY_BYTES:
        raise RuntimeAttestationError("runtime trust verification exceeds size limit")
    value = _decode(payload, "runtime trust verification")
    _require_exact_keys(
        value,
        {
            "format",
            "format_version",
            "verification_id",
            "source_attestation_sha256",
            "trust_registry_sha256",
            "issuer",
            "key_id",
            "signature_algorithm",
            "status",
            "trusted",
            "issuer_trusted",
            "key_trusted",
            "signature_verified",
            "time_valid",
            "replay_detected",
            "evaluated_at",
            "reason_codes",
            "key_fingerprint_sha256",
            "report_only",
            "policy_authority",
            "ci_blocked",
            "authority",
        },
        "runtime trust verification",
    )
    _require_authority(value, "runtime trust verification")
    try:
        decision = RuntimeTrustDecision(
            verification_id=_string(value, "verification_id"),
            source_attestation_sha256=_string(value, "source_attestation_sha256"),
            trust_registry_sha256=_optional_string(value, "trust_registry_sha256"),
            issuer=_string(value, "issuer"),
            key_id=_string(value, "key_id"),
            signature_algorithm=RuntimeSignatureAlgorithm(
                _string(value, "signature_algorithm")
            ),
            status=RuntimeTrustStatus(_string(value, "status")),
            issuer_trusted=_bool(value, "issuer_trusted"),
            key_trusted=_bool(value, "key_trusted"),
            signature_verified=_bool(value, "signature_verified"),
            time_valid=_bool(value, "time_valid"),
            replay_detected=_bool(value, "replay_detected"),
            evaluated_at=_string(value, "evaluated_at"),
            reason_codes=_string_tuple(value, "reason_codes"),
            key_fingerprint_sha256=_optional_string(value, "key_fingerprint_sha256"),
        )
    except (TypeError, ValueError) as error:
        raise RuntimeAttestationError(
            "runtime trust verification fields are invalid"
        ) from error
    if value.get("trusted") is not decision.trusted:
        raise RuntimeAttestationError(
            "runtime trust verification trusted flag is invalid"
        )
    return decision


def canonical_runtime_trust_registry_sha256(registry: RuntimeTrustRegistry) -> str:
    return hashlib.sha256(_canonical_bytes(registry.to_dict())).hexdigest()


def canonical_runtime_trust_verification_sha256(report: RuntimeTrustDecision) -> str:
    return hashlib.sha256(_canonical_bytes(report.to_dict())).hexdigest()


def export_runtime_trust_json_schemas(
    output_directory: Path,
) -> tuple[Path, Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    registry_path = output_directory / "runtime-trust-registry.schema.json"
    verification_path = output_directory / "runtime-trust-verification.schema.json"
    replay_path = output_directory / "runtime-replay-store.schema.json"
    authority = {
        "type": "object",
        "additionalProperties": False,
        "required": ["report_only", "policy_authority", "ci_blocked"],
        "properties": {
            "report_only": {"const": True},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
        },
    }
    issuer = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "issuer",
            "key_id",
            "algorithm",
            "secret_env_var",
            "status",
            "not_before",
            "not_after",
            "max_attestation_age_seconds",
            "allowed_clock_skew_seconds",
        ],
        "properties": {
            "issuer": {"type": "string", "minLength": 1, "maxLength": 128},
            "key_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "algorithm": {"enum": [item.value for item in RuntimeSignatureAlgorithm]},
            "secret_env_var": {
                "type": "string",
                "minLength": 1,
                "maxLength": _MAX_ENV_VAR_LENGTH,
            },
            "status": {"enum": [item.value for item in RuntimeIssuerStatus]},
            "not_before": {"type": ["string", "null"]},
            "not_after": {"type": ["string", "null"]},
            "max_attestation_age_seconds": {"type": "integer", "minimum": 1},
            "allowed_clock_skew_seconds": {"type": "integer", "minimum": 0},
        },
    }
    registry = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/runtime/runtime-trust-registry.schema.json",
        "title": "AgentSec Runtime Trust Registry",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "issuers",
            "report_only",
            "policy_authority",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": RUNTIME_TRUST_REGISTRY_FORMAT},
            "format_version": {"const": RUNTIME_TRUST_REGISTRY_FORMAT_VERSION},
            "issuers": {
                "type": "array",
                "minItems": 1,
                "maxItems": _MAX_ISSUERS,
                "items": issuer,
            },
            "report_only": {"const": True},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
            "authority": authority,
        },
    }
    verification = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/runtime/runtime-trust-verification.schema.json",
        "title": "AgentSec Runtime Trust Verification",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "verification_id",
            "source_attestation_sha256",
            "trust_registry_sha256",
            "issuer",
            "key_id",
            "signature_algorithm",
            "status",
            "trusted",
            "issuer_trusted",
            "key_trusted",
            "signature_verified",
            "time_valid",
            "replay_detected",
            "evaluated_at",
            "reason_codes",
            "key_fingerprint_sha256",
            "report_only",
            "policy_authority",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": RUNTIME_TRUST_VERIFICATION_FORMAT},
            "format_version": {"const": RUNTIME_TRUST_VERIFICATION_FORMAT_VERSION},
            "verification_id": {
                "type": "string",
                "pattern": "^runtime-trust-verification-sha256:[0-9a-f]{64}$",
            },
            "source_attestation_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "trust_registry_sha256": {
                "type": ["string", "null"],
                "pattern": "^[0-9a-f]{64}$",
            },
            "issuer": {"type": "string"},
            "key_id": {"type": "string"},
            "signature_algorithm": {
                "enum": [item.value for item in RuntimeSignatureAlgorithm]
            },
            "status": {"enum": [item.value for item in RuntimeTrustStatus]},
            "trusted": {"type": "boolean"},
            "issuer_trusted": {"type": "boolean"},
            "key_trusted": {"type": "boolean"},
            "signature_verified": {"type": "boolean"},
            "time_valid": {"type": "boolean"},
            "replay_detected": {"type": "boolean"},
            "evaluated_at": {"type": "string"},
            "reason_codes": {
                "type": "array",
                "minItems": 1,
                "maxItems": 16,
                "items": {"type": "string"},
            },
            "key_fingerprint_sha256": {
                "type": ["string", "null"],
                "pattern": "^[0-9a-f]{64}$",
            },
            "report_only": {"const": True},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
            "authority": authority,
        },
    }
    replay_entry = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "issuer",
            "key_id",
            "nonce_sha256",
            "attestation_sha256",
            "accepted_at",
            "expires_at",
        ],
        "properties": {
            "issuer": {"type": "string"},
            "key_id": {"type": "string"},
            "nonce_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "attestation_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "accepted_at": {"type": "string"},
            "expires_at": {"type": "string"},
        },
    }
    replay = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentsec.local/schemas/runtime/runtime-replay-store.schema.json",
        "title": "AgentSec Runtime Replay Store",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "format",
            "format_version",
            "entries",
            "report_only",
            "policy_authority",
            "ci_blocked",
            "authority",
        ],
        "properties": {
            "format": {"const": RUNTIME_REPLAY_STORE_FORMAT},
            "format_version": {"const": RUNTIME_REPLAY_STORE_FORMAT_VERSION},
            "entries": {
                "type": "array",
                "maxItems": _MAX_REPLAY_ENTRIES,
                "items": replay_entry,
            },
            "report_only": {"const": True},
            "policy_authority": {"const": False},
            "ci_blocked": {"const": False},
            "authority": authority,
        },
    }
    for path, payload in (
        (registry_path, registry),
        (verification_path, verification),
        (replay_path, replay),
    ):
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return registry_path, verification_path, replay_path


def _decision(
    base: dict[str, object],
    *,
    status: RuntimeTrustStatus,
    issuer_trusted: bool,
    key_trusted: bool,
    signature_verified: bool,
    time_valid: bool,
    replay_detected: bool,
    reason_codes: tuple[str, ...],
    key_fingerprint_sha256: str | None = None,
) -> RuntimeTrustDecision:
    values = {
        **base,
        "status": status,
        "issuer_trusted": issuer_trusted,
        "key_trusted": key_trusted,
        "signature_verified": signature_verified,
        "time_valid": time_valid,
        "replay_detected": replay_detected,
        "reason_codes": reason_codes,
        "key_fingerprint_sha256": key_fingerprint_sha256,
    }
    values["verification_id"] = runtime_trust_verification_id(
        **values,
        trusted=status is RuntimeTrustStatus.TRUSTED,
    )
    return RuntimeTrustDecision(**values)  # type: ignore[arg-type]


def _time_valid(
    attestation: RuntimeAttestation,
    issuer: TrustedRuntimeIssuer,
    now: datetime,
) -> tuple[bool, RuntimeTrustStatus]:
    skew = timedelta(seconds=issuer.allowed_clock_skew_seconds)
    issued = _parse_utc(attestation.issued_at)
    expires = _parse_utc(attestation.expires_at)
    if issued > now + skew:
        return False, RuntimeTrustStatus.NOT_YET_VALID
    if expires <= now:
        return False, RuntimeTrustStatus.EXPIRED
    if now - issued > timedelta(seconds=issuer.max_attestation_age_seconds) + skew:
        return False, RuntimeTrustStatus.EXPIRED
    if issuer.not_before and issued < _parse_utc(issuer.not_before) - skew:
        return False, RuntimeTrustStatus.NOT_YET_VALID
    if issuer.not_after and expires > _parse_utc(issuer.not_after) + skew:
        return False, RuntimeTrustStatus.EXPIRED
    return True, RuntimeTrustStatus.TRUSTED


def _attestation_digest(attestation: RuntimeAttestation) -> str:
    return hashlib.sha256(_canonical_bytes(attestation.to_dict())).hexdigest()


def _attestation_signing_bytes(attestation: RuntimeAttestation) -> bytes:
    return _canonical_bytes(attestation.signing_dict())


def _registry_digest(registry: RuntimeTrustRegistry | None) -> str | None:
    return canonical_runtime_trust_registry_sha256(registry) if registry else None


def _encode(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _decode(payload: str, label: str) -> dict[str, object]:
    if not isinstance(payload, str):
        raise TypeError(f"{label} decoder requires text")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeAttestationError(f"{label} JSON is invalid") from error
    if not isinstance(value, dict):
        raise RuntimeAttestationError(f"{label} JSON must be an object")
    return value


def _require_authority(value: dict[str, object], label: str) -> None:
    authority = value.get("authority")
    if (
        value.get("report_only") is not True
        or value.get("policy_authority") is not False
        or value.get("ci_blocked") is not False
        or not isinstance(authority, dict)
        or authority.get("report_only") is not True
        or authority.get("policy_authority") is not False
        or authority.get("ci_blocked") is not False
    ):
        raise RuntimeAttestationError(f"{label} authority is invalid")


def _require_exact_keys(
    value: dict[str, object],
    expected: set[str],
    label: str,
) -> None:
    if set(value) != expected:
        raise RuntimeAttestationError(f"{label} fields are invalid")


def _string(value: dict[str, object], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str):
        raise RuntimeAttestationError(f"runtime trust field {name} is invalid")
    return item


def _optional_string(value: dict[str, object], name: str) -> str | None:
    item = value.get(name)
    if item is not None and not isinstance(item, str):
        raise RuntimeAttestationError(f"runtime trust field {name} is invalid")
    return item


def _string_tuple(value: dict[str, object], name: str) -> tuple[str, ...]:
    item = value.get(name)
    if not isinstance(item, list) or any(not isinstance(entry, str) for entry in item):
        raise RuntimeAttestationError(f"runtime trust field {name} is invalid")
    return tuple(item)


def _bool(value: dict[str, object], name: str) -> bool:
    item = value.get(name)
    if not isinstance(item, bool):
        raise RuntimeAttestationError(f"runtime trust field {name} is invalid")
    return item


def _int(value: dict[str, object], name: str) -> int:
    item = value.get(name)
    if not isinstance(item, int) or isinstance(item, bool):
        raise RuntimeAttestationError(f"runtime trust field {name} is invalid")
    return item


def _require_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise RuntimeAttestationError(f"{label} is invalid")
    if any(char.isspace() or ord(char) < 0x20 for char in value):
        raise RuntimeAttestationError(f"{label} is invalid")


def _timestamp(value: str, label: str) -> datetime:
    try:
        return _parse_utc(value)
    except RuntimeAttestationError as error:
        raise RuntimeAttestationError(f"runtime trust {label} is invalid") from error


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _HEX64(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


__all__ = [
    "DeterministicRuntimeTrustVerifier",
    "EnvironmentRuntimeKeyResolver",
    "RuntimeIssuerStatus",
    "RuntimeReplayEntry",
    "RuntimeReplayStore",
    "RuntimeReplayStoreError",
    "RuntimeTrustRegistry",
    "RuntimeTrustVerificationReport",
    "TrustedRuntimeIssuer",
    "build_runtime_trust_registry",
    "canonical_runtime_trust_registry_sha256",
    "canonical_runtime_trust_verification_sha256",
    "decode_runtime_trust_registry_json",
    "decode_runtime_trust_verification_json",
    "encode_runtime_trust_registry_json",
    "encode_runtime_trust_verification_json",
    "export_runtime_trust_json_schemas",
]
