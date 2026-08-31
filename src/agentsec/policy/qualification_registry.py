"""Trusted Qualified Gate Registry for Capability CI enforcement (P2-EXIT-01).

Gate qualification authority is never discovered from scanned project
content. It is loaded from an explicitly pinned registry artifact whose
SHA-256 digest is fixed by the reviewed Capability CI Policy, and every
qualification report is verified through its full evidence-binding chain
before it may contribute Gate authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from yaml.tokens import AliasToken, AnchorToken, TagToken

from agentsec.versioning import QUALIFICATION_REGISTRY_SCHEMA_VERSION

QUALIFIED_GATE_REGISTRY_FORMAT = "agentsec-qualified-gate-registry"
QUALIFIED_GATE_REGISTRY_SCHEMA_VERSION = QUALIFICATION_REGISTRY_SCHEMA_VERSION
QUALIFIED_GATE_REGISTRY_MAX_SIZE_BYTES = 2_097_152
QUALIFICATION_REPORT_FORMAT = "agentsec-gate-scoped-qualification-report"
QUALIFICATION_REPORT_SCHEMA_VERSION = "0.1.0"
QUALIFICATION_REPORT_MAX_SIZE_BYTES = 8 * 1024 * 1024
QUALIFICATION_ARTIFACT_PREFIX = "qualification-report-sha256:"
HUMAN_EVIDENCE_ARTIFACT_PREFIX = "human-evidence-sha256:"
GATE_RULE_BINDING = {"HG-CAPCHAIN-001": "CAP-CHAIN-001"}
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REPORT_PATH_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HUMAN_ARTIFACT_PATTERN = re.compile(
    rf"^{re.escape(HUMAN_EVIDENCE_ARTIFACT_PREFIX)}[0-9a-f]{{64}}$"
)


class PolicyError(ValueError):
    """Safe policy configuration, registry, or qualification error."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class QualifiedGateEntry(_Strict):
    """One approved Gate qualification binding pinned by digest and artifact ID."""

    gate_id: Literal["HG-CAPCHAIN-001"]
    qualification_report_path: Annotated[
        str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    ]
    qualification_artifact_id: Annotated[
        str,
        Field(pattern=rf"^{re.escape(QUALIFICATION_ARTIFACT_PREFIX)}[0-9a-f]{{64}}$"),
    ]
    qualification_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    evidence_mode: Literal["human"]
    qualification_status: Literal["accepted"]
    allowed_floor: Literal["high"]


class QualifiedGateRegistry(_Strict):
    """Strict approved-Gate registry referenced by a Capability CI Policy."""

    format: Literal["agentsec-qualified-gate-registry"]
    schema_version: Literal["0.1.0"]
    registry_id: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    ]
    registry_version: Annotated[str, Field(min_length=1, max_length=32)]
    gates: tuple[QualifiedGateEntry, ...]

    @model_validator(mode="after")
    def gates_must_be_unique_and_bounded(self) -> QualifiedGateRegistry:
        gate_ids = tuple(entry.gate_id for entry in self.gates)
        if not gate_ids:
            raise ValueError("qualification registry requires at least one Gate")
        if len(gate_ids) != len(set(gate_ids)):
            raise ValueError("qualification registry Gate IDs must be unique")
        if gate_ids != tuple(sorted(gate_ids)):
            raise ValueError("qualification registry Gates must be sorted by Gate ID")
        if set(gate_ids) - set(GATE_RULE_BINDING):
            raise ValueError("qualification registry references an unsupported Gate")
        return self

    def entry_for(self, gate_id: str) -> QualifiedGateEntry | None:
        for entry in self.gates:
            if entry.gate_id == gate_id:
                return entry
        return None


@dataclass(frozen=True, slots=True)
class LoadedQualifiedGateRegistry:
    """A validated registry plus safe provenance for report binding."""

    registry: QualifiedGateRegistry
    path: Path
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class QualifiedGateEvidence:
    """Verified qualification evidence for one Gate."""

    gate_id: str
    rule_id: str
    allowed_floor: str
    evidence_mode: str
    qualification_artifact_id: str
    human_evidence_artifact_id: str
    qualification_report_sha256: str


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise PolicyError("qualification registry has duplicate keys")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _read_bounded(path: Path, label: str, limit: int) -> bytes:
    if path.is_symlink():
        raise PolicyError(f"{label} must not be a symlink")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PolicyError(f"{label} must be a regular file")
        if metadata.st_size > limit:
            raise PolicyError(f"{label} exceeds the bounded size limit")
        remaining = limit + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise PolicyError(f"{label} exceeds the bounded size limit")
        return raw
    except FileNotFoundError as error:
        raise PolicyError(f"{label} does not exist") from error
    except PolicyError:
        raise
    except OSError as error:
        raise PolicyError(f"{label} could not be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_qualification_registry(path: Path) -> LoadedQualifiedGateRegistry:
    """Load one bounded registry YAML without aliases, tags, or duplicate keys."""

    if not isinstance(path, Path):
        raise TypeError("qualification registry path must be a Path")
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise PolicyError("qualification registry must use .yaml or .yml")
    raw = _read_bounded(
        path, "qualification registry", QUALIFIED_GATE_REGISTRY_MAX_SIZE_BYTES
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError("qualification registry must be UTF-8") from error
    if not text.strip():
        raise PolicyError("qualification registry is empty")
    try:
        for token in yaml.scan(text, Loader=yaml.SafeLoader):
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise PolicyError(
                    "qualification registry aliases, anchors, and tags are forbidden"
                )
        documents = list(yaml.load_all(text, Loader=_UniqueSafeLoader))
    except PolicyError:
        raise
    except (yaml.YAMLError, TypeError, ValueError) as error:
        raise PolicyError("qualification registry is invalid YAML") from error
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise PolicyError("qualification registry must be one YAML mapping")
    try:
        registry = QualifiedGateRegistry.model_validate(documents[0])
    except Exception as error:
        raise PolicyError(
            "qualification registry failed schema or semantic validation"
        ) from error
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise PolicyError(
            "qualification registry path could not be resolved"
        ) from error
    return LoadedQualifiedGateRegistry(
        registry=registry,
        path=resolved,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
    )


def _canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _recomputed_artifact_id(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned["artifact_id"] = None
    return (
        QUALIFICATION_ARTIFACT_PREFIX
        + hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("qualification report has duplicate keys")
        result[key] = value
    return result


def verify_gate_qualification(
    entry: QualifiedGateEntry, *, registry_dir: Path
) -> QualifiedGateEvidence:
    """Verify one pinned qualification report through its full binding chain."""

    if not isinstance(entry, QualifiedGateEntry):
        raise TypeError("entry must be QualifiedGateEntry")
    if not isinstance(registry_dir, Path):
        raise TypeError("registry_dir must be a Path")
    report_name = entry.qualification_report_path
    if not _REPORT_PATH_PATTERN.fullmatch(report_name):
        raise PolicyError("qualification report path is unsafe")
    report_path = registry_dir / report_name
    raw = _read_bounded(
        report_path, "qualification report", QUALIFICATION_REPORT_MAX_SIZE_BYTES
    )
    observed_sha256 = hashlib.sha256(raw).hexdigest()
    if observed_sha256 != entry.qualification_sha256:
        raise PolicyError("qualification report digest does not match the registry pin")
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as error:
        raise PolicyError("qualification report is invalid JSON") from error
    if not isinstance(payload, dict):
        raise PolicyError("qualification report must be a JSON object")

    if payload.get("format") != QUALIFICATION_REPORT_FORMAT:
        raise PolicyError("qualification report format is invalid")
    if payload.get("schema_version") != QUALIFICATION_REPORT_SCHEMA_VERSION:
        raise PolicyError("qualification report schema version is invalid")
    if payload.get("status") != "complete":
        raise PolicyError("qualification report is incomplete")
    if payload.get("gate_id") != entry.gate_id:
        raise PolicyError("qualification report Gate binding is invalid")
    if payload.get("rule_id") != GATE_RULE_BINDING[entry.gate_id]:
        raise PolicyError("qualification report Rule binding is invalid")
    if payload.get("evidence_mode") != entry.evidence_mode:
        raise PolicyError("qualification report evidence mode is invalid")

    qualification = payload.get("qualification")
    if not isinstance(qualification, dict):
        raise PolicyError("qualification report qualification block is invalid")
    if qualification.get("status") != entry.qualification_status:
        raise PolicyError("qualification status does not match the registry pin")
    if qualification.get("eligible_for_report_only_gate") is not True:
        raise PolicyError("qualification report is not eligible for the Gate")
    blocking_reasons = qualification.get("blocking_reasons")
    if blocking_reasons != []:
        raise PolicyError("qualification report records blocking reasons")
    checks = qualification.get("checks")
    if not isinstance(checks, dict) or not checks:
        raise PolicyError("qualification report checks are invalid")
    for check in checks.values():
        if not isinstance(check, dict) or check.get("status") != "pass":
            raise PolicyError("qualification report has a failing check")

    policy_flags = payload.get("policy")
    if not isinstance(policy_flags, dict):
        raise PolicyError("qualification report policy block is invalid")
    if policy_flags.get("llm_used") is not False:
        raise PolicyError("qualification evidence must not depend on LLM output")
    if policy_flags.get("runtime_capability_verified") is not False:
        raise PolicyError("qualification evidence must not claim runtime proof")

    human_artifact_id = payload.get("human_evidence_artifact_id")
    if not isinstance(human_artifact_id, str) or not _HUMAN_ARTIFACT_PATTERN.fullmatch(
        human_artifact_id
    ):
        raise PolicyError("qualification human evidence binding is invalid")

    artifact_id = payload.get("artifact_id")
    recomputed = _recomputed_artifact_id(payload)
    if artifact_id != recomputed:
        raise PolicyError("qualification report artifact ID is invalid")
    if recomputed != entry.qualification_artifact_id:
        raise PolicyError(
            "qualification report artifact ID does not match the registry pin"
        )

    return QualifiedGateEvidence(
        gate_id=entry.gate_id,
        rule_id=GATE_RULE_BINDING[entry.gate_id],
        allowed_floor=entry.allowed_floor,
        evidence_mode=entry.evidence_mode,
        qualification_artifact_id=entry.qualification_artifact_id,
        human_evidence_artifact_id=human_artifact_id,
        qualification_report_sha256=observed_sha256,
    )


def export_qualified_gate_registry_json_schema(output_directory: Path) -> Path:
    """Write the frozen Qualified Gate Registry JSON Schema."""

    output_directory.mkdir(parents=True, exist_ok=True)
    path = output_directory / "qualified-gate-registry.schema.json"
    path.write_text(
        json.dumps(
            QualifiedGateRegistry.model_json_schema(mode="serialization"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


__all__ = [
    "GATE_RULE_BINDING",
    "HUMAN_EVIDENCE_ARTIFACT_PREFIX",
    "QUALIFICATION_ARTIFACT_PREFIX",
    "QUALIFICATION_REPORT_FORMAT",
    "QUALIFICATION_REPORT_MAX_SIZE_BYTES",
    "QUALIFICATION_REPORT_SCHEMA_VERSION",
    "QUALIFIED_GATE_REGISTRY_FORMAT",
    "QUALIFIED_GATE_REGISTRY_MAX_SIZE_BYTES",
    "QUALIFIED_GATE_REGISTRY_SCHEMA_VERSION",
    "LoadedQualifiedGateRegistry",
    "PolicyError",
    "QualifiedGateEntry",
    "QualifiedGateEvidence",
    "QualifiedGateRegistry",
    "export_qualified_gate_registry_json_schema",
    "load_qualification_registry",
    "verify_gate_qualification",
]
