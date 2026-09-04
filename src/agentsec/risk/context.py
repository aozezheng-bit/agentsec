"""RISK-01 strict Operation Context contracts.

The contract describes what an Agent operation claims to do and the context in
which it may occur.  It is evidence input only: it does not score a risk,
grant runtime authority, or prove that the operation is reachable.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.domain import EvidenceConfidence
from agentsec.domain.base import Sha256Digest, validate_relative_path
from agentsec.versioning import OPERATION_CONTEXT_SCHEMA_VERSION

OPERATION_CONTEXT_FORMAT = "agentsec-operation-context"
OPERATION_CONTEXT_SET_FORMAT = "agentsec-operation-context-set"
OPERATION_CONTEXT_BASIS = (
    "AgentSec RISK-01 deterministic Operation Context Contract 0.1.0",
    "Operation Context describes evidence and grants no runtime authority",
)

_STABLE_ID_PATTERN = r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$"
_EVIDENCE_ID_PATTERN = r"^operation-evidence-sha256:[0-9a-f]{64}$"

StableOperationIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=_STABLE_ID_PATTERN),
]
EvidenceIdentifier = Annotated[str, Field(pattern=_EVIDENCE_ID_PATTERN)]


class _Strict(BaseModel):
    """Strict immutable base for Operation Context values."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class OperationAction(StrEnum):
    """Atomic action represented by an Operation Context."""

    READ = "read"
    WRITE = "write"
    SEND = "send"
    EXECUTE = "execute"
    DELETE = "delete"
    SCHEDULE = "schedule"
    STORE = "store"
    MODIFY_POLICY = "modify_policy"
    MODIFY_IDENTITY = "modify_identity"
    UNKNOWN = "unknown"


class OperationTarget(StrEnum):
    """Bounded target classes for an Agent operation."""

    PUBLIC_WEB = "public_web"
    EXTERNAL_SERVICE = "external_service"
    EXTERNAL_MESSAGE_CHANNEL = "external_message_channel"
    LOCAL_FILE = "local_file"
    AGENT_CONTROL_FILE = "agent_control_file"
    WORKSPACE = "workspace"
    USER_PROFILE = "user_profile"
    USER_MAILBOX = "user_mailbox"
    CREDENTIAL = "credential"
    SECRET = "secret"
    PRODUCTION_SYSTEM = "production_system"
    TOOL_REGISTRY = "tool_registry"
    MCP_SERVER = "mcp_server"
    UNKNOWN = "unknown"


class DataClassification(StrEnum):
    """Sensitivity class of data touched by an operation."""

    PUBLIC = "public"
    INTERNAL = "internal"
    USER_PREFERENCE = "user_preference"
    PERSONAL = "personal"
    SENSITIVE = "sensitive"
    CREDENTIAL = "credential"
    SECRET = "secret"
    UNKNOWN = "unknown"


class DataSharingScope(StrEnum):
    """Destination scope for persisted or transferred data."""

    NONE = "none"
    MAIN_SESSION = "main_session"
    WORKSPACE = "workspace"
    ORGANIZATION = "organization"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class DataRetention(StrEnum):
    """Retention class for data handled by an operation."""

    EPHEMERAL = "ephemeral"
    SESSION = "session"
    BOUNDED = "bounded"
    INDEFINITE = "indefinite"
    UNKNOWN = "unknown"


class OperationTrigger(StrEnum):
    """Trigger or autonomy class for an operation."""

    USER_REQUESTED = "user_requested"
    USER_CONFIRMED = "user_confirmed"
    POLICY_TRIGGERED = "policy_triggered"
    SCHEDULED = "scheduled"
    PROACTIVE = "proactive"
    AUTONOMOUS = "autonomous"
    UNKNOWN = "unknown"


class OperationPurpose(StrEnum):
    """Declared purpose of an operation."""

    SEARCH = "search"
    ANALYSIS = "analysis"
    NOTIFICATION = "notification"
    MAINTENANCE = "maintenance"
    PERSISTENCE = "persistence"
    ADMINISTRATION = "administration"
    DEPLOYMENT = "deployment"
    EXTERNAL_COMMUNICATION = "external_communication"
    CONTROL_FILE_UPDATE = "control_file_update"
    UNKNOWN = "unknown"


class AuthorizationState(StrEnum):
    """Authorization and approval state without granting authority."""

    USER_CONFIRMED = "user_confirmed"
    POLICY_ALLOWED = "policy_allowed"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_MISSING = "approval_missing"
    NOT_REQUIRED = "not_required"
    UNKNOWN = "unknown"


class OperationReversibility(StrEnum):
    """Whether an operation's effects can be reversed."""

    REVERSIBLE = "reversible"
    PARTIALLY_REVERSIBLE = "partially_reversible"
    IRREVERSIBLE = "irreversible"
    UNKNOWN = "unknown"


class OperationScope(StrEnum):
    """Blast-radius scope of an operation."""

    SINGLE_ITEM = "single_item"
    SINGLE_FILE = "single_file"
    WORKSPACE = "workspace"
    USER_SCOPE = "user_scope"
    ORGANIZATION = "organization"
    EXTERNAL = "external"
    GLOBAL = "global"
    UNKNOWN = "unknown"


class Frequency(StrEnum):
    """Expected operation frequency."""

    ONE_TIME = "one_time"
    PERIODIC = "periodic"
    CONTINUOUS = "continuous"
    UNKNOWN = "unknown"


class ControlState(StrEnum):
    """Presence state of a named control."""

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class OperationContextStatus(StrEnum):
    """Completeness of the extracted Operation Context."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    NEEDS_CONTEXT = "needs_context"
    UNKNOWN = "unknown"


class OperationEvidenceMethod(StrEnum):
    """Trusted extraction source for static Operation Context evidence."""

    STATIC_DECLARATION = "static_declaration"
    STATIC_TEMPLATE_CLASSIFICATION = "static_template_classification"
    STATIC_DIFF = "static_diff"
    STRUCTURAL_FILE_STATE = "structural_file_state"
    MANIFEST = "manifest"
    POLICY_BOUNDARY = "policy_boundary"


class DataScope(_Strict):
    """Data sensitivity, sharing, and retention context."""

    classification: DataClassification
    sharing: DataSharingScope = DataSharingScope.UNKNOWN
    retention: DataRetention = DataRetention.UNKNOWN


class AuthorizationContext(_Strict):
    """Authorization facts, separate from runtime permission."""

    state: AuthorizationState = AuthorizationState.UNKNOWN
    approval_required: bool | None = None
    approval_present: bool | None = None

    @model_validator(mode="after")
    def values_must_be_coherent(self) -> AuthorizationContext:
        if self.approval_required is False and self.approval_present is True:
            raise ValueError(
                "approval_present cannot be true when approval_required is false"
            )
        if self.state is AuthorizationState.APPROVAL_MISSING and (
            self.approval_required is not True or self.approval_present is not False
        ):
            raise ValueError(
                "APPROVAL_MISSING requires approval_required=true and "
                "approval_present=false"
            )
        if self.state is AuthorizationState.APPROVAL_REQUIRED and (
            self.approval_required is not True
        ):
            raise ValueError("APPROVAL_REQUIRED requires approval_required=true")
        return self


class ControlEffectiveness(_Strict):
    """Explicit control observations; no field grants runtime authority."""

    approval: ControlState = ControlState.UNKNOWN
    user_consent: ControlState = ControlState.UNKNOWN
    allowlist: ControlState = ControlState.UNKNOWN
    audit: ControlState = ControlState.UNKNOWN
    retention: ControlState = ControlState.UNKNOWN
    redaction: ControlState = ControlState.UNKNOWN
    rate_limit: ControlState = ControlState.UNKNOWN


class OperationEvidence(_Strict):
    """Value-minimized source evidence for one operation context."""

    evidence_id: EvidenceIdentifier
    source_path: Annotated[str, Field(min_length=1, max_length=512)]
    field_path: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    start_line: Annotated[int, Field(ge=1)] | None = None
    end_line: Annotated[int, Field(ge=1)] | None = None
    content_sha256: Sha256Digest
    extraction_method: OperationEvidenceMethod
    confidence: EvidenceConfidence
    value_minimized: Literal[True] = True
    secret_values_included: Literal[False] = False

    @field_validator("source_path")
    @classmethod
    def source_path_must_be_relative(cls, value: str) -> str:
        return validate_relative_path(value)

    @field_validator("field_path")
    @classmethod
    def field_path_must_be_exact(cls, value: str | None) -> str | None:
        if value is not None and value != value.strip():
            raise ValueError("field_path must not contain outer whitespace")
        return value

    @model_validator(mode="after")
    def evidence_must_be_coherent(self) -> OperationEvidence:
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("Evidence line range must include start_line and end_line")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("Evidence line range is invalid")
        if self.evidence_id != operation_evidence_id(
            source_path=self.source_path,
            field_path=self.field_path,
            start_line=self.start_line,
            end_line=self.end_line,
            content_sha256=self.content_sha256,
            extraction_method=self.extraction_method,
        ):
            raise ValueError("Evidence ID is inconsistent with source metadata")
        return self

    def sort_key(self) -> tuple[str, str, int, int, str]:
        return (
            self.source_path,
            self.field_path or "",
            self.start_line or 0,
            self.end_line or 0,
            self.evidence_id,
        )


def operation_evidence_id(
    *,
    source_path: str,
    field_path: str | None,
    start_line: int | None,
    end_line: int | None,
    content_sha256: str,
    extraction_method: OperationEvidenceMethod,
) -> str:
    """Return a deterministic Evidence ID without including raw source text."""

    payload = {
        "source_path": validate_relative_path(source_path),
        "field_path": field_path,
        "start_line": start_line,
        "end_line": end_line,
        "content_sha256": content_sha256,
        "extraction_method": extraction_method.value,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"operation-evidence-sha256:{hashlib.sha256(encoded).hexdigest()}"


def build_operation_evidence(
    *,
    source_path: str,
    content_sha256: str,
    extraction_method: OperationEvidenceMethod,
    confidence: EvidenceConfidence,
    field_path: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
) -> OperationEvidence:
    """Construct source-bound Operation Evidence from safe metadata only."""

    evidence_id = operation_evidence_id(
        source_path=source_path,
        field_path=field_path,
        start_line=start_line,
        end_line=end_line,
        content_sha256=content_sha256,
        extraction_method=extraction_method,
    )
    return OperationEvidence(
        evidence_id=evidence_id,
        source_path=source_path,
        field_path=field_path,
        start_line=start_line,
        end_line=end_line,
        content_sha256=content_sha256,
        extraction_method=extraction_method,
        confidence=confidence,
    )


class OperationContext(_Strict):
    """One structured operation claim with bounded static evidence."""

    format: Literal["agentsec-operation-context"] = "agentsec-operation-context"
    schema_version: Literal["0.1.0"] = "0.1.0"
    operation_id: StableOperationIdentifier
    action: OperationAction
    target: OperationTarget
    data_scope: DataScope
    trigger: OperationTrigger
    purpose: OperationPurpose
    authorization: AuthorizationContext
    reversibility: OperationReversibility = OperationReversibility.UNKNOWN
    scope: OperationScope = OperationScope.UNKNOWN
    frequency: Frequency = Frequency.UNKNOWN
    controls: ControlEffectiveness = ControlEffectiveness()
    evidence: tuple[OperationEvidence, ...] = Field(min_length=1, max_length=32)
    status: OperationContextStatus
    runtime_verified: Literal[False] = False
    runtime_authority: Literal[False] = False

    @field_validator("operation_id")
    @classmethod
    def operation_id_must_be_exact(cls, value: str) -> str:
        if re.fullmatch(_STABLE_ID_PATTERN, value) is None:
            raise ValueError("operation_id must use stable form")
        return value

    @model_validator(mode="after")
    def context_must_be_coherent(self) -> OperationContext:
        evidence_keys = tuple(item.sort_key() for item in self.evidence)
        if evidence_keys != tuple(sorted(set(evidence_keys))):
            raise ValueError("Operation Context evidence must be sorted and unique")
        unknown_dimensions = self._primary_unknown_dimensions()
        if self.status is OperationContextStatus.COMPLETE and unknown_dimensions:
            raise ValueError(
                "complete context cannot contain unknown primary dimensions: "
                + ", ".join(unknown_dimensions)
            )
        if (
            self.status
            in {
                OperationContextStatus.NEEDS_CONTEXT,
                OperationContextStatus.UNKNOWN,
            }
            and not unknown_dimensions
        ):
            raise ValueError(
                "needs_context status requires at least one unknown primary dimension"
            )
        if self.runtime_verified is not False or self.runtime_authority is not False:
            raise ValueError("Operation Context cannot grant runtime authority")
        return self

    def _primary_unknown_dimensions(self) -> tuple[str, ...]:
        values = (
            ("action", self.action is OperationAction.UNKNOWN),
            ("target", self.target is OperationTarget.UNKNOWN),
            (
                "data_scope.classification",
                self.data_scope.classification is DataClassification.UNKNOWN,
            ),
            ("trigger", self.trigger is OperationTrigger.UNKNOWN),
            ("purpose", self.purpose is OperationPurpose.UNKNOWN),
            (
                "authorization.state",
                self.authorization.state is AuthorizationState.UNKNOWN,
            ),
        )
        return tuple(name for name, unknown in values if unknown)


class OperationContextSet(_Strict):
    """Bounded batch envelope for extracted operation contexts."""

    format: Literal["agentsec-operation-context-set"] = "agentsec-operation-context-set"
    schema_version: Literal["0.1.0"] = "0.1.0"
    subject_id: StableOperationIdentifier | None = None
    contexts: tuple[OperationContext, ...] = Field(min_length=1, max_length=128)
    coverage_complete: bool
    unknown_dimensions: tuple[StableOperationIdentifier, ...] = ()
    basis: tuple[str, ...] = OPERATION_CONTEXT_BASIS
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    runtime_authority: Literal[False] = False

    @field_validator("unknown_dimensions")
    @classmethod
    def unknown_dimensions_must_be_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("unknown_dimensions must be sorted and unique")
        return values

    @field_validator("basis")
    @classmethod
    def basis_must_be_sorted_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or values != tuple(dict.fromkeys(values)):
            raise ValueError("Operation Context basis must be non-empty and unique")
        return values

    @model_validator(mode="after")
    def contexts_must_be_sorted_and_authority_safe(self) -> OperationContextSet:
        operation_ids = tuple(item.operation_id for item in self.contexts)
        if operation_ids != tuple(sorted(set(operation_ids))):
            raise ValueError("Operation Contexts must be sorted and unique")
        if self.runtime_verified is not False or self.runtime_authority is not False:
            raise ValueError("Operation Context Set cannot grant runtime authority")
        return self


def canonical_operation_context_sha256(
    context: OperationContext | OperationContextSet,
) -> str:
    """Hash canonical JSON for deterministic later Snapshot/Diff binding."""

    if not isinstance(context, (OperationContext, OperationContextSet)):
        raise TypeError("context must be OperationContext or OperationContextSet")
    payload = context.model_dump(mode="json")
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def encode_operation_context_json(
    context: OperationContext | OperationContextSet,
) -> str:
    """Encode an Operation Context as deterministic JSON."""

    if not isinstance(context, (OperationContext, OperationContextSet)):
        raise TypeError("context must be OperationContext or OperationContextSet")
    return (
        json.dumps(
            context.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def export_operation_context_json_schema(output_directory: Path) -> Path:
    """Export the RISK-01 Operation Context Set JSON Schema."""

    if not isinstance(output_directory, Path):
        raise TypeError("Operation Context schema output directory must be a Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "operation-context.schema.json"
    schema = OperationContextSet.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["x-agentsec-operation-context-schema-version"] = (
        OPERATION_CONTEXT_SCHEMA_VERSION
    )
    output_path.write_text(
        json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


__all__ = [
    "AuthorizationContext",
    "AuthorizationState",
    "ControlEffectiveness",
    "ControlState",
    "DataClassification",
    "DataRetention",
    "DataScope",
    "DataSharingScope",
    "Frequency",
    "OPERATION_CONTEXT_BASIS",
    "OPERATION_CONTEXT_FORMAT",
    "OPERATION_CONTEXT_SCHEMA_VERSION",
    "OPERATION_CONTEXT_SET_FORMAT",
    "OperationAction",
    "OperationContext",
    "OperationContextSet",
    "OperationContextStatus",
    "OperationEvidence",
    "OperationEvidenceMethod",
    "OperationPurpose",
    "OperationReversibility",
    "OperationScope",
    "OperationTarget",
    "OperationTrigger",
    "build_operation_evidence",
    "canonical_operation_context_sha256",
    "encode_operation_context_json",
    "export_operation_context_json_schema",
    "operation_evidence_id",
]
