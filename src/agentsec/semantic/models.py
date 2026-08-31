"""Strict P3-01 semantic-analysis data contracts with no model authority."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.domain.base import Sha256Digest, validate_relative_path
from agentsec.domain.enums import FindingCategory
from agentsec.reporting.safety import SecretRedactor, escape_untrusted_text
from agentsec.versioning import parse_interface_version

SEMANTIC_ANALYZER_VERSION = "0.1.0"
SEMANTIC_INPUT_SCHEMA_VERSION = "0.1.0"
SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION = "0.1.0"
SEMANTIC_OUTPUT_SCHEMA_VERSION = "0.1.0"

SEMANTIC_INPUT_FORMAT = "agentsec-semantic-analysis-input"
SEMANTIC_MODEL_OUTPUT_FORMAT = "agentsec-semantic-model-output"
SEMANTIC_OUTPUT_FORMAT = "agentsec-semantic-analysis-result"

SEMANTIC_MAX_EVIDENCE_CHUNKS = 64
SEMANTIC_MAX_EVIDENCE_TEXT_CHARACTERS = 2_048
SEMANTIC_MAX_TOTAL_EVIDENCE_CHARACTERS = 65_536
SEMANTIC_MAX_CANDIDATES = 128
SEMANTIC_MAX_SUMMARY_CHARACTERS = 512
SEMANTIC_MAX_LIMITATIONS = 32

_STABLE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$"
_ANALYSIS_ID_PATTERN = r"^[a-z][a-z0-9._-]{0,127}$"
_EVIDENCE_ID_PATTERN = r"^semantic-evidence-sha256:[0-9a-f]{64}$"
_CANDIDATE_ID_PATTERN = r"^semantic-candidate-sha256:[0-9a-f]{64}$"
_CANDIDATE_KEY_PATTERN = r"^[a-z][a-z0-9-]{0,63}$"
_URL_PATTERN = re.compile(r"https?://[^\s)>]+", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

StableSemanticIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=160, pattern=_STABLE_ID_PATTERN),
]
AnalysisIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=_ANALYSIS_ID_PATTERN),
]
EvidenceIdentifier = Annotated[str, Field(pattern=_EVIDENCE_ID_PATTERN)]
CandidateIdentifier = Annotated[str, Field(pattern=_CANDIDATE_ID_PATTERN)]
CandidateKey = Annotated[str, Field(pattern=_CANDIDATE_KEY_PATTERN)]
SafeSummary = Annotated[
    str,
    Field(min_length=1, max_length=SEMANTIC_MAX_SUMMARY_CHARACTERS),
]
SafeLimitation = Annotated[str, Field(min_length=1, max_length=512)]


class SemanticContractError(ValueError):
    """Safe semantic-contract validation failure."""


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class SemanticCandidateKind(StrEnum):
    """Bounded semantic judgment families; none is a published Finding."""

    CAPABILITY_DECLARATION = "capability_declaration"
    CONTROL_WEAKENING = "control_weakening"
    SEMANTIC_CONFLICT = "semantic_conflict"
    CROSS_FILE_CHAIN = "cross_file_chain"
    RISKY_INTENT = "risky_intent"
    AMBIGUITY = "ambiguity"


class SemanticCandidateDisposition(StrEnum):
    """Probabilistic support state without enforcement meaning."""

    SUPPORTED = "supported"
    NOT_SUPPORTED = "not_supported"
    UNCERTAIN = "uncertain"


class SemanticAnalysisStatus(StrEnum):
    """Final status derived by trusted post-processing."""

    COMPLETE = "complete"
    PARTIAL = "partial"


class SemanticAuthorityBoundary(_Strict):
    """Immutable literals preventing semantic output from gaining authority."""

    mode: Literal["shadow_only"] = "shadow_only"
    candidate_evidence_only: Literal[True] = True
    allow_decision: Literal[False] = False
    block_decision: Literal[False] = False
    severity_authority: Literal[False] = False
    confidence_authority: Literal[False] = False
    rule_publication: Literal[False] = False
    waiver_approval: Literal[False] = False
    runtime_claim_authority: Literal[False] = False
    model_tool_access: Literal[False] = False
    model_filesystem_write: Literal[False] = False
    model_network_access: Literal[False] = False


class SemanticEvidenceChunk(_Strict):
    """Trusted bounded data-channel evidence; never model-authored location data."""

    evidence_id: EvidenceIdentifier
    asset_path: Annotated[str, Field(min_length=1, max_length=512)]
    asset_sha256: Sha256Digest
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]
    text: Annotated[
        str,
        Field(min_length=1, max_length=SEMANTIC_MAX_EVIDENCE_TEXT_CHARACTERS),
    ]
    text_sha256: Sha256Digest
    sanitization_applied: bool
    content_role: Literal["untrusted_evidence"] = "untrusted_evidence"
    instruction_authority: Literal[False] = False
    secret_values_included: Literal[False] = False
    value_minimized: Literal[True] = True

    @field_validator("asset_path")
    @classmethod
    def path_must_be_safe_relative(cls, value: str) -> str:
        return validate_relative_path(value)

    @field_validator("text")
    @classmethod
    def text_must_be_safe(cls, value: str) -> str:
        return _require_safe_text(value, "semantic evidence text")

    @model_validator(mode="after")
    def binding_must_be_recomputable(self) -> SemanticEvidenceChunk:
        if self.end_line < self.start_line:
            raise ValueError("semantic evidence line range is incoherent")
        expected_text_hash = _sha256_text(self.text)
        if self.text_sha256 != expected_text_hash:
            raise ValueError("semantic evidence text hash is inconsistent")
        if self.evidence_id != _semantic_evidence_id(
            asset_path=self.asset_path,
            asset_sha256=self.asset_sha256,
            start_line=self.start_line,
            end_line=self.end_line,
            text_sha256=self.text_sha256,
        ):
            raise ValueError("semantic evidence ID is inconsistent")
        return self

    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.asset_path, self.start_line, self.end_line, self.evidence_id)


class SemanticDeterministicContext(_Strict):
    """Deterministic state that semantic output may not remove or rewrite."""

    coverage_complete: bool
    manifest_sha256: Sha256Digest | None = None
    assessment_sha256: Sha256Digest | None = None
    finding_ids: tuple[StableSemanticIdentifier, ...] = ()
    capability_ids: tuple[StableSemanticIdentifier, ...] = ()
    unknown_dimensions: tuple[StableSemanticIdentifier, ...] = ()

    @field_validator("finding_ids", "capability_ids", "unknown_dimensions")
    @classmethod
    def identifiers_must_be_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("semantic context identifiers must be sorted and unique")
        return values


class SemanticAnalysisInput(_Strict):
    """Trusted Shadow-only semantic request envelope."""

    format: Literal["agentsec-semantic-analysis-input"] = (
        "agentsec-semantic-analysis-input"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    analyzer_version: Literal["0.1.0"] = "0.1.0"
    analysis_id: AnalysisIdentifier
    authority_boundary: SemanticAuthorityBoundary = SemanticAuthorityBoundary()
    deterministic_context: SemanticDeterministicContext
    evidence: Annotated[
        tuple[SemanticEvidenceChunk, ...],
        Field(min_length=1, max_length=SEMANTIC_MAX_EVIDENCE_CHUNKS),
    ]

    @model_validator(mode="after")
    def evidence_must_be_bounded_sorted_unique(self) -> SemanticAnalysisInput:
        keys = tuple(item.sort_key() for item in self.evidence)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("semantic evidence must be sorted and unique")
        ids = tuple(item.evidence_id for item in self.evidence)
        if len(set(ids)) != len(ids):
            raise ValueError("semantic evidence IDs must be unique")
        if sum(len(item.text) for item in self.evidence) > (
            SEMANTIC_MAX_TOTAL_EVIDENCE_CHARACTERS
        ):
            raise ValueError("semantic evidence exceeds the total text limit")
        return self


class SemanticModelCandidate(_Strict):
    """Untrusted structured model row without risk or authorization fields."""

    candidate_key: CandidateKey
    kind: SemanticCandidateKind
    category: FindingCategory
    disposition: SemanticCandidateDisposition
    summary: SafeSummary
    evidence_ids: Annotated[tuple[EvidenceIdentifier, ...], Field(min_length=1)]
    limitations: Annotated[
        tuple[SafeLimitation, ...], Field(max_length=SEMANTIC_MAX_LIMITATIONS)
    ] = ()
    runtime_verified: Literal[False] = False

    @field_validator("summary")
    @classmethod
    def summary_must_be_safe(cls, value: str) -> str:
        return _require_safe_text(value, "semantic candidate summary")

    @field_validator("limitations")
    @classmethod
    def limitations_must_be_safe_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("semantic candidate limitations must be sorted and unique")
        return tuple(
            _require_safe_text(item, "semantic candidate limitation") for item in values
        )

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_must_be_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("candidate Evidence IDs must be sorted and unique")
        return values

    @model_validator(mode="after")
    def category_must_not_redefine_coverage(self) -> SemanticModelCandidate:
        if self.category is FindingCategory.SCAN_COVERAGE:
            raise ValueError("semantic candidates cannot redefine scan Coverage")
        return self

    def semantic_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "category": self.category.value,
            "disposition": self.disposition.value,
            "summary": self.summary,
            "evidence_ids": list(self.evidence_ids),
            "limitations": list(self.limitations),
            "runtime_verified": self.runtime_verified,
        }


class SemanticModelOutput(_Strict):
    """Untrusted constrained model response parsed before trusted validation."""

    format: Literal["agentsec-semantic-model-output"] = "agentsec-semantic-model-output"
    schema_version: Literal["0.1.0"] = "0.1.0"
    analysis_id: AnalysisIdentifier
    analyzed_evidence_ids: tuple[EvidenceIdentifier, ...]
    candidates: Annotated[
        tuple[SemanticModelCandidate, ...], Field(max_length=SEMANTIC_MAX_CANDIDATES)
    ] = ()
    limitations: Annotated[
        tuple[SafeLimitation, ...], Field(max_length=SEMANTIC_MAX_LIMITATIONS)
    ] = ()

    @field_validator("analyzed_evidence_ids")
    @classmethod
    def analyzed_ids_must_be_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("analyzed Evidence IDs must be sorted and unique")
        return values

    @field_validator("limitations")
    @classmethod
    def limitations_must_be_safe_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("semantic output limitations must be sorted and unique")
        return tuple(
            _require_safe_text(item, "semantic output limitation") for item in values
        )

    @model_validator(mode="after")
    def candidates_must_be_sorted_unique(self) -> SemanticModelOutput:
        keys = tuple(item.candidate_key for item in self.candidates)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("semantic model candidates must be sorted and unique")
        payloads = tuple(
            _canonical_hash(item.semantic_payload()) for item in self.candidates
        )
        if len(set(payloads)) != len(payloads):
            raise ValueError("semantic model output contains duplicate judgments")
        return self


class SemanticInvocationProvenance(_Strict):
    """Trusted invocation metadata; Provider identifiers grant no authority."""

    provider_id: StableSemanticIdentifier
    model_id: StableSemanticIdentifier
    prompt_version: Annotated[str, Field(min_length=1, max_length=32)]
    invocation_sha256: Sha256Digest
    invocation_mode: Literal["offline_fixture", "shadow_provider"]
    model_tools_enabled: Literal[False] = False
    model_filesystem_write: Literal[False] = False
    model_network_access: Literal[False] = False
    raw_request_retained: Literal[False] = False
    raw_response_retained: Literal[False] = False

    @field_validator("prompt_version")
    @classmethod
    def prompt_version_must_be_semver(cls, value: str) -> str:
        parse_interface_version(value)
        return value


class SemanticCandidateEvidence(_Strict):
    """Trusted candidate evidence; not a Finding and never an authorization input."""

    candidate_id: CandidateIdentifier
    model_candidate_key: CandidateKey
    kind: SemanticCandidateKind
    category: FindingCategory
    disposition: SemanticCandidateDisposition
    summary: SafeSummary
    evidence_ids: tuple[EvidenceIdentifier, ...]
    limitations: tuple[SafeLimitation, ...] = ()
    evidence_confidence: Literal["C"] = "C"
    confidence_method: Literal["llm_semantic_analysis"] = "llm_semantic_analysis"
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    authority_effect: Literal["none"] = "none"

    @model_validator(mode="after")
    def candidate_id_must_be_recomputable(self) -> SemanticCandidateEvidence:
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError(
                "semantic candidate Evidence IDs must be sorted and unique"
            )
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("semantic candidate limitations must be sorted and unique")
        return self

    def sort_key(self) -> tuple[str, str]:
        return (self.model_candidate_key, self.candidate_id)


class SemanticCoverage(_Strict):
    """Coverage derived by trusted post-processing, not accepted from the model."""

    input_evidence_count: Annotated[int, Field(ge=1)]
    analyzed_evidence_count: Annotated[int, Field(ge=0)]
    omitted_evidence_ids: tuple[EvidenceIdentifier, ...]
    semantic_complete: bool
    deterministic_coverage_complete: bool
    unknown_dimensions: tuple[StableSemanticIdentifier, ...]
    complete: bool

    @model_validator(mode="after")
    def coverage_must_be_coherent(self) -> SemanticCoverage:
        if self.omitted_evidence_ids != tuple(sorted(set(self.omitted_evidence_ids))):
            raise ValueError("omitted Evidence IDs must be sorted and unique")
        if self.analyzed_evidence_count + len(self.omitted_evidence_ids) != (
            self.input_evidence_count
        ):
            raise ValueError("semantic Coverage counts are inconsistent")
        if self.semantic_complete != (not self.omitted_evidence_ids):
            raise ValueError("semantic complete flag is inconsistent")
        expected_complete = (
            self.semantic_complete and self.deterministic_coverage_complete
        )
        if self.complete != expected_complete:
            raise ValueError("combined semantic Coverage is inconsistent")
        return self


class SemanticAnalysisResult(_Strict):
    """Final Shadow-only result with fixed non-authority semantics."""

    format: Literal["agentsec-semantic-analysis-result"] = (
        "agentsec-semantic-analysis-result"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    analyzer_version: Literal["0.1.0"] = "0.1.0"
    analysis_id: AnalysisIdentifier
    status: SemanticAnalysisStatus
    input_sha256: Sha256Digest
    model_output_sha256: Sha256Digest
    invocation: SemanticInvocationProvenance
    authority_boundary: SemanticAuthorityBoundary = SemanticAuthorityBoundary()
    deterministic_context: SemanticDeterministicContext
    coverage: SemanticCoverage
    candidates: tuple[SemanticCandidateEvidence, ...]
    limitations: Annotated[
        tuple[SafeLimitation, ...],
        Field(min_length=1, max_length=SEMANTIC_MAX_LIMITATIONS),
    ]
    report_only: Literal[True] = True
    runtime_verified: Literal[False] = False
    blocks: Literal[False] = False

    @field_validator("limitations")
    @classmethod
    def limitations_must_be_safe_sorted_unique(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("semantic result limitations must be sorted and unique")
        return tuple(
            _require_safe_text(item, "semantic result limitation") for item in values
        )

    @model_validator(mode="after")
    def result_must_be_coherent(self) -> SemanticAnalysisResult:
        keys = tuple(item.sort_key() for item in self.candidates)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("semantic candidates must be sorted and unique")
        expected_status = (
            SemanticAnalysisStatus.COMPLETE
            if self.coverage.complete
            else SemanticAnalysisStatus.PARTIAL
        )
        if self.status is not expected_status:
            raise ValueError("semantic result status is inconsistent with Coverage")
        for candidate in self.candidates:
            model_candidate = SemanticModelCandidate(
                candidate_key=candidate.model_candidate_key,
                kind=candidate.kind,
                category=candidate.category,
                disposition=candidate.disposition,
                summary=candidate.summary,
                evidence_ids=candidate.evidence_ids,
                limitations=candidate.limitations,
                runtime_verified=False,
            )
            expected_id = semantic_candidate_id(
                analysis_id=self.analysis_id,
                input_sha256=self.input_sha256,
                invocation=self.invocation,
                candidate=model_candidate,
            )
            if candidate.candidate_id != expected_id:
                raise ValueError("semantic candidate ID is inconsistent")
        return self


def build_semantic_evidence_chunk(
    *,
    asset_path: str,
    asset_sha256: str,
    start_line: int,
    end_line: int,
    text: str,
) -> SemanticEvidenceChunk:
    """Create one value-minimized chunk without retaining the raw source text."""

    if not isinstance(text, str):
        raise TypeError("semantic evidence source text must be a string")
    minimized = _minimize_semantic_text(text)
    text_sha256 = _sha256_text(minimized)
    normalized_path = validate_relative_path(asset_path)
    evidence_id = _semantic_evidence_id(
        asset_path=normalized_path,
        asset_sha256=asset_sha256,
        start_line=start_line,
        end_line=end_line,
        text_sha256=text_sha256,
    )
    return SemanticEvidenceChunk(
        evidence_id=evidence_id,
        asset_path=normalized_path,
        asset_sha256=asset_sha256,
        start_line=start_line,
        end_line=end_line,
        text=minimized,
        text_sha256=text_sha256,
        sanitization_applied=minimized != text,
    )


def canonical_model_sha256(model: BaseModel) -> str:
    """Hash one validated model using canonical JSON without source excerpts."""

    return _canonical_hash(model.model_dump(mode="json"))


def semantic_candidate_id(
    *,
    analysis_id: str,
    input_sha256: str,
    invocation: SemanticInvocationProvenance,
    candidate: SemanticModelCandidate,
) -> str:
    """Compute a trusted candidate identity; the model cannot choose it."""

    payload = {
        "analysis_id": analysis_id,
        "input_sha256": input_sha256,
        "provider_id": invocation.provider_id,
        "model_id": invocation.model_id,
        "prompt_version": invocation.prompt_version,
        "candidate": candidate.semantic_payload(),
    }
    return f"semantic-candidate-sha256:{_canonical_hash(payload)}"


def _semantic_evidence_id(
    *,
    asset_path: str,
    asset_sha256: str,
    start_line: int,
    end_line: int,
    text_sha256: str,
) -> str:
    payload = {
        "asset_path": asset_path,
        "asset_sha256": asset_sha256,
        "start_line": start_line,
        "end_line": end_line,
        "text_sha256": text_sha256,
    }
    return f"semantic-evidence-sha256:{_canonical_hash(payload)}"


def _minimize_semantic_text(text: str) -> str:
    redacted = SecretRedactor().redact(text)
    minimized = _URL_PATTERN.sub("<external-location>", redacted)
    minimized = _EMAIL_PATTERN.sub("<email-address>", minimized)
    minimized = _IPV4_PATTERN.sub("<network-address>", minimized)
    escaped = escape_untrusted_text(minimized)
    return _require_safe_text(escaped, "semantic evidence text")


def _require_safe_text(value: str, label: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be exact non-empty text")
    redactor = SecretRedactor()
    for segment in re.split(r"\\[nrt]", value):
        if redactor.redact(segment) != segment:
            raise ValueError(f"{label} contains unredacted sensitive material")
    if (
        _URL_PATTERN.search(value)
        or _EMAIL_PATTERN.search(value)
        or _IPV4_PATTERN.search(value)
    ):
        raise ValueError(f"{label} contains a non-minimized location")
    if any(
        unicodedata.category(character) in _UNSAFE_CATEGORIES for character in value
    ):
        raise ValueError(f"{label} contains unsafe control characters")
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "SEMANTIC_ANALYZER_VERSION",
    "SEMANTIC_INPUT_FORMAT",
    "SEMANTIC_INPUT_SCHEMA_VERSION",
    "SEMANTIC_MAX_CANDIDATES",
    "SEMANTIC_MAX_EVIDENCE_CHUNKS",
    "SEMANTIC_MODEL_OUTPUT_FORMAT",
    "SEMANTIC_MODEL_OUTPUT_SCHEMA_VERSION",
    "SEMANTIC_OUTPUT_FORMAT",
    "SEMANTIC_OUTPUT_SCHEMA_VERSION",
    "SemanticAnalysisInput",
    "SemanticAnalysisResult",
    "SemanticAnalysisStatus",
    "SemanticAuthorityBoundary",
    "SemanticCandidateDisposition",
    "SemanticCandidateEvidence",
    "SemanticCandidateKind",
    "SemanticContractError",
    "SemanticCoverage",
    "SemanticDeterministicContext",
    "SemanticEvidenceChunk",
    "SemanticInvocationProvenance",
    "SemanticModelCandidate",
    "SemanticModelOutput",
    "build_semantic_evidence_chunk",
    "canonical_model_sha256",
    "semantic_candidate_id",
]
