"""Offline CVE/CWE data-source adapters and conservative auto-association.

The source boundary is deliberately local and inert.  It accepts bounded JSON
files, normalizes NVD JSON 2.0 or the AgentSec catalog format, and associates a
Finding only when one exact CVE token is present in the Finding's own textual
evidence and that CVE exists in the normalized source.  It never executes source
content, contacts a network, or treats an identifier match as runtime proof.
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.domain import Assessment, VulnerabilityReference
from agentsec.risk import CvssAdapterError, CvssBaseAdapter
from agentsec.vulnerabilities.input import CvssInputPayload

VULNERABILITY_CATALOG_FORMAT: Final = "agentsec-vulnerability-catalog"
VULNERABILITY_CATALOG_VERSION: Final = "0.1.0"
NVD_CVE_FORMAT: Final = "NVD_CVE"
NVD_CVE_VERSION: Final = "2.0"
NVD_SOURCE_ID: Final = "nvd-json-2.0"
MAX_VULNERABILITY_SOURCE_SIZE_BYTES: Final = 64 * 1024 * 1024
_READ_CHUNK_SIZE: Final = 65_536
_CVE_TOKEN_PATTERN: Final = re.compile(
    r"(?<![A-Za-z0-9])CVE-[0-9]{4}-[0-9]{4,}(?![A-Za-z0-9-])",
    re.IGNORECASE,
)
_CWE_PATTERN: Final = re.compile(
    r"^(?:NVD-)?CWE-(?:[0-9]+|Other|noinfo)$",
    re.IGNORECASE,
)
_SOURCE_ID_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"


class VulnerabilitySourceCode(StrEnum):
    """Stable non-sensitive failures for source loading and adaptation."""

    MISSING = "missing"
    INVALID_PATH = "invalid_path"
    SYMBOLIC_LINK = "symbolic_link"
    TOO_LARGE = "too_large"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_JSON = "invalid_json"
    UNSUPPORTED_FORMAT = "unsupported_format"
    INVALID_SCHEMA = "invalid_schema"
    EMPTY_SOURCE = "empty_source"
    DUPLICATE_CVE = "duplicate_cve"


class VulnerabilitySourceError(RuntimeError):
    """Safe source failure that never echoes untrusted source payloads."""

    def __init__(self, code: VulnerabilitySourceCode, message: str) -> None:
        self.code = code
        super().__init__(message)


class _SourceModel(BaseModel):
    """Strict immutable model boundary for normalized source data."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class VulnerabilitySourceRecord(_SourceModel):
    """One normalized CVE record suitable for deterministic association."""

    cve_id: Annotated[str, Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")]
    cwe_ids: tuple[
        Annotated[str, Field(pattern=r"^CWE-(?:[0-9]+|Other|noinfo)$")], ...
    ] = ()
    cvss: CvssInputPayload | None = None

    @field_validator("cwe_ids")
    @classmethod
    def cwes_must_be_unique_and_ordered(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Normalize source CWE references into a stable unique order."""

        if len(set(value)) != len(value):
            raise ValueError("source CWE identifiers must be unique")
        return tuple(sorted(value))

    @field_validator("cvss")
    @classmethod
    def cvss_must_be_locally_valid(
        cls, value: CvssInputPayload | None
    ) -> CvssInputPayload | None:
        """Validate source CVSS through the one canonical adapter."""

        if value is not None:
            try:
                CvssBaseAdapter().adapt(value.model_dump(exclude_none=True))
            except CvssAdapterError as error:
                raise ValueError("source CVSS payload is invalid") from error
        return value


class VulnerabilityCatalog(_SourceModel):
    """Versioned normalized catalog consumed by the auto-associator."""

    format: Literal["agentsec-vulnerability-catalog"]
    format_version: Literal["0.1.0"]
    source_id: Annotated[str, Field(pattern=_SOURCE_ID_PATTERN)]
    source_format: Annotated[str, Field(pattern=_SOURCE_ID_PATTERN)]
    records: tuple[VulnerabilitySourceRecord, ...] = Field(min_length=1)

    @field_validator("format")
    @classmethod
    def format_must_match(cls, value: str) -> str:
        """Reject normalized documents from another contract version."""

        if value != VULNERABILITY_CATALOG_FORMAT:
            raise ValueError("vulnerability catalog format is unsupported")
        return value

    @field_validator("format_version")
    @classmethod
    def version_must_match(cls, value: str) -> str:
        """Reject normalized documents from another contract version."""

        if value != VULNERABILITY_CATALOG_VERSION:
            raise ValueError("vulnerability catalog version is unsupported")
        return value

    @model_validator(mode="after")
    def cves_must_be_unique(self) -> VulnerabilityCatalog:
        """Prevent ambiguous source lookup caused by duplicate CVE rows."""

        cve_ids = tuple(record.cve_id for record in self.records)
        if len(set(cve_ids)) != len(cve_ids):
            raise ValueError("vulnerability catalog CVE identifiers must be unique")
        return self


@dataclass(frozen=True, slots=True)
class VulnerabilitySourceIssue:
    """Bounded issue metadata for records skipped during tolerant NVD parsing."""

    code: VulnerabilitySourceCode


@dataclass(frozen=True, slots=True)
class VulnerabilitySourceReadResult:
    """Validated catalog plus safe file and adaptation metadata."""

    catalog: VulnerabilityCatalog
    path: Path
    size_bytes: int
    skipped_records: int = 0
    issues: tuple[VulnerabilitySourceIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class VulnerabilityAssociationStats:
    """Non-sensitive counters describing one automatic association pass."""

    inspected_findings: int
    matched_findings: int
    cvss_enriched_findings: int
    skipped_existing_findings: int
    ambiguous_findings: int
    unknown_cve_findings: int
    findings_without_cve: int


@dataclass(frozen=True, slots=True)
class VulnerabilityAssociationResult:
    """Enriched Assessment and deterministic association counters."""

    assessment: Assessment
    stats: VulnerabilityAssociationStats


def extract_cve_ids(values: Sequence[str]) -> tuple[str, ...]:
    """Extract canonical unique CVE tokens from bounded Finding text values."""

    identifiers = {
        match.group(0).upper()
        for value in values
        for match in _CVE_TOKEN_PATTERN.finditer(value)
    }
    return tuple(sorted(identifiers))


class AgentSecCatalogAdapter:
    """Adapt a strict normalized AgentSec vulnerability catalog."""

    def adapt(self, payload: Mapping[str, object]) -> VulnerabilityCatalog:
        """Validate one normalized catalog without interpreting free-form text."""

        try:
            return VulnerabilityCatalog.model_validate(payload)
        except Exception as error:
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.INVALID_SCHEMA,
                "vulnerability catalog failed schema validation",
            ) from error


class NvdJson20Adapter:
    """Adapt the supported subset of the NVD CVE JSON 2.0 feed format."""

    def __init__(self, *, cvss_adapter: CvssBaseAdapter | None = None) -> None:
        self._cvss_adapter = cvss_adapter or CvssBaseAdapter()

    def adapt(
        self, payload: Mapping[str, object]
    ) -> tuple[VulnerabilityCatalog, tuple[VulnerabilitySourceIssue, ...]]:
        """Normalize NVD CVE records while skipping malformed individual rows."""

        if (
            payload.get("format") != NVD_CVE_FORMAT
            or payload.get("version") != NVD_CVE_VERSION
        ):
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.UNSUPPORTED_FORMAT,
                "vulnerability source is not supported NVD JSON 2.0",
            )
        raw_records = payload.get("vulnerabilities")
        if not isinstance(raw_records, Sequence) or isinstance(
            raw_records, (str, bytes)
        ):
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.INVALID_SCHEMA,
                "NVD source vulnerabilities must be an array",
            )
        if not raw_records:
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.EMPTY_SOURCE,
                "NVD source contains no vulnerability records",
            )

        records: list[VulnerabilitySourceRecord] = []
        issues: list[VulnerabilitySourceIssue] = []
        seen: set[str] = set()
        for raw_record in raw_records:
            try:
                record = self._adapt_record(raw_record)
            except Exception:
                issues.append(
                    VulnerabilitySourceIssue(VulnerabilitySourceCode.INVALID_SCHEMA)
                )
                continue
            if record.cve_id in seen:
                raise VulnerabilitySourceError(
                    VulnerabilitySourceCode.DUPLICATE_CVE,
                    "NVD source contains duplicate CVE identifiers",
                )
            seen.add(record.cve_id)
            records.append(record)

        if not records:
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.EMPTY_SOURCE,
                "NVD source contains no usable vulnerability records",
            )
        catalog = VulnerabilityCatalog(
            format=VULNERABILITY_CATALOG_FORMAT,
            format_version=VULNERABILITY_CATALOG_VERSION,
            source_id=NVD_SOURCE_ID,
            source_format="nvd-json-2.0",
            records=tuple(records),
        )
        return catalog, tuple(issues)

    def _adapt_record(self, raw_record: object) -> VulnerabilitySourceRecord:
        wrapper = _mapping(raw_record)
        cve = _mapping(wrapper.get("cve"))
        cve_id = cve.get("id")
        if not isinstance(cve_id, str):
            raise ValueError("NVD record has no CVE ID")
        canonical_cve = cve_id.strip().upper()
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", canonical_cve):
            raise ValueError("NVD record CVE ID is invalid")
        cwe_ids = _extract_nvd_cwes(cve.get("weaknesses"))
        cvss = self._extract_nvd_cvss(cve.get("metrics"))
        return VulnerabilitySourceRecord(
            cve_id=canonical_cve,
            cwe_ids=cwe_ids,
            cvss=cvss,
        )

    def _extract_nvd_cvss(self, value: object) -> CvssInputPayload | None:
        metrics = _mapping(value)
        for metric_name in ("cvssMetricV40", "cvssMetricV31"):
            candidates = metrics.get(metric_name)
            if not isinstance(candidates, Sequence) or isinstance(
                candidates, (str, bytes)
            ):
                continue
            ordered = sorted(
                (_mapping(item) for item in candidates),
                key=lambda item: (
                    0 if item.get("type") == "Primary" else 1,
                    0 if item.get("source") == "nvd@nist.gov" else 1,
                    str(_mapping(item.get("cvssData")).get("vectorString", "")),
                ),
            )
            for candidate in ordered:
                cvss_data = _mapping(candidate.get("cvssData"))
                vector = cvss_data.get("vectorString")
                if not isinstance(vector, str):
                    continue
                payload: dict[str, object] = {"vector": vector}
                base_score = cvss_data.get("baseScore")
                if isinstance(base_score, (int, float)) and not isinstance(
                    base_score, bool
                ):
                    payload["base_score"] = base_score
                base_severity = cvss_data.get("baseSeverity")
                if isinstance(base_severity, str):
                    payload["base_severity"] = base_severity.lower()
                try:
                    self._cvss_adapter.adapt(payload)
                except CvssAdapterError:
                    payload = {"vector": vector}
                    try:
                        self._cvss_adapter.adapt(payload)
                    except CvssAdapterError:
                        continue
                return CvssInputPayload.model_validate(payload)
        return None


VULNERABILITY_CATALOG_SCHEMA_FILENAME: Final = "vulnerability-catalog.schema.json"


def export_vulnerability_catalog_json_schema(output_directory: Path) -> Path:
    """Write the strict normalized vulnerability catalog JSON Schema."""

    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / VULNERABILITY_CATALOG_SCHEMA_FILENAME
    output_path.write_text(
        json.dumps(
            VulnerabilityCatalog.model_json_schema(mode="serialization"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


class VulnerabilitySourceFileReader:
    """Read bounded local JSON and dispatch to the supported source adapter."""

    def __init__(
        self,
        *,
        max_file_size_bytes: int = MAX_VULNERABILITY_SOURCE_SIZE_BYTES,
        catalog_adapter: AgentSecCatalogAdapter | None = None,
        nvd_adapter: NvdJson20Adapter | None = None,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("vulnerability source size limit must be positive")
        self._max_file_size_bytes = max_file_size_bytes
        self._catalog_adapter = catalog_adapter or AgentSecCatalogAdapter()
        self._nvd_adapter = nvd_adapter or NvdJson20Adapter()

    def read(self, path: Path) -> VulnerabilitySourceReadResult:
        """Read one local source without following links or executing content."""

        content = self._read_bytes(path)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.INVALID_UTF8,
                "vulnerability source must be valid UTF-8",
            ) from error
        try:
            payload = json.loads(text)
        except (TypeError, ValueError) as error:
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.INVALID_JSON,
                "vulnerability source is not valid JSON",
            ) from error
        if not isinstance(payload, Mapping):
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.INVALID_SCHEMA,
                "vulnerability source must contain one JSON object",
            )
        if payload.get("format") == VULNERABILITY_CATALOG_FORMAT:
            catalog = self._catalog_adapter.adapt(payload)
            issues: tuple[VulnerabilitySourceIssue, ...] = ()
        elif payload.get("format") == NVD_CVE_FORMAT:
            catalog, issues = self._nvd_adapter.adapt(payload)
        else:
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.UNSUPPORTED_FORMAT,
                "vulnerability source format is unsupported",
            )
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.INVALID_PATH,
                "vulnerability source path could not be resolved safely",
            ) from error
        return VulnerabilitySourceReadResult(
            catalog=catalog,
            path=resolved,
            size_bytes=len(content),
            skipped_records=len(issues),
            issues=issues,
        )

    def _read_bytes(self, path: Path) -> bytes:
        if not isinstance(path, Path):
            raise TypeError("vulnerability source path must be a Path")
        if path.suffix.lower() != ".json":
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.INVALID_PATH,
                "vulnerability source must use a .json filename",
            )
        if path.is_symlink():
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.SYMBOLIC_LINK,
                "vulnerability source must not be a symbolic link",
            )
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise VulnerabilitySourceError(
                    VulnerabilitySourceCode.INVALID_PATH,
                    "vulnerability source must be a regular file",
                )
            if metadata.st_size > self._max_file_size_bytes:
                raise VulnerabilitySourceError(
                    VulnerabilitySourceCode.TOO_LARGE,
                    "vulnerability source exceeds the hard file-size limit",
                )
            remaining = self._max_file_size_bytes + 1
            chunks: list[bytes] = []
            while remaining > 0:
                chunk = os.read(descriptor, min(_READ_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) > self._max_file_size_bytes:
                raise VulnerabilitySourceError(
                    VulnerabilitySourceCode.TOO_LARGE,
                    "vulnerability source exceeds the hard file-size limit",
                )
            return content
        except FileNotFoundError as error:
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.MISSING,
                "vulnerability source does not exist",
            ) from error
        except VulnerabilitySourceError:
            raise
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise VulnerabilitySourceError(
                    VulnerabilitySourceCode.SYMBOLIC_LINK,
                    "vulnerability source must not be a symbolic link",
                ) from error
            raise VulnerabilitySourceError(
                VulnerabilitySourceCode.INVALID_PATH,
                "vulnerability source could not be read safely",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)


class VulnerabilityAutoAssociator:
    """Associate exact CVE evidence with records from one local catalog."""

    def __init__(self, *, cvss_adapter: CvssBaseAdapter | None = None) -> None:
        self._cvss_adapter = cvss_adapter or CvssBaseAdapter()

    def apply(
        self,
        assessment: Assessment,
        catalog: VulnerabilityCatalog,
    ) -> VulnerabilityAssociationResult:
        """Return an enriched Assessment without changing AgentSec risk fields."""

        if not isinstance(assessment, Assessment):
            raise TypeError(
                "automatic vulnerability association requires an Assessment"
            )
        if not isinstance(catalog, VulnerabilityCatalog):
            raise TypeError("automatic vulnerability association requires a catalog")

        records = {record.cve_id: record for record in catalog.records}
        findings = []
        matched = 0
        cvss_enriched = 0
        skipped_existing = 0
        ambiguous = 0
        unknown = 0
        without_cve = 0
        for finding in assessment.findings:
            if finding.vulnerability is not None:
                skipped_existing += 1
                findings.append(finding)
                continue
            identifiers = extract_cve_ids(
                (
                    finding.title,
                    finding.description,
                    *(evidence.excerpt or "" for evidence in finding.evidence),
                )
            )
            if not identifiers:
                without_cve += 1
                findings.append(finding)
                continue
            if len(identifiers) != 1:
                ambiguous += 1
                findings.append(finding)
                continue
            record = records.get(identifiers[0])
            if record is None:
                unknown += 1
                findings.append(finding)
                continue

            reference = VulnerabilityReference(
                vulnerability_id=record.cve_id,
                cve_id=record.cve_id,
                cwe_ids=record.cwe_ids,
                source=catalog.source_id,
                association_method="deterministic_match",
                association_basis=(
                    "Exact CVE identifier matched Finding title, description, "
                    "or evidence.",
                    f"Matched normalized {catalog.source_format} source record.",
                ),
            )
            enriched = finding.attach_vulnerability(reference)
            matched += 1
            if enriched.cvss is None and record.cvss is not None:
                try:
                    enriched = (
                        CvssBaseAdapter()
                        .adapt(record.cvss.model_dump(exclude_none=True))
                        .attach_to_finding(enriched)
                    )
                    cvss_enriched += 1
                except (CvssAdapterError, TypeError, ValueError):
                    # The normalized catalog validates CVSS.  Keep the CVE
                    # association if a future adapter implementation changes.
                    pass
            findings.append(enriched)

        return VulnerabilityAssociationResult(
            assessment=assessment.model_copy(update={"findings": tuple(findings)}),
            stats=VulnerabilityAssociationStats(
                inspected_findings=len(assessment.findings),
                matched_findings=matched,
                cvss_enriched_findings=cvss_enriched,
                skipped_existing_findings=skipped_existing,
                ambiguous_findings=ambiguous,
                unknown_cve_findings=unknown,
                findings_without_cve=without_cve,
            ),
        )


def _mapping(value: object) -> Mapping[str, object]:
    """Return a JSON object or an empty safe mapping."""

    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return {}


def _extract_nvd_cwes(value: object) -> tuple[str, ...]:
    """Normalize NVD weakness descriptions into supported CWE identifiers."""

    identifiers: set[str] = set()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    for weakness in value:
        raw_descriptions = _mapping(weakness).get("description")
        if not isinstance(raw_descriptions, Sequence) or isinstance(
            raw_descriptions, (str, bytes)
        ):
            continue
        for description in raw_descriptions:
            item = _mapping(description)
            raw = item.get("value")
            if not isinstance(raw, str):
                continue
            normalized = raw.strip()
            if not _CWE_PATTERN.fullmatch(normalized):
                continue
            normalized = normalized.upper().removeprefix("NVD-")
            if normalized == "CWE-NOINFO":
                normalized = "CWE-noinfo"
            elif normalized == "CWE-OTHER":
                normalized = "CWE-Other"
            identifiers.add(normalized)
    return tuple(sorted(identifiers))
