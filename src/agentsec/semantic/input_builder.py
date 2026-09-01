"""Trusted construction of bounded SemanticAnalysisInput from inspected assets."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from agentsec.frameworks import FrameworkAssetRecord, FrameworkInspectionResult
from agentsec.manifests import AgentManifest
from agentsec.parsers import (
    ParsedMarkdown,
    ParsedRulesDocument,
    StructuredDocument,
    format_structured_path,
)
from agentsec.semantic.models import (
    SEMANTIC_MAX_EVIDENCE_CHUNKS,
    SemanticAnalysisInput,
    SemanticDeterministicContext,
    SemanticEvidenceChunk,
    build_semantic_evidence_chunk,
    canonical_model_sha256,
)

_ROOT_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")


class SemanticInputBuildError(ValueError):
    """Safe input-builder failure that never contains source text."""


@dataclass(frozen=True, slots=True)
class TrustedSemanticInputBuilder:
    """Build semantic input only from trusted Adapter and Manifest outputs.

    The builder consumes parsed, bounded Adapter records. It never executes or
    dereferences a target asset and never accepts model-authored locations.
    """

    max_evidence_chunks: int = SEMANTIC_MAX_EVIDENCE_CHUNKS

    def __post_init__(self) -> None:
        if not 1 <= self.max_evidence_chunks <= SEMANTIC_MAX_EVIDENCE_CHUNKS:
            raise ValueError("semantic input evidence limit is outside the contract")

    def build(
        self,
        inspection: FrameworkInspectionResult,
        manifest: AgentManifest,
        *,
        analysis_id: str | None = None,
        finding_ids: tuple[str, ...] = (),
        assessment_sha256: str | None = None,
    ) -> SemanticAnalysisInput:
        if not isinstance(inspection, FrameworkInspectionResult):
            raise TypeError("semantic input builder requires inspection result")
        if not isinstance(manifest, AgentManifest):
            raise TypeError("semantic input builder requires AgentManifest")
        if not isinstance(finding_ids, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in finding_ids
        ):
            raise TypeError("finding_ids must be a tuple of non-empty strings")
        if assessment_sha256 is not None and not _is_sha256(assessment_sha256):
            raise ValueError("assessment_sha256 must be a lowercase SHA-256 digest")

        source_keys = {source.locator.sort_key() for source in manifest.sources}
        inspected_keys = {
            (
                record.asset.locator.scope.value,
                record.asset.locator.root_id,
                record.asset.locator.path,
            )
            for record in inspection.assets
        }
        if not inspected_keys <= source_keys:
            raise SemanticInputBuildError(
                "inspection and Manifest source sets disagree"
            )

        derived_analysis_id = analysis_id or self._analysis_id(inspection, manifest)
        if not re.fullmatch(r"[a-z][a-z0-9._-]{0,127}", derived_analysis_id):
            raise ValueError("analysis_id must use stable lowercase form")

        chunks = sorted(_record_chunks(record) for record in inspection.assets)
        flattened = [chunk for group in chunks for chunk in group]
        unique: dict[tuple[str, int, int, str], SemanticEvidenceChunk] = {}
        for chunk in flattened:
            unique[(chunk.asset_path, chunk.start_line, chunk.end_line, chunk.text)] = (
                chunk
            )
        ordered = sorted(unique.values(), key=lambda item: item.sort_key())
        if not ordered:
            raise SemanticInputBuildError(
                "no source-backed semantic Evidence was available"
            )

        complete = inspection.complete and manifest.coverage.complete
        unknown_dimensions = {item.dimension.value for item in manifest.unknowns}
        if len(ordered) > self.max_evidence_chunks:
            ordered = ordered[: self.max_evidence_chunks]
            complete = False
            unknown_dimensions.add("semantic_evidence_limit")

        context = SemanticDeterministicContext(
            coverage_complete=complete,
            manifest_sha256=canonical_model_sha256(manifest),
            assessment_sha256=assessment_sha256,
            finding_ids=tuple(sorted(set(finding_ids))),
            capability_ids=tuple(sorted(tool.tool_id for tool in manifest.tools.tools)),
            unknown_dimensions=tuple(sorted(unknown_dimensions)),
        )
        return SemanticAnalysisInput(
            analysis_id=derived_analysis_id,
            deterministic_context=context,
            evidence=tuple(ordered),
        )

    @staticmethod
    def _analysis_id(
        inspection: FrameworkInspectionResult, manifest: AgentManifest
    ) -> str:
        payload = {
            "manifest": canonical_model_sha256(manifest),
            "framework": inspection.metadata.framework_id,
            "adapter_version": inspection.metadata.adapter_version,
            "assets": [
                {
                    "scope": record.asset.locator.scope.value,
                    "root_id": record.asset.locator.root_id,
                    "path": record.asset.locator.path,
                    "sha256": record.asset.content_sha256,
                    "line_count": record.asset.line_count,
                }
                for record in inspection.assets
            ],
            "issues": [issue._sort_key() for issue in inspection.issues],
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return f"semantic-{digest}"


def _record_chunks(record: FrameworkAssetRecord) -> tuple[SemanticEvidenceChunk, ...]:
    asset = record.asset
    path = _asset_path(
        asset.locator.scope.value, asset.locator.root_id, asset.locator.path
    )
    candidates: list[tuple[int, int, str]] = []
    document = record.document
    if isinstance(document, ParsedMarkdown):
        candidates.extend(
            (block.start_line, block.end_line, block.raw_text or block.text)
            for block in document.blocks
            if block.raw_text or block.text
        )
        if document.frontmatter is not None:
            candidates.append(
                (
                    document.frontmatter.start_line,
                    document.frontmatter.end_line,
                    document.frontmatter.raw_text,
                )
            )
        candidates.extend(
            (item.start_line, item.end_line, item.raw_text)
            for item in document.references
            if item.raw_text
        )
    elif isinstance(document, ParsedRulesDocument):
        for item in document.rules:
            candidates.extend(
                (
                    item.start_line,
                    item.end_line,
                    (
                        f"pattern={item.pattern.value!r} "
                        f"decision={item.decision.value.value!r}"
                    ),
                )
                for _ in (0,)
            )
    elif isinstance(document, StructuredDocument):
        candidates.extend(
            (
                item.start_line,
                item.end_line,
                (
                    str(item.value)
                    if item.value is not None
                    else format_structured_path(item.path)
                ),
            )
            for item in document.nodes
        )
    else:  # pragma: no cover - Adapter contract exhaustiveness
        raise SemanticInputBuildError("unsupported inspected document type")

    chunks: list[SemanticEvidenceChunk] = []
    for start_line, end_line, text in candidates:
        if not isinstance(text, str) or not text.strip():
            continue
        try:
            chunks.append(
                build_semantic_evidence_chunk(
                    asset_path=path,
                    asset_sha256=asset.content_sha256,
                    start_line=start_line,
                    end_line=end_line,
                    text=text,
                )
            )
        except (TypeError, ValueError) as error:
            raise SemanticInputBuildError(
                "inspected source Evidence could not be sanitized safely"
            ) from error
    return tuple(chunks)


def _asset_path(scope: str, root_id: str, path: str) -> str:
    if scope == "project" and root_id == "project":
        return path
    root = _ROOT_COMPONENT.sub("_", root_id).strip("._") or "root"
    return f"{scope}/{root}/{path}"


def _is_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[a-f0-9]{64}", value))


__all__ = ["SemanticInputBuildError", "TrustedSemanticInputBuilder"]
