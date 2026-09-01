"""Trusted deterministic validation for untrusted semantic model output."""

from __future__ import annotations

from pydantic import ValidationError

from agentsec.semantic.models import (
    SemanticAnalysisInput,
    SemanticAnalysisResult,
    SemanticAnalysisStatus,
    SemanticCandidateEvidence,
    SemanticContractError,
    SemanticCoverage,
    SemanticInvocationProvenance,
    SemanticModelOutput,
    canonical_model_sha256,
    semantic_candidate_id,
)

_STANDARD_LIMITATIONS = (
    "Deterministic Rules and reviewed Policy retain all authorization authority.",
    "Semantic output is candidate evidence only and cannot Allow or Block.",
    "Static semantic judgment does not prove runtime capability or exploitability.",
)
_INCOMPLETE_LIMITATION = (
    "Deterministic Coverage or semantic Evidence coverage is incomplete."
)


class SemanticAnalysisContract:
    """Validate one constrained response and produce a non-authoritative result."""

    def validate(
        self,
        request: SemanticAnalysisInput,
        model_output: SemanticModelOutput,
        invocation: SemanticInvocationProvenance,
    ) -> SemanticAnalysisResult:
        """Bind model judgments to trusted Evidence and fixed Shadow semantics."""

        if not isinstance(request, SemanticAnalysisInput):
            raise TypeError("semantic request must be SemanticAnalysisInput")
        if not isinstance(model_output, SemanticModelOutput):
            raise TypeError("model output must be SemanticModelOutput")
        if not isinstance(invocation, SemanticInvocationProvenance):
            raise TypeError("invocation must be SemanticInvocationProvenance")
        if model_output.analysis_id != request.analysis_id:
            raise SemanticContractError("semantic Analysis ID does not match")

        evidence_ids = tuple(item.evidence_id for item in request.evidence)
        known = set(evidence_ids)
        analyzed = set(model_output.analyzed_evidence_ids)
        if not analyzed <= known:
            raise SemanticContractError(
                "model output references unknown analyzed Evidence"
            )

        for candidate in model_output.candidates:
            referenced = set(candidate.evidence_ids)
            if not referenced <= known:
                raise SemanticContractError(
                    "semantic candidate references unknown Evidence"
                )
            if not referenced <= analyzed:
                raise SemanticContractError(
                    "semantic candidate references Evidence not reported as analyzed"
                )

        input_sha256 = canonical_model_sha256(request)
        output_sha256 = canonical_model_sha256(model_output)
        candidates = tuple(
            SemanticCandidateEvidence(
                candidate_id=semantic_candidate_id(
                    analysis_id=request.analysis_id,
                    input_sha256=input_sha256,
                    invocation=invocation,
                    candidate=item,
                ),
                model_candidate_key=item.candidate_key,
                kind=item.kind,
                category=item.category,
                disposition=item.disposition,
                summary=item.summary,
                evidence_ids=item.evidence_ids,
                limitations=item.limitations,
            )
            for item in model_output.candidates
        )
        candidate_ids = tuple(item.candidate_id for item in candidates)
        if len(set(candidate_ids)) != len(candidate_ids):
            raise SemanticContractError("semantic candidate identities collide")

        omitted = tuple(sorted(known - analyzed))
        semantic_complete = not omitted
        combined_complete = (
            semantic_complete and request.deterministic_context.coverage_complete
        )
        coverage = SemanticCoverage(
            input_evidence_count=len(evidence_ids),
            analyzed_evidence_count=len(analyzed),
            omitted_evidence_ids=omitted,
            semantic_complete=semantic_complete,
            deterministic_coverage_complete=(
                request.deterministic_context.coverage_complete
            ),
            unknown_dimensions=request.deterministic_context.unknown_dimensions,
            complete=combined_complete,
        )
        limitations = set(_STANDARD_LIMITATIONS)
        limitations.update(model_output.limitations)
        if not combined_complete:
            limitations.add(_INCOMPLETE_LIMITATION)
        return SemanticAnalysisResult(
            analysis_id=request.analysis_id,
            status=(
                SemanticAnalysisStatus.COMPLETE
                if combined_complete
                else SemanticAnalysisStatus.PARTIAL
            ),
            input_sha256=input_sha256,
            model_output_sha256=output_sha256,
            invocation=invocation,
            authority_boundary=request.authority_boundary,
            deterministic_context=request.deterministic_context,
            coverage=coverage,
            candidates=candidates,
            limitations=tuple(sorted(limitations)),
        )

    def validate_json(
        self,
        request: SemanticAnalysisInput,
        model_output_json: str,
        invocation: SemanticInvocationProvenance,
    ) -> SemanticAnalysisResult:
        """Parse strict JSON and validate without retaining free-form response text."""

        if not isinstance(model_output_json, str):
            raise TypeError("semantic model output JSON must be a string")
        try:
            model_output = SemanticModelOutput.model_validate_json(model_output_json)
        except ValidationError as error:
            raise SemanticContractError(
                "semantic model output failed schema validation"
            ) from error
        return self.validate(request, model_output, invocation)


__all__ = ["SemanticAnalysisContract"]
