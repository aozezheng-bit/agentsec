"""P3-06 read-only Semantic Candidate integration and Rule proposals.

The semantic result is deliberately kept on the evidence side of the trust
boundary.  This module can relate a candidate to an already materialized
Finding, but it cannot create, mutate, score, gate, or publish one.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsec.domain import Evidence, EvidenceSource, Finding, FindingCategory
from agentsec.semantic.models import SemanticAnalysisResult, SemanticEvidenceChunk

SEMANTIC_FINDING_INTEGRATION_VERSION = "0.1.0"
SEMANTIC_RULE_CANDIDATE_WORKFLOW_VERSION = "0.1.0"

_FINDING_ID = Annotated[str, Field(min_length=1, max_length=256)]
_CANDIDATE_ID = Annotated[
    str, Field(pattern=r"^semantic-candidate-sha256:[0-9a-f]{64}$")
]
_EVIDENCE_ID = Annotated[str, Field(pattern=r"^semantic-evidence-sha256:[0-9a-f]{64}$")]
_REVIEWER_ID = Annotated[str, Field(min_length=1, max_length=128)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class SemanticFindingRelation(StrEnum):
    """A report-only relationship to a pre-existing deterministic Finding."""

    SUPPORTS = "supports"
    DUPLICATES = "duplicates"
    CONTRADICTS = "contradicts"
    UNMATCHED = "unmatched"


class SemanticFindingLink(_Strict):
    candidate_id: _CANDIDATE_ID
    finding_id: _FINDING_ID | None = None
    relation: SemanticFindingRelation
    basis: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...]
    candidate_evidence_count: int = Field(ge=1)

    @field_validator("basis")
    @classmethod
    def basis_must_be_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("semantic Finding link basis must be sorted and unique")
        return value

    @model_validator(mode="after")
    def unmatched_must_not_have_finding(self) -> SemanticFindingLink:
        if self.relation is SemanticFindingRelation.UNMATCHED and self.finding_id:
            raise ValueError("unmatched semantic link cannot name a Finding")
        if (
            self.relation is not SemanticFindingRelation.UNMATCHED
            and not self.finding_id
        ):
            raise ValueError("matched semantic link must name a Finding")
        return self


class SemanticFindingIntegrationReport(_Strict):
    format: Literal["agentsec-semantic-finding-integration-report"] = (
        "agentsec-semantic-finding-integration-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    semantic_result_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    links: tuple[SemanticFindingLink, ...]
    report_only: Literal[True] = True
    finding_authority: Literal[False] = False
    severity_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False

    @model_validator(mode="after")
    def links_must_be_stable(self) -> SemanticFindingIntegrationReport:
        keys = tuple(
            (item.candidate_id, item.finding_id or "", item.relation.value)
            for item in self.links
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("semantic Finding links must be sorted and unique")
        return self


class RuleCandidateStatus(StrEnum):
    REVIEW_REQUIRED = "review_required"
    ACCEPTED_FOR_IMPLEMENTATION = "accepted_for_implementation"
    REJECTED = "rejected"


class SemanticRuleCandidate(_Strict):
    proposal_id: Annotated[
        str, Field(pattern=r"^semantic-rule-proposal-sha256:[0-9a-f]{64}$")
    ]
    source_candidate_id: _CANDIDATE_ID
    category: FindingCategory
    proposed_rule_family: Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{1,31}$")]
    evidence_ids: tuple[_EVIDENCE_ID, ...]
    status: RuleCandidateStatus = RuleCandidateStatus.REVIEW_REQUIRED
    reviewer_id: _REVIEWER_ID | None = None
    automatic_publication: Literal[False] = False
    deterministic_rule_authority: Literal[False] = False

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_must_be_sorted_unique(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        if not value or value != tuple(sorted(set(value))):
            raise ValueError("rule candidate Evidence IDs must be non-empty and unique")
        return value

    @model_validator(mode="after")
    def reviewer_state_must_be_coherent(self) -> SemanticRuleCandidate:
        if self.status is RuleCandidateStatus.REVIEW_REQUIRED and self.reviewer_id:
            raise ValueError("review-required proposal cannot have a reviewer")
        if (
            self.status is not RuleCandidateStatus.REVIEW_REQUIRED
            and not self.reviewer_id
        ):
            raise ValueError("reviewed proposal must have a reviewer")
        return self


class SemanticRuleCandidateReport(_Strict):
    format: Literal["agentsec-semantic-rule-candidate-report"] = (
        "agentsec-semantic-rule-candidate-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    semantic_result_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    proposals: tuple[SemanticRuleCandidate, ...]
    report_only: Literal[True] = True
    automatic_rule_publication: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False

    @model_validator(mode="after")
    def proposals_must_be_stable(self) -> SemanticRuleCandidateReport:
        keys = tuple(item.proposal_id for item in self.proposals)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("rule candidate proposals must be sorted and unique")
        return self


def _evidence_matches(chunk: SemanticEvidenceChunk, evidence: Evidence) -> bool:
    """Return whether trusted static locators can support one Finding."""

    if evidence.source_type not in (EvidenceSource.FILE, EvidenceSource.DIFF):
        return False
    if evidence.asset_path != chunk.asset_path:
        return False
    if evidence.content_sha256 != chunk.asset_sha256:
        return False
    if evidence.start_line is None or evidence.end_line is None:
        return False
    return not (
        evidence.end_line < chunk.start_line or chunk.end_line < evidence.start_line
    )


def _exact_locator(chunk: SemanticEvidenceChunk, evidence: Evidence) -> bool:
    """Return whether the semantic and Finding line locators are identical."""

    return (
        evidence.asset_path == chunk.asset_path
        and evidence.content_sha256 == chunk.asset_sha256
        and evidence.start_line == chunk.start_line
        and evidence.end_line == chunk.end_line
    )


class SemanticFindingIntegrator:
    """Relate semantic evidence to existing Findings without creating Findings.

    A relationship is emitted only when a trusted semantic Evidence chunk and a
    deterministic Finding Evidence item share the normalized path, authoritative
    asset hash, and an overlapping line range.  Category matching is also
    required for a positive relationship.  No model-authored path, line, hash,
    Finding ID, Severity, or Confidence is accepted.
    """

    def integrate(
        self,
        result: SemanticAnalysisResult,
        findings: tuple[Finding, ...],
        evidence: tuple[SemanticEvidenceChunk, ...] = (),
    ) -> SemanticFindingIntegrationReport:
        if not isinstance(result, SemanticAnalysisResult):
            raise TypeError("semantic result is required")
        if not isinstance(findings, tuple) or any(
            not isinstance(item, Finding) for item in findings
        ):
            raise TypeError("findings must be a tuple of Finding")
        if not isinstance(evidence, tuple) or any(
            not isinstance(item, SemanticEvidenceChunk) for item in evidence
        ):
            raise TypeError("evidence must be a tuple of SemanticEvidenceChunk")

        by_finding_id: dict[str, Finding] = {}
        for finding in findings:
            if finding.finding_id in by_finding_id:
                raise ValueError("Finding IDs must be unique for semantic integration")
            by_finding_id[finding.finding_id] = finding

        by_evidence_id: dict[str, SemanticEvidenceChunk] = {}
        for chunk in evidence:
            if chunk.evidence_id in by_evidence_id:
                raise ValueError("semantic Evidence IDs must be unique")
            by_evidence_id[chunk.evidence_id] = chunk

        links: list[SemanticFindingLink] = []
        for candidate in result.candidates:
            chunks = tuple(
                by_evidence_id[item]
                for item in candidate.evidence_ids
                if item in by_evidence_id
            )
            missing = set(candidate.evidence_ids) - set(by_evidence_id)
            matches: list[tuple[Finding, tuple[str, ...], bool]] = []
            for finding in findings:
                match_basis: set[str] = set()
                exact = False
                for chunk in chunks:
                    for item in finding.evidence:
                        if finding.category is candidate.category and _evidence_matches(
                            chunk, item
                        ):
                            match_basis.update(
                                {
                                    "asset_path",
                                    "asset_sha256",
                                    "category",
                                    "line_overlap",
                                }
                            )
                            exact = exact or _exact_locator(chunk, item)
                if match_basis:
                    if missing:
                        match_basis.add("partial_candidate_evidence")
                    matches.append((finding, tuple(sorted(match_basis)), exact))

            if matches:
                # Emit every deterministic match, in stable order.  Exact
                # locator matches are duplicates; partial range matches are
                # supporting relationships.  A NOT_SUPPORTED candidate is a
                # report-only contradiction, never a Finding update.
                for finding, link_basis, exact in matches:
                    relation = (
                        SemanticFindingRelation.CONTRADICTS
                        if candidate.disposition.value == "not_supported"
                        else (
                            SemanticFindingRelation.DUPLICATES
                            if exact
                            else SemanticFindingRelation.SUPPORTS
                        )
                    )
                    links.append(
                        SemanticFindingLink(
                            candidate_id=candidate.candidate_id,
                            finding_id=finding.finding_id,
                            relation=relation,
                            basis=link_basis,
                            candidate_evidence_count=len(candidate.evidence_ids),
                        )
                    )
            else:
                unmatched_basis: set[str] = {
                    "semantic_evidence_not_a_finding"
                    if not chunks
                    else "no_deterministic_evidence_overlap"
                }
                if missing:
                    unmatched_basis.add("evidence_reference_unavailable")
                links.append(
                    SemanticFindingLink(
                        candidate_id=candidate.candidate_id,
                        finding_id=None,
                        relation=SemanticFindingRelation.UNMATCHED,
                        basis=tuple(sorted(unmatched_basis)),
                        candidate_evidence_count=len(candidate.evidence_ids),
                    )
                )

        digest = hashlib.sha256(
            json.dumps(
                result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        return SemanticFindingIntegrationReport(
            semantic_result_sha256=digest,
            links=tuple(
                sorted(
                    links,
                    key=lambda item: (
                        item.candidate_id,
                        item.finding_id or "",
                        item.relation.value,
                    ),
                )
            ),
        )


# Category-to-family is intentionally a trusted, finite mapping.  It prevents
# model text from becoming a new Rule family or Rule namespace.
_RULE_FAMILY_BY_CATEGORY: dict[FindingCategory, str] = {
    FindingCategory.INSTRUCTION_INTEGRITY: "SEMANTIC_INSTRUCTION",
    FindingCategory.HUMAN_APPROVAL: "SEMANTIC_APPROVAL",
    FindingCategory.CODE_EXECUTION: "SEMANTIC_EXECUTION",
    FindingCategory.NETWORK_ACCESS: "SEMANTIC_NETWORK",
    FindingCategory.SECRET_ACCESS: "SEMANTIC_SECRET",
    FindingCategory.PRIVILEGED_ACCESS: "SEMANTIC_PRIVILEGE",
    FindingCategory.DESTRUCTIVE_ACTION: "SEMANTIC_DESTRUCTIVE",
    FindingCategory.PERSISTENT_MEMORY: "SEMANTIC_MEMORY",
    FindingCategory.SELF_MODIFICATION: "SEMANTIC_SELF_MODIFICATION",
    FindingCategory.OBFUSCATION: "SEMANTIC_OBFUSCATION",
    FindingCategory.EXTERNAL_TOOLING: "SEMANTIC_EXTERNAL_TOOL",
    FindingCategory.OTHER: "SEMANTIC_OTHER",
}


class SemanticRuleCandidateWorkflow:
    """Create review-required proposals; never publishes or mutates Rules."""

    def propose(self, result: SemanticAnalysisResult) -> SemanticRuleCandidateReport:
        if not isinstance(result, SemanticAnalysisResult):
            raise TypeError("semantic result is required")
        digest = hashlib.sha256(
            json.dumps(
                result.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        proposals = []
        for candidate in result.candidates:
            family = _RULE_FAMILY_BY_CATEGORY.get(candidate.category)
            if family is None:
                raise ValueError("semantic category has no trusted Rule family")
            payload = f"{digest}:{candidate.candidate_id}:{candidate.category.value}"
            proposal_id = (
                "semantic-rule-proposal-sha256:"
                + hashlib.sha256(payload.encode()).hexdigest()
            )
            proposals.append(
                SemanticRuleCandidate(
                    proposal_id=proposal_id,
                    source_candidate_id=candidate.candidate_id,
                    category=candidate.category,
                    proposed_rule_family=family,
                    evidence_ids=candidate.evidence_ids,
                )
            )
        return SemanticRuleCandidateReport(
            semantic_result_sha256=digest,
            proposals=tuple(sorted(proposals, key=lambda item: item.proposal_id)),
        )

    def accept_for_implementation(
        self, proposal: SemanticRuleCandidate, *, reviewer_id: str
    ) -> SemanticRuleCandidate:
        return self._review(
            proposal,
            reviewer_id=reviewer_id,
            status=RuleCandidateStatus.ACCEPTED_FOR_IMPLEMENTATION,
        )

    def reject(
        self, proposal: SemanticRuleCandidate, *, reviewer_id: str
    ) -> SemanticRuleCandidate:
        return self._review(
            proposal, reviewer_id=reviewer_id, status=RuleCandidateStatus.REJECTED
        )

    @staticmethod
    def _review(
        proposal: SemanticRuleCandidate,
        *,
        reviewer_id: str,
        status: RuleCandidateStatus,
    ) -> SemanticRuleCandidate:
        if not isinstance(proposal, SemanticRuleCandidate):
            raise TypeError("proposal is required")
        if not reviewer_id or not reviewer_id.strip():
            raise ValueError("reviewer_id is required")
        if proposal.status is not RuleCandidateStatus.REVIEW_REQUIRED:
            raise ValueError("only review-required proposals can be reviewed")
        return proposal.model_copy(
            update={"status": status, "reviewer_id": reviewer_id.strip()}
        )


__all__ = [
    "SEMANTIC_FINDING_INTEGRATION_VERSION",
    "SEMANTIC_RULE_CANDIDATE_WORKFLOW_VERSION",
    "RuleCandidateStatus",
    "SemanticFindingIntegrator",
    "SemanticFindingIntegrationReport",
    "SemanticFindingLink",
    "SemanticFindingRelation",
    "SemanticRuleCandidate",
    "SemanticRuleCandidateReport",
    "SemanticRuleCandidateWorkflow",
]
