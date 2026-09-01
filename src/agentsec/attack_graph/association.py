"""P3-AG-05 deterministic Attack Path and Evidence association.

This module joins already validated static Attack Graph paths to existing
Finding Evidence and Shadow-only Semantic Evidence.  It is deliberately a
read-only correlation layer: it does not create or mutate Findings,
Semantic Candidates, Rules, Policy, CI decisions, or runtime claims.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.attack_graph.models import (
    AttackGraphPath,
    AttackGraphSourceRef,
    CapabilityAttackGraph,
)
from agentsec.attack_graph.report import (
    build_attack_path_report,
    canonical_attack_graph_sha256,
)
from agentsec.domain import Evidence, EvidenceSource, Finding

if TYPE_CHECKING:
    from agentsec.semantic.models import (
        SemanticAnalysisResult,
        SemanticEvidenceChunk,
    )

ATTACK_PATH_EVIDENCE_ASSOCIATION_VERSION = "0.1.0"
ATTACK_PATH_EVIDENCE_ASSOCIATION_FORMAT = (
    "agentsec-attack-path-evidence-association-report"
)
ATTACK_PATH_ASSOCIATION_MAX_LIMITATIONS = 32

_FINDING_ID = Annotated[str, Field(min_length=1, max_length=256)]
_CANDIDATE_ID = Annotated[
    str, Field(pattern=r"^semantic-candidate-sha256:[0-9a-f]{64}$")
]


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class AttackPathAssociationBasis(StrEnum):
    """Finite, auditable reasons for a deterministic association."""

    ASSET_PATH = "asset_path"
    ASSET_SHA256 = "asset_sha256"
    LINE_OVERLAP = "line_overlap"
    GRAPH_NODE_SOURCE = "graph_node_source"
    GRAPH_EDGE_SOURCE = "graph_edge_source"
    EXACT_LOCATOR = "exact_locator"
    PARTIAL_EVIDENCE_OVERLAP = "partial_evidence_overlap"
    NO_DETERMINISTIC_EVIDENCE_OVERLAP = "no_deterministic_evidence_overlap"
    GRAPH_SOURCE_UNAVAILABLE = "graph_source_unavailable"
    FINDING_EVIDENCE_NOT_STATIC = "finding_evidence_not_static"
    SEMANTIC_EVIDENCE_REFERENCE_UNAVAILABLE = "semantic_evidence_reference_unavailable"


class AttackPathGraphEvidenceRef(_Strict):
    """One path source locator with its graph role(s), without source text."""

    source: AttackGraphSourceRef
    roles: tuple[Literal["node", "edge"], ...] = ()

    @model_validator(mode="after")
    def roles_must_be_sorted_unique(self) -> AttackPathGraphEvidenceRef:
        if self.roles != tuple(sorted(set(self.roles))):
            raise ValueError("Attack Path graph Evidence roles must be sorted unique")
        return self

    def sort_key(self) -> tuple[str, str, int, int]:
        return self.source.sort_key()


class AttackPathFindingEvidenceRef(_Strict):
    """Value-free projection of eligible static Finding Evidence."""

    source_type: Literal[EvidenceSource.FILE, EvidenceSource.DIFF]
    asset_path: Annotated[str, Field(min_length=1, max_length=512)]
    content_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def locator_must_be_coherent(self) -> AttackPathFindingEvidenceRef:
        if self.end_line < self.start_line:
            raise ValueError("Finding Evidence line range is incoherent")
        return self

    def sort_key(self) -> tuple[str, str, int, int, str]:
        return (
            self.asset_path,
            self.content_sha256,
            self.start_line,
            self.end_line,
            self.source_type.value,
        )


class AttackPathSemanticEvidenceRef(_Strict):
    """Trusted Semantic Evidence locator without the minimized source text."""

    evidence_id: Annotated[
        str, Field(pattern=r"^semantic-evidence-sha256:[0-9a-f]{64}$")
    ]
    asset_path: Annotated[str, Field(min_length=1, max_length=512)]
    asset_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def locator_must_be_coherent(self) -> AttackPathSemanticEvidenceRef:
        if self.end_line < self.start_line:
            raise ValueError("Semantic Evidence line range is incoherent")
        return self

    def sort_key(self) -> tuple[str, str, int, int, str]:
        return (
            self.asset_path,
            self.asset_sha256,
            self.start_line,
            self.end_line,
            self.evidence_id,
        )


class AttackPathAssociationRelation(StrEnum):
    """Report-only relationship between a path and one Evidence target."""

    SUPPORTS = "supports"
    PARTIALLY_SUPPORTS = "partially_supports"
    DUPLICATES = "duplicates"
    UNMATCHED = "unmatched"


class AttackPathEvidenceAssociation(_Strict):
    """One deterministic path-to-Finding or path-to-Semantic association."""

    path_id: Annotated[str, Field(pattern=r"^attack-path-sha256:[0-9a-f]{64}$")]
    target_kind: Literal["finding", "semantic_candidate"]
    finding_id: _FINDING_ID | None = None
    semantic_candidate_id: _CANDIDATE_ID | None = None
    relation: AttackPathAssociationRelation
    basis: tuple[AttackPathAssociationBasis, ...]
    evidence_refs: tuple[AttackPathGraphEvidenceRef, ...]
    finding_evidence_refs: tuple[AttackPathFindingEvidenceRef, ...] = ()
    semantic_evidence_refs: tuple[AttackPathSemanticEvidenceRef, ...] = ()

    @model_validator(mode="after")
    def association_must_be_coherent(self) -> AttackPathEvidenceAssociation:
        if self.basis != tuple(sorted(set(self.basis), key=lambda item: item.value)):
            raise ValueError("Attack Path association basis must be sorted and unique")
        graph_keys = tuple(item.sort_key() for item in self.evidence_refs)
        if graph_keys != tuple(sorted(set(graph_keys))):
            raise ValueError(
                "Attack Path association Evidence refs must be sorted unique"
            )
        finding_keys = tuple(item.sort_key() for item in self.finding_evidence_refs)
        if finding_keys != tuple(sorted(set(finding_keys))):
            raise ValueError("Finding Evidence refs must be sorted unique")
        semantic_keys = tuple(item.sort_key() for item in self.semantic_evidence_refs)
        if semantic_keys != tuple(sorted(set(semantic_keys))):
            raise ValueError("Semantic Evidence refs must be sorted unique")

        if self.target_kind == "finding":
            if self.semantic_candidate_id is not None:
                raise ValueError("Finding association must name only a Finding")
            if self.semantic_evidence_refs:
                raise ValueError("Finding association cannot carry Semantic Evidence")
        else:
            if self.finding_id is not None:
                raise ValueError(
                    "Semantic association must name only a Semantic Candidate"
                )
            if self.finding_evidence_refs:
                raise ValueError("Semantic association cannot carry Finding Evidence")

        matched = self.relation is not AttackPathAssociationRelation.UNMATCHED
        if matched and (
            (self.target_kind == "finding" and not self.finding_id)
            or (
                self.target_kind == "semantic_candidate"
                and not self.semantic_candidate_id
            )
        ):
            raise ValueError("matched association must name its target")
        if matched and not self.evidence_refs:
            raise ValueError("matched association requires graph Evidence")
        if self.target_kind == "finding" and matched and not self.finding_evidence_refs:
            raise ValueError("matched Finding association requires Finding Evidence")
        if (
            self.target_kind == "semantic_candidate"
            and matched
            and not self.semantic_evidence_refs
        ):
            raise ValueError("matched Semantic association requires Semantic Evidence")
        if not matched and (self.finding_evidence_refs or self.semantic_evidence_refs):
            raise ValueError("unmatched association cannot carry target Evidence")
        return self

    def sort_key(self) -> tuple[str, str, str, str]:
        target_id = self.finding_id or self.semantic_candidate_id or ""
        return (self.path_id, self.target_kind, target_id, self.relation.value)


# Semantic aliases keep the two report domains discoverable while sharing one
# strict row contract.  The producer still emits a single stable association
# model so callers can merge and sort rows without a second serialization shape.
AttackPathFindingAssociation = AttackPathEvidenceAssociation
AttackPathSemanticAssociation = AttackPathEvidenceAssociation


ATTACK_PATH_EVIDENCE_ASSOCIATION_LIMITATIONS: tuple[str, ...] = (
    "associations use only validated static locators and content digests",
    "Finding Evidence is eligible only when source_type is file or diff",
    "Semantic output remains candidate evidence and cannot create or mutate a Finding",
    (
        "a path is a static declared relation; runtime reachability and "
        "exploitability are not proven"
    ),
    (
        "association does not change Severity, Confidence, Policy, CI, "
        "Hard Gate, or release state"
    ),
    "reports contain no source excerpts, credentials, endpoints, or secret values",
)


class AttackPathEvidenceAssociationReport(_Strict):
    """Content-addressed, report-only association output."""

    format: Literal["agentsec-attack-path-evidence-association-report"] = (
        "agentsec-attack-path-evidence-association-report"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    graph_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    path_report_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    findings_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    semantic_result_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")] | None = (
        None
    )
    path_count: int = Field(ge=0, le=256)
    finding_count: int = Field(ge=0)
    semantic_candidate_count: int = Field(ge=0)
    associations: tuple[AttackPathEvidenceAssociation, ...]
    association_count: int = Field(ge=0)
    limitations: tuple[str, ...] = Field(
        max_length=ATTACK_PATH_ASSOCIATION_MAX_LIMITATIONS
    )
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    finding_authority: Literal[False] = False
    semantic_authority: Literal[False] = False
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    hard_gate_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> AttackPathEvidenceAssociationReport:
        if self.association_count != len(self.associations):
            raise ValueError("association count is inconsistent")
        keys = tuple(item.sort_key() for item in self.associations)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("associations must be sorted and unique")
        if not self.limitations:
            raise ValueError("association report must disclose limitations")
        return self

    @property
    def finding_associations(self) -> tuple[AttackPathEvidenceAssociation, ...]:
        """Return only path-to-Finding rows."""

        return tuple(
            item for item in self.associations if item.target_kind == "finding"
        )

    @property
    def semantic_associations(self) -> tuple[AttackPathEvidenceAssociation, ...]:
        """Return only path-to-Semantic Candidate rows."""

        return tuple(
            item
            for item in self.associations
            if item.target_kind == "semantic_candidate"
        )


def canonical_attack_path_evidence_association_sha256(
    report: AttackPathEvidenceAssociationReport,
) -> str:
    """Return the canonical digest of an association report."""

    if not isinstance(report, AttackPathEvidenceAssociationReport):
        raise TypeError(
            "association digest requires AttackPathEvidenceAssociationReport"
        )
    return _canonical_hash(report.model_dump(mode="json"))


class AttackPathEvidenceAssociator:
    """Join static path source locators to trusted Finding/Semantic Evidence."""

    def associate(
        self,
        graph: CapabilityAttackGraph,
        findings: tuple[Finding, ...] = (),
        semantic_result: SemanticAnalysisResult | None = None,
        semantic_evidence: tuple[SemanticEvidenceChunk, ...] = (),
    ) -> AttackPathEvidenceAssociationReport:
        from agentsec.semantic.models import (
            SemanticAnalysisResult,
            SemanticEvidenceChunk,
        )

        if not isinstance(graph, CapabilityAttackGraph):
            raise TypeError("association requires CapabilityAttackGraph")
        if not isinstance(findings, tuple) or any(
            not isinstance(item, Finding) for item in findings
        ):
            raise TypeError("findings must be a tuple of Finding")
        if semantic_result is not None and not isinstance(
            semantic_result, SemanticAnalysisResult
        ):
            raise TypeError("semantic_result must be SemanticAnalysisResult")
        if not isinstance(semantic_evidence, tuple) or any(
            not isinstance(item, SemanticEvidenceChunk) for item in semantic_evidence
        ):
            raise TypeError(
                "semantic_evidence must be a tuple of SemanticEvidenceChunk"
            )
        if semantic_result is None and semantic_evidence:
            raise ValueError("semantic Evidence requires a SemanticAnalysisResult")

        finding_by_id = self._index_findings(findings)
        semantic_by_id = self._index_semantic_evidence(semantic_evidence)
        paths = tuple(sorted(graph.paths, key=lambda item: item.path_id))
        associations: list[AttackPathEvidenceAssociation] = []

        for path in paths:
            graph_refs = _path_graph_evidence(graph, path)
            if not findings:
                associations.append(
                    self._unmatched_finding(path, graph_refs, no_input=True)
                )
            else:
                finding_matches = [
                    (finding, self._finding_match(path, graph_refs, finding))
                    for finding in finding_by_id.values()
                ]
                matched = [item for item in finding_matches if item[1] is not None]
                if matched:
                    for finding, match in matched:
                        assert match is not None
                        associations.append(
                            self._finding_association(path, graph_refs, finding, match)
                        )
                else:
                    associations.append(
                        self._unmatched_finding(path, graph_refs, no_input=False)
                    )

            if semantic_result is not None:
                for candidate in semantic_result.candidates:
                    chunks = tuple(
                        semantic_by_id[evidence_id]
                        for evidence_id in candidate.evidence_ids
                        if evidence_id in semantic_by_id
                    )
                    semantic_match = self._semantic_match(path, graph_refs, chunks)
                    if semantic_match is None:
                        basis = {
                            AttackPathAssociationBasis.NO_DETERMINISTIC_EVIDENCE_OVERLAP
                        }
                        if not chunks:
                            basis = {
                                AttackPathAssociationBasis.SEMANTIC_EVIDENCE_REFERENCE_UNAVAILABLE
                            }
                        associations.append(
                            AttackPathEvidenceAssociation(
                                path_id=path.path_id,
                                target_kind="semantic_candidate",
                                semantic_candidate_id=candidate.candidate_id,
                                relation=AttackPathAssociationRelation.UNMATCHED,
                                basis=tuple(sorted(basis, key=lambda item: item.value)),
                                evidence_refs=graph_refs,
                            )
                        )
                    else:
                        associations.append(
                            self._semantic_association(
                                path,
                                graph_refs,
                                candidate.candidate_id,
                                semantic_match,
                            )
                        )

        path_report = build_attack_path_report(graph)
        semantic_digest = (
            None
            if semantic_result is None
            else _canonical_hash(semantic_result.model_dump(mode="json"))
        )
        return AttackPathEvidenceAssociationReport(
            graph_sha256=canonical_attack_graph_sha256(graph),
            path_report_sha256=_canonical_hash(path_report.model_dump(mode="json")),
            findings_sha256=_canonical_hash(
                [item.model_dump(mode="json") for item in finding_by_id.values()]
            ),
            semantic_result_sha256=semantic_digest,
            path_count=len(paths),
            finding_count=len(findings),
            semantic_candidate_count=(
                0 if semantic_result is None else len(semantic_result.candidates)
            ),
            associations=tuple(sorted(associations, key=lambda item: item.sort_key())),
            association_count=len(associations),
            limitations=ATTACK_PATH_EVIDENCE_ASSOCIATION_LIMITATIONS,
        )

    @staticmethod
    def _index_findings(findings: tuple[Finding, ...]) -> dict[str, Finding]:
        indexed: dict[str, Finding] = {}
        for finding in findings:
            if finding.finding_id in indexed:
                raise ValueError("Finding IDs must be unique for association")
            indexed[finding.finding_id] = finding
        return dict(sorted(indexed.items()))

    @staticmethod
    def _index_semantic_evidence(
        evidence: tuple[SemanticEvidenceChunk, ...],
    ) -> dict[str, SemanticEvidenceChunk]:
        indexed: dict[str, SemanticEvidenceChunk] = {}
        for chunk in evidence:
            if chunk.evidence_id in indexed:
                raise ValueError("Semantic Evidence IDs must be unique for association")
            indexed[chunk.evidence_id] = chunk
        return indexed

    @staticmethod
    def _finding_match(
        path: AttackGraphPath,
        graph_refs: tuple[AttackPathGraphEvidenceRef, ...],
        finding: Finding,
    ) -> (
        tuple[
            tuple[AttackPathFindingEvidenceRef, ...],
            tuple[AttackPathAssociationBasis, ...],
            bool,
        ]
        | None
    ):
        del path
        eligible = tuple(
            item
            for item in finding.evidence
            if item.source_type in (EvidenceSource.FILE, EvidenceSource.DIFF)
            and item.asset_path is not None
            and item.content_sha256 is not None
            and item.start_line is not None
            and item.end_line is not None
        )
        matches: list[AttackPathFindingEvidenceRef] = []
        covered = 0
        exact = True
        for graph_ref in graph_refs:
            overlapping = tuple(
                item
                for item in eligible
                if _locators_overlap(
                    graph_ref.source.asset_path,
                    graph_ref.source.asset_sha256,
                    graph_ref.source.start_line,
                    graph_ref.source.end_line,
                    item.asset_path,
                    item.content_sha256,
                    item.start_line,
                    item.end_line,
                )
            )
            if overlapping:
                covered += 1
                exact = exact and any(
                    item.start_line == graph_ref.source.start_line
                    and item.end_line == graph_ref.source.end_line
                    for item in overlapping
                )
                matches.extend(_finding_evidence_ref(item) for item in overlapping)
        if not graph_refs or not covered:
            return None
        unique_matches = tuple(
            sorted(
                {item.sort_key(): item for item in matches}.values(),
                key=lambda item: item.sort_key(),
            )
        )
        basis = _positive_basis(graph_refs, covered, exact)
        return unique_matches, basis, covered == len(graph_refs) and exact

    @staticmethod
    def _semantic_match(
        path: AttackGraphPath,
        graph_refs: tuple[AttackPathGraphEvidenceRef, ...],
        chunks: tuple[SemanticEvidenceChunk, ...],
    ) -> (
        tuple[
            tuple[AttackPathSemanticEvidenceRef, ...],
            tuple[AttackPathAssociationBasis, ...],
            bool,
        ]
        | None
    ):
        del path
        matches: list[AttackPathSemanticEvidenceRef] = []
        covered = 0
        exact = True
        for graph_ref in graph_refs:
            overlapping = tuple(
                chunk
                for chunk in chunks
                if _locators_overlap(
                    graph_ref.source.asset_path,
                    graph_ref.source.asset_sha256,
                    graph_ref.source.start_line,
                    graph_ref.source.end_line,
                    chunk.asset_path,
                    chunk.asset_sha256,
                    chunk.start_line,
                    chunk.end_line,
                )
            )
            if overlapping:
                covered += 1
                exact = exact and any(
                    chunk.start_line == graph_ref.source.start_line
                    and chunk.end_line == graph_ref.source.end_line
                    for chunk in overlapping
                )
                matches.extend(_semantic_evidence_ref(chunk) for chunk in overlapping)
        if not graph_refs or not covered:
            return None
        unique_matches = tuple(
            sorted(
                {item.sort_key(): item for item in matches}.values(),
                key=lambda item: item.sort_key(),
            )
        )
        return (
            unique_matches,
            _positive_basis(graph_refs, covered, exact),
            covered == len(graph_refs) and exact,
        )

    @staticmethod
    def _finding_association(
        path: AttackGraphPath,
        graph_refs: tuple[AttackPathGraphEvidenceRef, ...],
        finding: Finding,
        match: tuple[
            tuple[AttackPathFindingEvidenceRef, ...],
            tuple[AttackPathAssociationBasis, ...],
            bool,
        ],
    ) -> AttackPathEvidenceAssociation:
        evidence, basis, exact = match
        return AttackPathEvidenceAssociation(
            path_id=path.path_id,
            target_kind="finding",
            finding_id=finding.finding_id,
            relation=(
                AttackPathAssociationRelation.DUPLICATES
                if exact
                else (
                    AttackPathAssociationRelation.SUPPORTS
                    if AttackPathAssociationBasis.PARTIAL_EVIDENCE_OVERLAP not in basis
                    else AttackPathAssociationRelation.PARTIALLY_SUPPORTS
                )
            ),
            basis=basis,
            evidence_refs=graph_refs,
            finding_evidence_refs=evidence,
        )

    @staticmethod
    def _semantic_association(
        path: AttackGraphPath,
        graph_refs: tuple[AttackPathGraphEvidenceRef, ...],
        candidate_id: str,
        match: tuple[
            tuple[AttackPathSemanticEvidenceRef, ...],
            tuple[AttackPathAssociationBasis, ...],
            bool,
        ],
    ) -> AttackPathEvidenceAssociation:
        evidence, basis, exact = match
        return AttackPathEvidenceAssociation(
            path_id=path.path_id,
            target_kind="semantic_candidate",
            semantic_candidate_id=candidate_id,
            relation=(
                AttackPathAssociationRelation.DUPLICATES
                if exact
                else (
                    AttackPathAssociationRelation.SUPPORTS
                    if AttackPathAssociationBasis.PARTIAL_EVIDENCE_OVERLAP not in basis
                    else AttackPathAssociationRelation.PARTIALLY_SUPPORTS
                )
            ),
            basis=basis,
            evidence_refs=graph_refs,
            semantic_evidence_refs=evidence,
        )

    @staticmethod
    def _unmatched_finding(
        path: AttackGraphPath,
        graph_refs: tuple[AttackPathGraphEvidenceRef, ...],
        *,
        no_input: bool,
    ) -> AttackPathEvidenceAssociation:
        basis = (
            (AttackPathAssociationBasis.GRAPH_SOURCE_UNAVAILABLE,)
            if not graph_refs
            else (
                (AttackPathAssociationBasis.NO_DETERMINISTIC_EVIDENCE_OVERLAP,)
                if not no_input
                else (AttackPathAssociationBasis.FINDING_EVIDENCE_NOT_STATIC,)
            )
        )
        return AttackPathEvidenceAssociation(
            path_id=path.path_id,
            target_kind="finding",
            relation=AttackPathAssociationRelation.UNMATCHED,
            basis=basis,
            evidence_refs=graph_refs,
        )


def _path_graph_evidence(
    graph: CapabilityAttackGraph, path: AttackGraphPath
) -> tuple[AttackPathGraphEvidenceRef, ...]:
    nodes = {item.node_id: item for item in graph.nodes}
    edges = {item.edge_id: item for item in graph.edges}
    roles: dict[tuple[str, str, int, int], set[Literal["node", "edge"]]] = {}
    sources: dict[tuple[str, str, int, int], AttackGraphSourceRef] = {}
    for node_id in path.node_sequence:
        for source in nodes[node_id].sources:
            key = source.sort_key()
            roles.setdefault(key, set()).add("node")
            sources[key] = source
    for edge_id in path.edge_sequence:
        for source in edges[edge_id].sources:
            key = source.sort_key()
            roles.setdefault(key, set()).add("edge")
            sources[key] = source
    return tuple(
        AttackPathGraphEvidenceRef(
            source=sources[key],
            roles=tuple(sorted(roles[key])),
        )
        for key in sorted(sources)
    )


def _locators_overlap(
    left_path: str,
    left_hash: str,
    left_start: int,
    left_end: int,
    right_path: str | None,
    right_hash: str | None,
    right_start: int | None,
    right_end: int | None,
) -> bool:
    return (
        right_path == left_path
        and right_hash == left_hash
        and right_start is not None
        and right_end is not None
        and not (left_end < right_start or right_end < left_start)
    )


def _positive_basis(
    graph_refs: tuple[AttackPathGraphEvidenceRef, ...], covered: int, exact: bool
) -> tuple[AttackPathAssociationBasis, ...]:
    basis = {
        AttackPathAssociationBasis.ASSET_PATH,
        AttackPathAssociationBasis.ASSET_SHA256,
        AttackPathAssociationBasis.LINE_OVERLAP,
    }
    if any("node" in item.roles for item in graph_refs):
        basis.add(AttackPathAssociationBasis.GRAPH_NODE_SOURCE)
    if any("edge" in item.roles for item in graph_refs):
        basis.add(AttackPathAssociationBasis.GRAPH_EDGE_SOURCE)
    if exact and covered == len(graph_refs):
        basis.add(AttackPathAssociationBasis.EXACT_LOCATOR)
    elif covered < len(graph_refs):
        basis.add(AttackPathAssociationBasis.PARTIAL_EVIDENCE_OVERLAP)
    return tuple(sorted(basis, key=lambda item: item.value))


def _finding_evidence_ref(value: Evidence) -> AttackPathFindingEvidenceRef:
    """Project one validated static Finding Evidence item without its excerpt."""

    if (
        value.source_type not in (EvidenceSource.FILE, EvidenceSource.DIFF)
        or value.asset_path is None
        or value.content_sha256 is None
        or value.start_line is None
        or value.end_line is None
    ):
        raise ValueError("only complete static Finding Evidence can be projected")
    return AttackPathFindingEvidenceRef(
        source_type=value.source_type,
        asset_path=value.asset_path,
        content_sha256=value.content_sha256,
        start_line=value.start_line,
        end_line=value.end_line,
    )


def _semantic_evidence_ref(
    chunk: SemanticEvidenceChunk,
) -> AttackPathSemanticEvidenceRef:
    return AttackPathSemanticEvidenceRef(
        evidence_id=chunk.evidence_id,
        asset_path=chunk.asset_path,
        asset_sha256=chunk.asset_sha256,
        start_line=chunk.start_line,
        end_line=chunk.end_line,
    )


def encode_attack_path_evidence_association_json(
    report: AttackPathEvidenceAssociationReport,
) -> str:
    """Encode a validated association report as canonical JSON."""

    if not isinstance(report, AttackPathEvidenceAssociationReport):
        raise TypeError(
            "association encoder requires AttackPathEvidenceAssociationReport"
        )
    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_attack_path_evidence_association_text(
    report: AttackPathEvidenceAssociationReport,
) -> str:
    """Render a bounded, boundary-first association summary."""

    if not isinstance(report, AttackPathEvidenceAssociationReport):
        raise TypeError(
            "association renderer requires AttackPathEvidenceAssociationReport"
        )
    lines = [
        "AgentSec Attack Path Evidence Association Report",
        f"Format: {report.format} {report.schema_version}",
        f"Paths: {report.path_count}",
        f"Associations: {report.association_count}",
    ]
    for item in report.associations:
        target = item.finding_id or item.semantic_candidate_id or "none"
        lines.append(
            f"- {item.path_id} -> {item.target_kind}:{target} "
            f"[{item.relation.value}] graph_evidence={len(item.evidence_refs)}"
        )
    lines.extend(
        (
            (
                "Mode: report_only=true; blocks=false; finding/semantic/policy/CI/"
                "Hard-Gate/release authority=false"
            ),
            (
                "Boundary: static locator correlation only; runtime_verified=false; "
                "reachability/exploitability=not_proven"
            ),
            (
                "No Finding, Semantic Candidate, Severity, Confidence, Rule, or "
                "Policy mutation occurred."
            ),
        )
    )
    return "\n".join(lines) + "\n"


def export_attack_path_evidence_association_json_schema(output_path: Path) -> Path:
    """Export the association report JSON Schema."""

    if not isinstance(output_path, Path):
        raise TypeError("association Schema output path must be a Path")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            AttackPathEvidenceAssociationReport.model_json_schema(mode="serialization"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path


def _canonical_hash(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "ATTACK_PATH_EVIDENCE_ASSOCIATION_FORMAT",
    "ATTACK_PATH_EVIDENCE_ASSOCIATION_LIMITATIONS",
    "ATTACK_PATH_EVIDENCE_ASSOCIATION_VERSION",
    "AttackPathAssociationBasis",
    "AttackPathAssociationRelation",
    "AttackPathEvidenceAssociation",
    "AttackPathFindingAssociation",
    "AttackPathSemanticAssociation",
    "AttackPathEvidenceAssociationReport",
    "AttackPathEvidenceAssociator",
    "AttackPathFindingEvidenceRef",
    "AttackPathGraphEvidenceRef",
    "AttackPathSemanticEvidenceRef",
    "canonical_attack_path_evidence_association_sha256",
    "encode_attack_path_evidence_association_json",
    "export_attack_path_evidence_association_json_schema",
    "render_attack_path_evidence_association_text",
]
