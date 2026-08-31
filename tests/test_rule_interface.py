"""Contract tests for the P1-17 deterministic Rule interface."""

from __future__ import annotations

import hashlib
from dataclasses import fields

import pytest

from agentsec.domain import (
    AgentAsset,
    AssetSource,
    AssetType,
    EvidenceSource,
    FindingCategory,
)
from agentsec.parsers import MarkdownItParser
from agentsec.rules import (
    Rule,
    RuleContext,
    RuleContractError,
    RuleEvaluation,
    RuleEvaluationError,
    RuleEvidenceCandidate,
    RuleFindingCandidate,
    RuleMetadata,
    RuleScope,
    RuleTarget,
)


def make_context(
    content: str = "# Deployment\n\nRun the release command.\n",
) -> RuleContext:
    """Build one coherent, source-backed rule context."""

    content_bytes = content.encode("utf-8")
    asset = AgentAsset(
        path="skills/release/SKILL.md",
        asset_type=AssetType.SKILL,
        source=AssetSource.DISCOVERED,
        sha256=hashlib.sha256(content_bytes).hexdigest(),
        size_bytes=len(content_bytes),
        line_count=len(content.splitlines()),
    )
    return RuleContext(
        asset=asset,
        content=content,
        document=MarkdownItParser().parse(content),
    )


def make_metadata() -> RuleMetadata:
    """Build stable metadata without any risk-scoring fields."""

    return RuleMetadata(
        rule_id="MD-EXEC-001",
        title="Executable command declaration",
        description="Detects declarations that may allow command execution.",
        category=FindingCategory.CODE_EXECUTION,
        recommendations=("Require explicit human approval before execution.",),
        scope=RuleScope(
            asset_types=frozenset({AssetType.AGENTS, AssetType.SKILL}),
            targets=frozenset({RuleTarget.MARKDOWN_BLOCK}),
        ),
    )


def make_evaluation() -> RuleEvaluation:
    """Build one source-ordered candidate evaluation."""

    return RuleEvaluation(
        candidates=(
            RuleFindingCandidate(
                evidence=(
                    RuleEvidenceCandidate(
                        start_line=3,
                        end_line=3,
                        excerpt="Run the release command.",
                    ),
                )
            ),
        )
    )


class StaticRule:
    """Test adapter proving the structural Protocol seam."""

    @property
    def metadata(self) -> RuleMetadata:
        """Return immutable rule metadata."""

        return make_metadata()

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Return deterministic test output without side effects."""

        del context
        return make_evaluation()


def test_rule_protocol_is_structural_and_has_one_evaluation_method() -> None:
    """Adapters satisfy the Protocol without inheriting scanner implementation."""

    rule = StaticRule()

    assert isinstance(rule, Rule)
    assert rule.metadata.rule_id == "MD-EXEC-001"
    assert rule.evaluate(make_context()) == make_evaluation()


def test_rule_metadata_requires_stable_identity_and_determinism() -> None:
    """Rule identity cannot be ambiguous or opt out of deterministic behavior."""

    metadata = make_metadata()
    assert metadata.deterministic is True

    for invalid_rule_id in (
        "md-exec-001",
        "MD-001",
        "MD-EXEC-1",
        "MD_EXEC_001",
        "MD-EXEC-001-RENAMED",
    ):
        with pytest.raises(ValueError, match="Rule ID"):
            RuleMetadata(
                rule_id=invalid_rule_id,
                title=metadata.title,
                description=metadata.description,
                category=metadata.category,
                recommendations=metadata.recommendations,
                scope=metadata.scope,
            )

    with pytest.raises(ValueError, match="deterministic"):
        RuleMetadata(
            rule_id=metadata.rule_id,
            title=metadata.title,
            description=metadata.description,
            category=metadata.category,
            recommendations=metadata.recommendations,
            scope=metadata.scope,
            deterministic=False,  # type: ignore[arg-type]
        )


def test_rule_scope_is_explicit_non_empty_and_applicable_by_asset_type() -> None:
    """The host can skip rules outside their declared Phase 1 scope."""

    scope = make_metadata().scope

    assert scope.applies_to(AssetType.AGENTS)
    assert scope.applies_to(AssetType.SKILL)
    assert not scope.applies_to(AssetType.AGENTS_OVERRIDE)

    with pytest.raises(ValueError, match="asset type"):
        RuleScope(
            asset_types=frozenset(),
            targets=frozenset({RuleTarget.MARKDOWN_BLOCK}),
        )

    with pytest.raises(ValueError, match="target"):
        RuleScope(
            asset_types=frozenset({AssetType.AGENTS}),
            targets=frozenset(),
        )


def test_rule_context_is_coherent_and_exposes_no_execution_dependencies() -> None:
    """Rules receive only bounded parsed data, never filesystem or tool handles."""

    context = make_context()
    public_fields = {
        item.name for item in fields(RuleContext) if not item.name.startswith("_")
    }

    assert public_fields == {"asset", "content", "document"}
    assert context.source_text(1, 1) == "# Deployment\n"
    assert context.source_text(3, 3) == "Run the release command.\n"
    assert "Run the release command" not in repr(context)


def test_rule_context_rejects_mismatched_hash_size_lines_and_document() -> None:
    """A rule cannot evaluate content under stale asset or parser provenance."""

    context = make_context()

    with pytest.raises(ValueError, match="SHA-256"):
        RuleContext(
            asset=context.asset.model_copy(update={"sha256": "0" * 64}),
            content=context.content,
            document=context.document,
        )

    with pytest.raises(ValueError, match="byte size"):
        RuleContext(
            asset=context.asset.model_copy(update={"size_bytes": 1}),
            content=context.content,
            document=context.document,
        )

    with pytest.raises(ValueError, match="line count"):
        RuleContext(
            asset=context.asset.model_copy(update={"line_count": 1}),
            content=context.content,
            document=context.document,
        )

    other_document = MarkdownItParser().parse("one line")
    with pytest.raises(ValueError, match="parsed document"):
        RuleContext(
            asset=context.asset,
            content=context.content,
            document=other_document,
        )


def test_evidence_candidate_binds_path_hash_and_exact_source_range() -> None:
    """Rules propose local evidence; the host binds authoritative provenance."""

    context = make_context()
    candidate = make_evaluation().candidates[0]

    evidence = candidate.materialize_evidence(context)

    assert len(evidence) == 1
    assert evidence[0].source_type is EvidenceSource.FILE
    assert evidence[0].asset_path == context.asset.path
    assert evidence[0].content_sha256 == context.asset.sha256
    assert evidence[0].start_line == 3
    assert evidence[0].end_line == 3
    assert evidence[0].excerpt == "Run the release command."


def test_evidence_candidate_rejects_spoofed_or_out_of_range_evidence() -> None:
    """Candidate evidence cannot invent a source excerpt or line location."""

    context = make_context("token: super-secret-value\n")

    spoofed = RuleEvidenceCandidate(
        start_line=1,
        end_line=1,
        excerpt="safe replacement text",
    )
    with pytest.raises(RuleContractError, match="source range") as captured:
        spoofed.materialize(context)
    assert "super-secret-value" not in str(captured.value)

    out_of_range = RuleEvidenceCandidate(start_line=2, end_line=2)
    with pytest.raises(RuleContractError, match="line range"):
        out_of_range.materialize(context)

    secret_field = RuleEvidenceCandidate(
        start_line=1,
        end_line=1,
        field="super-secret-value",
    )
    assert "super-secret-value" not in repr(spoofed)
    assert "super-secret-value" not in repr(secret_field)


def test_candidate_and_evaluation_require_source_ordered_unique_tuples() -> None:
    """Output ordering is part of deterministic Rule behavior."""

    first = RuleEvidenceCandidate(start_line=1, end_line=1)
    second = RuleEvidenceCandidate(start_line=3, end_line=3)

    with pytest.raises(ValueError, match="source order"):
        RuleFindingCandidate(evidence=(second, first))

    candidate = RuleFindingCandidate(evidence=(first,))
    with pytest.raises(ValueError, match="unique"):
        RuleEvaluation(candidates=(candidate, candidate))

    with pytest.raises(TypeError, match="tuple"):
        RuleEvaluation(candidates=[candidate])  # type: ignore[arg-type]


def test_rule_interface_does_not_assign_risk_scores_or_confidence() -> None:
    """P1-17 candidates remain separate from later scoring and confidence."""

    prohibited = {
        "likelihood",
        "impact",
        "severity",
        "score",
        "confidence",
        "hard_gate",
    }

    assert prohibited.isdisjoint({item.name for item in fields(RuleMetadata)})
    assert prohibited.isdisjoint({item.name for item in fields(RuleFindingCandidate)})
    assert prohibited.isdisjoint({item.name for item in fields(RuleEvidenceCandidate)})


def test_rule_evaluation_error_has_a_fixed_safe_message() -> None:
    """Expected rule failures cannot copy untrusted source into an exception."""

    error = RuleEvaluationError()

    assert str(error) == "Rule evaluation failed safely."
