"""Tests for P1-19 deterministic rule execution and Finding pipeline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from agentsec.domain import (
    AgentAsset,
    AssetSource,
    AssetType,
    CoverageIssue,
    CoverageIssueCode,
    FindingCategory,
    ScanCoverage,
)
from agentsec.parsers import MarkdownItParser
from agentsec.rules import (
    DeterministicRuleRunner,
    KeywordRule,
    RuleContext,
    RuleEvaluation,
    RuleEvidenceCandidate,
    RuleFailure,
    RuleFindingCandidate,
    RuleMetadata,
    RulePipelineError,
    RuleRegistryError,
    RuleScope,
    RuleTarget,
    UnscoredFinding,
    merge_rule_coverage,
)


def make_context(
    content: str,
    *,
    path: str = "AGENTS.md",
    asset_type: AssetType = AssetType.AGENTS,
) -> RuleContext:
    """Build one coherent parsed rule context."""

    content_bytes = content.encode("utf-8")
    return RuleContext(
        asset=AgentAsset(
            path=path,
            asset_type=asset_type,
            source=AssetSource.DISCOVERED,
            sha256=hashlib.sha256(content_bytes).hexdigest(),
            size_bytes=len(content_bytes),
            line_count=len(content.splitlines()),
        ),
        content=content,
        document=MarkdownItParser().parse(content),
    )


def make_metadata(
    rule_id: str,
    *,
    category: FindingCategory = FindingCategory.CODE_EXECUTION,
) -> RuleMetadata:
    """Build stable trusted metadata for pipeline tests."""

    return RuleMetadata(
        rule_id=rule_id,
        title=f"Rule {rule_id}",
        description="Detects one deterministic test condition.",
        category=category,
        recommendations=("Review the source-backed declaration.",),
        scope=RuleScope.all_markdown(RuleTarget.MARKDOWN_BLOCK),
    )


def make_keyword_rule(rule_id: str, keyword: str) -> KeywordRule:
    """Build one concrete matcher adapter."""

    return KeywordRule(make_metadata(rule_id), keywords=(keyword,))


@dataclass(frozen=True, slots=True)
class ExplodingRule:
    """Rule adapter that raises attacker-controlled exception text."""

    metadata: RuleMetadata

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Raise without letting the runner report source or exception details."""

        raise RuntimeError(f"secret failure: {context.content}")


@dataclass(frozen=True, slots=True)
class InvalidReturnRule:
    """Rule adapter violating the evaluation return contract."""

    metadata: RuleMetadata

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Return an invalid object for isolation testing."""

        del context
        return "not-an-evaluation"  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class CandidateRule:
    """Rule adapter returning caller-supplied candidates."""

    metadata: RuleMetadata
    evaluation: RuleEvaluation

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Return deterministic test candidates."""

        del context
        return self.evaluation


class BrokenMetadataRule:
    """Registry adapter whose metadata property is unsafe."""

    @property
    def metadata(self) -> RuleMetadata:
        """Raise an exception containing text that must not escape."""

        raise RuntimeError("registry-secret-value")

    def evaluate(self, context: RuleContext) -> RuleEvaluation:
        """Remain unreachable because registry validation fails first."""

        del context
        return RuleEvaluation()


def test_runner_materializes_trusted_metadata_and_domain_evidence() -> None:
    """Rule candidates become deterministic unscored Findings with trusted fields."""

    context = make_context("Execute the shell command.\n")
    runner = DeterministicRuleRunner(
        (make_keyword_rule("MD-EXEC-001", "shell command"),)
    )

    result = runner.run((context,))
    finding = result.findings[0]

    assert result.complete is True
    assert result.failures == ()
    assert finding.finding_id.startswith("finding-sha256:")
    assert len(finding.finding_id.removeprefix("finding-sha256:")) == 64
    assert finding.rule_id == "MD-EXEC-001"
    assert finding.category is FindingCategory.CODE_EXECUTION
    assert finding.title == "Rule MD-EXEC-001"
    assert finding.evidence[0].asset_path == "AGENTS.md"
    assert finding.evidence[0].start_line == 1
    assert finding.evidence[0].content_sha256 == context.asset.sha256
    assert finding.recommendations == ("Review the source-backed declaration.",)
    assert not hasattr(finding, "severity")
    assert not hasattr(finding, "confidence")


def test_output_and_finding_ids_are_independent_of_input_order() -> None:
    """Rule and context ordering cannot change the materialized result."""

    agents = make_context("shell access\nnetwork access\n")
    skill = make_context(
        "network access\nshell access\n",
        path="skills/release/SKILL.md",
        asset_type=AssetType.SKILL,
    )
    shell_rule = make_keyword_rule("MD-EXEC-001", "shell")
    network_rule = KeywordRule(
        make_metadata("MD-NET-001", category=FindingCategory.NETWORK_ACCESS),
        keywords=("network",),
    )

    first = DeterministicRuleRunner((network_rule, shell_rule)).run((skill, agents))
    second = DeterministicRuleRunner((shell_rule, network_rule)).run((agents, skill))

    assert first == second
    assert [(item.rule_id, item.evidence[0].asset_path) for item in first.findings] == [
        ("MD-EXEC-001", "AGENTS.md"),
        ("MD-EXEC-001", "skills/release/SKILL.md"),
        ("MD-NET-001", "AGENTS.md"),
        ("MD-NET-001", "skills/release/SKILL.md"),
    ]


def test_one_rule_failure_does_not_discard_other_rule_findings() -> None:
    """Each rule×asset evaluation has an independent exception boundary."""

    context = make_context("token: sensitive-value\nshell command\n")
    runner = DeterministicRuleRunner(
        (
            ExplodingRule(make_metadata("MD-FAIL-001")),
            make_keyword_rule("MD-EXEC-001", "shell command"),
        )
    )

    result = runner.run((context,))

    assert [finding.rule_id for finding in result.findings] == ["MD-EXEC-001"]
    assert result.complete is False
    assert result.failures == (RuleFailure("MD-FAIL-001", "AGENTS.md"),)
    assert result.coverage_issues == (
        CoverageIssue(
            code=CoverageIssueCode.RULE_ERROR,
            message="Rule MD-FAIL-001 failed safely.",
            asset_path="AGENTS.md",
        ),
    )
    assert "sensitive-value" not in repr(result)
    assert "sensitive-value" not in result.coverage_issues[0].message


def test_invalid_return_and_candidate_materialization_are_isolated() -> None:
    """Return-contract and evidence-contract violations become safe failures."""

    context = make_context("secret token value\nshell command\n")
    invalid_evidence = RuleEvaluation(
        candidates=(
            RuleFindingCandidate(
                evidence=(
                    RuleEvidenceCandidate(
                        start_line=1,
                        end_line=1,
                        excerpt="not present in source",
                    ),
                )
            ),
        )
    )
    runner = DeterministicRuleRunner(
        (
            InvalidReturnRule(make_metadata("MD-FAIL-001")),
            CandidateRule(make_metadata("MD-FAIL-002"), invalid_evidence),
            make_keyword_rule("MD-EXEC-001", "shell command"),
        )
    )

    result = runner.run((context,))

    assert [finding.rule_id for finding in result.findings] == ["MD-EXEC-001"]
    assert [(item.rule_id, item.asset_path) for item in result.failures] == [
        ("MD-FAIL-001", "AGENTS.md"),
        ("MD-FAIL-002", "AGENTS.md"),
    ]
    assert "secret token value" not in repr(result)


def test_rule_context_execution_is_atomic_when_one_candidate_is_invalid() -> None:
    """A failed candidate discards earlier results from the same rule and asset."""

    context = make_context("shell command\nsecret token\n")
    mixed = RuleEvaluation(
        candidates=(
            RuleFindingCandidate(
                evidence=(RuleEvidenceCandidate(start_line=1, end_line=1),)
            ),
            RuleFindingCandidate(
                evidence=(
                    RuleEvidenceCandidate(
                        start_line=2,
                        end_line=2,
                        excerpt="spoofed excerpt",
                    ),
                )
            ),
        )
    )
    runner = DeterministicRuleRunner(
        (CandidateRule(make_metadata("MD-EXEC-001"), mixed),)
    )

    result = runner.run((context,))

    assert result.findings == ()
    assert result.failures == (RuleFailure("MD-EXEC-001", "AGENTS.md"),)


def test_same_rule_can_fail_on_one_asset_and_succeed_on_another() -> None:
    """Isolation is per asset rather than disabling a rule globally."""

    safe = make_context("safe text\n", path="AGENTS.md")
    risky = make_context(
        "shell command\n",
        path="skills/deploy/SKILL.md",
        asset_type=AssetType.SKILL,
    )

    @dataclass(frozen=True, slots=True)
    class PathSensitiveRule:
        metadata: RuleMetadata

        def evaluate(self, context: RuleContext) -> RuleEvaluation:
            if context.asset.path == "AGENTS.md":
                raise RuntimeError("asset-specific failure")
            return RuleEvaluation(
                candidates=(
                    RuleFindingCandidate(
                        evidence=(RuleEvidenceCandidate(start_line=1, end_line=1),)
                    ),
                )
            )

    result = DeterministicRuleRunner(
        (PathSensitiveRule(make_metadata("MD-EXEC-001")),)
    ).run((risky, safe))

    assert [item.evidence[0].asset_path for item in result.findings] == [
        "skills/deploy/SKILL.md"
    ]
    assert result.failures == (RuleFailure("MD-EXEC-001", "AGENTS.md"),)


def test_finding_dedup_ignores_excerpt_representation_for_same_locator() -> None:
    """Equivalent locators collapse while retaining a useful exact excerpt."""

    context = make_context("shell command\n")
    evaluation = RuleEvaluation(
        candidates=(
            RuleFindingCandidate(
                evidence=(RuleEvidenceCandidate(start_line=1, end_line=1),)
            ),
            RuleFindingCandidate(
                evidence=(
                    RuleEvidenceCandidate(
                        start_line=1,
                        end_line=1,
                        excerpt="shell command",
                    ),
                )
            ),
        )
    )
    runner = DeterministicRuleRunner(
        (CandidateRule(make_metadata("MD-EXEC-001"), evaluation),)
    )

    result = runner.run((context,))

    assert len(result.findings) == 1
    assert result.findings[0].evidence[0].excerpt == "shell command"


def test_different_rule_ids_at_same_location_remain_separate_findings() -> None:
    """Deduplication never erases distinct stable Rule meanings."""

    context = make_context("shell network action\n")
    first = make_keyword_rule("MD-EXEC-001", "shell")
    second = KeywordRule(
        make_metadata("MD-NET-001", category=FindingCategory.NETWORK_ACCESS),
        keywords=("network",),
    )

    result = DeterministicRuleRunner((second, first)).run((context,))

    assert len(result.findings) == 2
    assert result.findings[0].finding_id != result.findings[1].finding_id


def test_duplicate_rule_ids_and_broken_metadata_fail_registry_safely() -> None:
    """A corrupt trusted rule registry is rejected before project evaluation."""

    with pytest.raises(RuleRegistryError, match="registry"):
        DeterministicRuleRunner(
            (
                make_keyword_rule("MD-EXEC-001", "shell"),
                make_keyword_rule("MD-EXEC-001", "exec"),
            )
        )

    with pytest.raises(RuleRegistryError, match="registry") as captured:
        DeterministicRuleRunner((BrokenMetadataRule(),))
    assert "registry-secret-value" not in str(captured.value)


def test_runner_rejects_non_tuple_and_duplicate_context_paths() -> None:
    """Input context identity must be immutable and unambiguous."""

    runner = DeterministicRuleRunner(())
    context = make_context("safe\n")

    with pytest.raises(TypeError, match="tuple"):
        runner.run([context])  # type: ignore[arg-type]
    with pytest.raises(RulePipelineError, match="contexts"):
        runner.run((context, context))


def test_empty_rule_registry_returns_complete_empty_result() -> None:
    """The pre-P1-20 empty rule pack is a valid deterministic pipeline state."""

    contexts = (
        make_context("safe\n", path="AGENTS.md"),
        make_context(
            "safe\n",
            path="skills/review/SKILL.md",
            asset_type=AssetType.SKILL,
        ),
    )

    result = DeterministicRuleRunner(()).run(tuple(reversed(contexts)))

    assert result.complete is True
    assert result.findings == ()
    assert result.failures == ()
    assert result.evaluated_asset_paths == (
        "AGENTS.md",
        "skills/review/SKILL.md",
    )


def test_merge_rule_coverage_counts_each_failed_asset_once() -> None:
    """Multiple failed rules make one asset incomplete without double-counting it."""

    base = ScanCoverage(
        discovered_assets=2,
        scanned_assets=2,
        skipped_assets=0,
        complete=True,
    )
    context_a = make_context("unsafe\n", path="AGENTS.md")
    context_b = make_context(
        "safe\n",
        path="skills/review/SKILL.md",
        asset_type=AssetType.SKILL,
    )
    result = DeterministicRuleRunner(
        (
            ExplodingRule(make_metadata("MD-FAIL-001")),
            ExplodingRule(make_metadata("MD-FAIL-002")),
        )
    ).run((context_b, context_a))

    merged = merge_rule_coverage(base, result)

    assert merged.discovered_assets == 2
    assert merged.scanned_assets == 0
    assert merged.skipped_assets == 2
    assert merged.complete is False
    assert len(merged.issues) == 4
    assert {issue.code for issue in merged.issues} == {CoverageIssueCode.RULE_ERROR}


def test_merge_preserves_existing_coverage_and_adds_rule_failures() -> None:
    """Parser/collector issues remain visible when rule coverage is merged."""

    base = ScanCoverage(
        discovered_assets=2,
        scanned_assets=1,
        skipped_assets=1,
        complete=False,
        issues=(
            CoverageIssue(
                code=CoverageIssueCode.PARSE_ERROR,
                message="Markdown parsing failed safely.",
                asset_path="broken/AGENTS.md",
            ),
        ),
    )
    context = make_context("unsafe\n")
    result = DeterministicRuleRunner(
        (ExplodingRule(make_metadata("MD-FAIL-001")),)
    ).run((context,))

    merged = merge_rule_coverage(base, result)

    assert merged.discovered_assets == 2
    assert merged.scanned_assets == 0
    assert merged.skipped_assets == 2
    assert [issue.code for issue in merged.issues] == [
        CoverageIssueCode.RULE_ERROR,
        CoverageIssueCode.PARSE_ERROR,
    ]


def test_merge_rejects_context_count_that_does_not_match_scanned_coverage() -> None:
    """Coverage cannot be adjusted against a partial or unrelated context set."""

    coverage = ScanCoverage(
        discovered_assets=2,
        scanned_assets=2,
        skipped_assets=0,
        complete=True,
    )
    result = DeterministicRuleRunner(()).run((make_context("safe\n"),))

    with pytest.raises(RulePipelineError, match="coverage"):
        merge_rule_coverage(coverage, result)


def test_unscored_finding_repr_does_not_copy_evidence_excerpt() -> None:
    """Accidental object logging cannot disclose retained unredacted evidence."""

    context = make_context("token: highly-sensitive-value\n")
    result = DeterministicRuleRunner(
        (make_keyword_rule("MD-SECRET-001", "highly-sensitive-value"),)
    ).run((context,))

    finding = result.findings[0]

    assert isinstance(finding, UnscoredFinding)
    assert "highly-sensitive-value" not in repr(finding)
    assert "highly-sensitive-value" not in repr(result)
