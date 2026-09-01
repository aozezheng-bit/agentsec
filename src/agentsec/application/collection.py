"""Complete deterministic Phase 1 Markdown assessment orchestration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from agentsec.application.assessment import AssessmentAnalysisError, AssessmentRequest
from agentsec.collectors import AssetCollector, CollectedAsset
from agentsec.domain import (
    Assessment,
    AssessmentMetadata,
    CoverageIssue,
    CoverageIssueCode,
    Finding,
    ScanCoverage,
)
from agentsec.parsers import MarkdownItParser, MarkdownParser, ParsedMarkdown
from agentsec.risk import (
    ConfidenceEngine,
    DeterministicConfidenceEngine,
    DeterministicHardGateEngine,
    DeterministicRiskEngine,
    HardGateEngine,
    RiskEngine,
)
from agentsec.rules import (
    DeterministicRuleRunner,
    RuleContext,
    RuleRunResult,
    builtin_markdown_rules,
    merge_rule_coverage,
)
from agentsec.versioning import current_versions


def _utc_now() -> datetime:
    """Return a timezone-aware timestamp for assessment metadata."""

    return datetime.now(UTC)


class CollectionAssessmentEngine:
    """Build a final Assessment through the complete Phase 1 static pipeline."""

    def __init__(
        self,
        collector: AssetCollector,
        *,
        parser: MarkdownParser | None = None,
        rule_runner: DeterministicRuleRunner | None = None,
        risk_engine: RiskEngine | None = None,
        confidence_engine: ConfidenceEngine | None = None,
        hard_gate_engine: HardGateEngine | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._collector = collector
        self._parser = parser if parser is not None else MarkdownItParser()
        self._rule_runner = (
            rule_runner
            if rule_runner is not None
            else DeterministicRuleRunner(builtin_markdown_rules())
        )
        self._risk_engine = (
            risk_engine if risk_engine is not None else DeterministicRiskEngine()
        )
        self._confidence_engine = (
            confidence_engine
            if confidence_engine is not None
            else DeterministicConfidenceEngine()
        )
        self._hard_gate_engine = (
            hard_gate_engine
            if hard_gate_engine is not None
            else DeterministicHardGateEngine()
        )
        self._clock = clock

    def assess(self, request: AssessmentRequest) -> Assessment:
        """Collect, parse, detect, score, gate, and assemble final Findings."""

        started_at = self._clock()
        try:
            result = self._collector.collect(request.project_root, request.config)
        except Exception as error:
            raise AssessmentAnalysisError(
                "required asset collection failed safely"
            ) from error
        parsed_assets, parse_issues = self._parse_assets(result.assets)
        parsed_coverage = self._merge_parse_coverage(result.coverage, parse_issues)
        rule_result = self._run_rules(parsed_assets)
        coverage = self._merge_rule_coverage(parsed_coverage, rule_result)
        findings = self._build_findings(rule_result)
        completed_at = self._clock()
        versions = current_versions()

        return Assessment(
            metadata=AssessmentMetadata(
                schema_version=versions.domain_schema,
                scanner_version=versions.package,
                config_schema_version=request.config.version,
                rule_pack_version=versions.rule_pack,
                risk_model_version=versions.risk_model,
                target_root=str(request.project_root),
                started_at=started_at,
                completed_at=completed_at,
            ),
            assets=tuple(item.asset for item in result.assets),
            findings=findings,
            coverage=coverage,
        )

    def _parse_assets(
        self,
        assets: tuple[CollectedAsset, ...],
    ) -> tuple[
        tuple[tuple[CollectedAsset, ParsedMarkdown], ...],
        tuple[CoverageIssue, ...],
    ]:
        """Isolate parser failures and retain successful data-only documents."""

        parsed: list[tuple[CollectedAsset, ParsedMarkdown]] = []
        issues: list[CoverageIssue] = []
        for collected_asset in assets:
            try:
                document = self._parser.parse(collected_asset.content)
            except Exception:
                issues.append(
                    CoverageIssue(
                        code=CoverageIssueCode.PARSE_ERROR,
                        message="Markdown parsing failed safely.",
                        asset_path=collected_asset.asset.path,
                    )
                )
                continue
            parsed.append((collected_asset, document))
        return tuple(parsed), tuple(issues)

    def _run_rules(
        self,
        parsed_assets: tuple[tuple[CollectedAsset, ParsedMarkdown], ...],
    ) -> RuleRunResult:
        """Construct bounded Rule contexts and run the deterministic pack."""

        try:
            contexts = tuple(
                RuleContext(
                    asset=item.asset,
                    content=item.content,
                    document=document,
                )
                for item, document in parsed_assets
            )
            return self._rule_runner.run(contexts)
        except Exception as error:
            raise AssessmentAnalysisError(
                "required deterministic rule analysis failed safely"
            ) from error

    @staticmethod
    def _merge_rule_coverage(
        coverage: ScanCoverage,
        result: RuleRunResult,
    ) -> ScanCoverage:
        """Expose isolated Rule failures as incomplete Coverage."""

        try:
            return merge_rule_coverage(coverage, result)
        except Exception as error:
            raise AssessmentAnalysisError(
                "required rule coverage analysis failed safely"
            ) from error

    def _build_findings(self, result: RuleRunResult) -> tuple[Finding, ...]:
        """Run Risk, Confidence, and report-only Hard Gate stages."""

        try:
            scored = self._risk_engine.score_all(result.findings)
            confidence_findings = self._confidence_engine.assign_all(scored)
            gated = self._hard_gate_engine.apply_all(confidence_findings)
            return tuple(item.to_domain_finding() for item in gated)
        except Exception as error:
            raise AssessmentAnalysisError(
                "required risk analysis failed safely"
            ) from error

    @staticmethod
    def _merge_parse_coverage(
        collection_coverage: ScanCoverage,
        parse_issues: tuple[CoverageIssue, ...],
    ) -> ScanCoverage:
        """Move parser failures from scanned to skipped coverage counts."""

        failed_assets = len(parse_issues)
        if failed_assets == 0:
            return collection_coverage

        issues = tuple(
            sorted(
                (*collection_coverage.issues, *parse_issues),
                key=lambda issue: (
                    issue.asset_path or "",
                    issue.code.value,
                    issue.message,
                ),
            )
        )
        return ScanCoverage(
            discovered_assets=collection_coverage.discovered_assets,
            scanned_assets=collection_coverage.scanned_assets - failed_assets,
            skipped_assets=collection_coverage.skipped_assets + failed_assets,
            complete=False,
            issues=issues,
        )
