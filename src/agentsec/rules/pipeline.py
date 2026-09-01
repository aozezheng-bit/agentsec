"""Deterministic multi-rule execution, isolation, and unscored Finding pipeline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from agentsec.domain import (
    CoverageIssue,
    CoverageIssueCode,
    Evidence,
    FindingCategory,
    ScanCoverage,
)
from agentsec.domain.base import validate_relative_path
from agentsec.rules.base import (
    Rule,
    RuleContext,
    RuleEvaluation,
    RuleFindingCandidate,
    RuleMetadata,
)

_FINDING_ID_PATTERN = re.compile(r"^finding-sha256:[a-f0-9]{64}$")


@dataclass(frozen=True, slots=True)
class UnscoredFinding:
    """Trusted Rule metadata bound to validated Evidence before risk scoring."""

    finding_id: str
    rule_id: str
    category: FindingCategory
    title: str
    description: str
    evidence: tuple[Evidence, ...] = dataclass_field(repr=False)
    recommendations: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require coherent deterministic materialized Finding data."""

        if _FINDING_ID_PATTERN.fullmatch(self.finding_id) is None:
            raise ValueError("unscored Finding ID must use finding-sha256 format")
        _require_text(self.rule_id, "unscored Finding rule_id")
        if not isinstance(self.category, FindingCategory):
            raise TypeError("unscored Finding category must be FindingCategory")
        _require_text(self.title, "unscored Finding title")
        _require_text(self.description, "unscored Finding description")
        if not isinstance(self.evidence, tuple) or not self.evidence:
            raise ValueError("unscored Finding requires an Evidence tuple")
        if any(not isinstance(item, Evidence) for item in self.evidence):
            raise TypeError("unscored Finding contains invalid Evidence")
        evidence_keys = tuple(_evidence_full_key(item) for item in self.evidence)
        if evidence_keys != tuple(sorted(evidence_keys)):
            raise ValueError("unscored Finding Evidence must be source ordered")
        if len({_evidence_locator(item) for item in self.evidence}) != len(
            self.evidence
        ):
            raise ValueError("unscored Finding Evidence locators must be unique")
        if not isinstance(self.recommendations, tuple) or not self.recommendations:
            raise ValueError("unscored Finding requires recommendations")
        for recommendation in self.recommendations:
            _require_text(recommendation, "unscored Finding recommendation")
        if len(set(self.recommendations)) != len(self.recommendations):
            raise ValueError("unscored Finding recommendations must be unique")

    def _sort_key(self) -> tuple[str, str, int, str]:
        """Return stable report-independent ordering."""

        first = self.evidence[0]
        return (
            self.rule_id,
            first.asset_path or "",
            first.start_line or 0,
            self.finding_id,
        )

    def _metadata_key(self) -> tuple[str, FindingCategory, str, str, tuple[str, ...]]:
        """Return trusted metadata used to detect impossible ID conflicts."""

        return (
            self.rule_id,
            self.category,
            self.title,
            self.description,
            self.recommendations,
        )


@dataclass(frozen=True, slots=True, order=True)
class RuleFailure:
    """One safe rule×asset failure without the original exception or source text."""

    rule_id: str
    asset_path: str

    def __post_init__(self) -> None:
        """Require trusted rule identity and project-relative asset identity."""

        _require_text(self.rule_id, "rule failure rule_id")
        object.__setattr__(self, "asset_path", validate_relative_path(self.asset_path))

    def to_coverage_issue(self) -> CoverageIssue:
        """Convert the structured failure to visible Domain coverage."""

        return CoverageIssue(
            code=CoverageIssueCode.RULE_ERROR,
            message=f"Rule {self.rule_id} failed safely.",
            asset_path=self.asset_path,
        )


@dataclass(frozen=True, slots=True)
class RuleRunResult:
    """Stable unscored Findings and failures from all requested contexts."""

    evaluated_asset_paths: tuple[str, ...]
    findings: tuple[UnscoredFinding, ...] = dataclass_field(repr=False)
    failures: tuple[RuleFailure, ...] = ()

    def __post_init__(self) -> None:
        """Keep paths, Findings, and failures sorted and unique."""

        if not isinstance(self.evaluated_asset_paths, tuple):
            raise TypeError("evaluated_asset_paths must be a tuple")
        normalized_paths = tuple(
            validate_relative_path(path) for path in self.evaluated_asset_paths
        )
        if normalized_paths != tuple(sorted(set(normalized_paths))):
            raise ValueError("evaluated asset paths must be sorted and unique")
        if not isinstance(self.findings, tuple):
            raise TypeError("rule run findings must be a tuple")
        if any(not isinstance(item, UnscoredFinding) for item in self.findings):
            raise TypeError("rule run result contains an invalid Finding")
        finding_keys = tuple(item._sort_key() for item in self.findings)
        if finding_keys != tuple(sorted(finding_keys)):
            raise ValueError("rule run Findings must be deterministically ordered")
        if len({item.finding_id for item in self.findings}) != len(self.findings):
            raise ValueError("rule run Finding IDs must be unique")
        if not isinstance(self.failures, tuple):
            raise TypeError("rule run failures must be a tuple")
        if any(not isinstance(item, RuleFailure) for item in self.failures):
            raise TypeError("rule run result contains an invalid failure")
        if self.failures != tuple(sorted(set(self.failures))):
            raise ValueError("rule failures must be sorted and unique")
        evaluated = set(self.evaluated_asset_paths)
        if any(item.asset_path not in evaluated for item in self.failures):
            raise ValueError("rule failure path was not evaluated")

    @property
    def complete(self) -> bool:
        """Return whether every applicable rule completed for every context."""

        return not self.failures

    @property
    def coverage_issues(self) -> tuple[CoverageIssue, ...]:
        """Return stable visible coverage issues for failed rule evaluations."""

        return tuple(item.to_coverage_issue() for item in self.failures)


@dataclass(frozen=True, slots=True)
class _RegisteredRule:
    """Trusted immutable metadata snapshot paired with its Rule adapter."""

    rule: Rule = dataclass_field(repr=False)
    metadata: RuleMetadata


class DeterministicRuleRunner:
    """Execute every applicable Rule with per-asset failure isolation."""

    def __init__(self, rules: tuple[Rule, ...]) -> None:
        if not isinstance(rules, tuple):
            raise TypeError("rules must be a tuple")

        registered: list[_RegisteredRule] = []
        try:
            for rule in rules:
                metadata = rule.metadata
                if not isinstance(metadata, RuleMetadata):
                    raise TypeError("rule metadata is invalid")
                if not callable(getattr(rule, "evaluate", None)):
                    raise TypeError("rule evaluate method is invalid")
                registered.append(_RegisteredRule(rule=rule, metadata=metadata))
        except Exception:
            raise RuleRegistryError() from None

        registered.sort(key=lambda item: item.metadata.rule_id)
        rule_ids = tuple(item.metadata.rule_id for item in registered)
        if len(set(rule_ids)) != len(rule_ids):
            raise RuleRegistryError()
        self._rules = tuple(registered)

    def run(self, contexts: tuple[RuleContext, ...]) -> RuleRunResult:
        """Return all successful Findings while isolating each rule×asset failure."""

        if not isinstance(contexts, tuple):
            raise TypeError("rule contexts must be a tuple")
        if any(not isinstance(item, RuleContext) for item in contexts):
            raise TypeError("rule contexts contain an invalid item")

        ordered_contexts = tuple(sorted(contexts, key=lambda item: item.asset.path))
        asset_paths = tuple(item.asset.path for item in ordered_contexts)
        if len(set(asset_paths)) != len(asset_paths):
            raise RulePipelineError("Rule contexts must have unique asset paths.")

        findings: list[UnscoredFinding] = []
        failures: list[RuleFailure] = []

        for context in ordered_contexts:
            for registered in self._rules:
                metadata = registered.metadata
                if not metadata.scope.applies_to(context.asset.asset_type):
                    continue
                try:
                    evaluation = registered.rule.evaluate(context)
                    if not isinstance(evaluation, RuleEvaluation):
                        raise TypeError("rule returned an invalid evaluation")
                    validated_evaluation = RuleEvaluation(
                        candidates=evaluation.candidates
                    )
                    local_findings = tuple(
                        _materialize_candidate(metadata, context, candidate)
                        for candidate in validated_evaluation.candidates
                    )
                except Exception:
                    failures.append(
                        RuleFailure(
                            rule_id=metadata.rule_id,
                            asset_path=context.asset.path,
                        )
                    )
                    continue
                findings.extend(local_findings)

        return RuleRunResult(
            evaluated_asset_paths=asset_paths,
            findings=_deduplicate_findings(tuple(findings)),
            failures=tuple(sorted(set(failures))),
        )


class RuleRegistryError(RuntimeError):
    """Fixed safe failure for invalid trusted rule registration."""

    def __init__(self) -> None:
        super().__init__("Rule registry validation failed safely.")


class RulePipelineError(ValueError):
    """Safe orchestration error that never copies scanned source text."""


def merge_rule_coverage(
    coverage: ScanCoverage,
    result: RuleRunResult,
) -> ScanCoverage:
    """Mark each failed asset incomplete once while retaining every rule issue."""

    if len(result.evaluated_asset_paths) != coverage.scanned_assets:
        raise RulePipelineError(
            "Rule contexts do not match the scanned coverage count."
        )
    if not result.failures:
        return coverage

    failed_asset_paths = {item.asset_path for item in result.failures}
    failed_asset_count = len(failed_asset_paths)
    if failed_asset_count > coverage.scanned_assets:
        raise RulePipelineError("Rule failures exceed scanned coverage.")

    issues = _deduplicate_coverage_issues((*coverage.issues, *result.coverage_issues))
    return ScanCoverage(
        discovered_assets=coverage.discovered_assets,
        scanned_assets=coverage.scanned_assets - failed_asset_count,
        skipped_assets=coverage.skipped_assets + failed_asset_count,
        complete=False,
        issues=issues,
    )


def _materialize_candidate(
    metadata: RuleMetadata,
    context: RuleContext,
    candidate: RuleFindingCandidate,
) -> UnscoredFinding:
    """Bind one candidate to trusted metadata and canonical Domain Evidence."""

    evidence = candidate.materialize_evidence(context)
    canonical_evidence = _canonicalize_evidence(evidence)
    finding_id = _finding_id(metadata.rule_id, canonical_evidence)
    return UnscoredFinding(
        finding_id=finding_id,
        rule_id=metadata.rule_id,
        category=metadata.category,
        title=metadata.title,
        description=metadata.description,
        evidence=canonical_evidence,
        recommendations=metadata.recommendations,
    )


def _finding_id(rule_id: str, evidence: tuple[Evidence, ...]) -> str:
    """Hash stable Rule and Evidence locator identity without plaintext excerpts."""

    payload = {
        "rule_id": rule_id,
        "evidence": [_evidence_locator_payload(item) for item in evidence],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"finding-sha256:{hashlib.sha256(encoded).hexdigest()}"


def _deduplicate_findings(
    findings: tuple[UnscoredFinding, ...],
) -> tuple[UnscoredFinding, ...]:
    """Deduplicate equal locator identities and prefer useful minimal excerpts."""

    grouped: dict[str, UnscoredFinding] = {}
    for finding in findings:
        existing = grouped.get(finding.finding_id)
        if existing is None:
            grouped[finding.finding_id] = finding
            continue
        if existing._metadata_key() != finding._metadata_key():
            raise RulePipelineError("Finding identity conflict detected safely.")
        merged_evidence = _canonicalize_evidence(
            (*existing.evidence, *finding.evidence)
        )
        grouped[finding.finding_id] = UnscoredFinding(
            finding_id=existing.finding_id,
            rule_id=existing.rule_id,
            category=existing.category,
            title=existing.title,
            description=existing.description,
            evidence=merged_evidence,
            recommendations=existing.recommendations,
        )
    return tuple(sorted(grouped.values(), key=lambda item: item._sort_key()))


def _canonicalize_evidence(evidence: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
    """Keep one deterministic Evidence representation per authoritative locator."""

    selected: dict[tuple[str, str, int, int, str, str], Evidence] = {}
    for item in evidence:
        if not isinstance(item, Evidence):
            raise TypeError("candidate materialized invalid Evidence")
        locator = _evidence_locator(item)
        existing = selected.get(locator)
        if existing is None or _excerpt_preference(item) < _excerpt_preference(
            existing
        ):
            selected[locator] = item
    return tuple(sorted(selected.values(), key=_evidence_full_key))


def _excerpt_preference(evidence: Evidence) -> tuple[bool, int, str]:
    """Prefer a present, shorter, deterministic exact excerpt for one locator."""

    excerpt = evidence.excerpt
    return (excerpt is None, len(excerpt or ""), excerpt or "")


def _evidence_locator(evidence: Evidence) -> tuple[str, str, int, int, str, str]:
    """Return the stable source identity of Evidence excluding display excerpt."""

    return (
        evidence.source_type.value,
        evidence.asset_path or "",
        evidence.start_line or 0,
        evidence.end_line or 0,
        evidence.field or "",
        evidence.content_sha256 or "",
    )


def _evidence_locator_payload(evidence: Evidence) -> dict[str, object]:
    """Return a canonical JSON-safe locator for Finding fingerprinting."""

    return {
        "source_type": evidence.source_type.value,
        "asset_path": evidence.asset_path,
        "start_line": evidence.start_line,
        "end_line": evidence.end_line,
        "field": evidence.field,
        "content_sha256": evidence.content_sha256,
    }


def _evidence_full_key(
    evidence: Evidence,
) -> tuple[str, str, int, int, str, str, str]:
    """Return deterministic Evidence ordering including the retained excerpt."""

    return (*_evidence_locator(evidence), evidence.excerpt or "")


def _deduplicate_coverage_issues(
    issues: tuple[CoverageIssue, ...],
) -> tuple[CoverageIssue, ...]:
    """Return stable unique coverage issues without parsing their messages."""

    keyed = {
        (issue.asset_path or "", issue.code.value, issue.message): issue
        for issue in issues
    }
    return tuple(keyed[key] for key in sorted(keyed))


def _require_text(value: str, label: str) -> None:
    """Validate trusted pipeline text without echoing its value."""

    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if not value.strip():
        raise ValueError(f"{label} must not be empty")
