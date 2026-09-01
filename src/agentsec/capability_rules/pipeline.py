"""Deterministic Capability Rule registration, isolation, and materialization."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from agentsec.capability_rules.base import (
    CAPABILITY_RISK_MAPPING_BASIS,
    CapabilityCorrelation,
    CapabilityRule,
    CapabilityRuleCandidate,
    CapabilityRuleContext,
    CapabilityRuleEvaluation,
    CapabilityRuleFinding,
    CapabilityRuleMetadata,
    confidence_for_correlation,
    likelihood_for_correlation,
)
from agentsec.manifests import AgentManifest
from agentsec.risk import (
    agentsec_base_score,
    nist_risk_level,
    nist_semi_quantitative_value,
    severity_for_score,
)
from agentsec.versioning import (
    CAPABILITY_RISK_MODEL_VERSION,
    CAPABILITY_RULE_PACK_VERSION,
)


@dataclass(frozen=True, slots=True, order=True)
class CapabilityRuleFailure:
    """One isolated safe Rule failure retaining only stable Rule identity."""

    rule_id: str

    def __post_init__(self) -> None:
        if not self.rule_id.startswith("CAP-"):
            raise ValueError("Capability Rule failure ID is invalid")


@dataclass(frozen=True, slots=True)
class CapabilityRuleRunResult:
    """Stable Findings and isolated failures for one Agent Manifest."""

    agent_id: str
    evaluated_rule_ids: tuple[str, ...]
    findings: tuple[CapabilityRuleFinding, ...] = dataclass_field(repr=False)
    failures: tuple[CapabilityRuleFailure, ...] = ()
    capability_rule_pack_version: str = CAPABILITY_RULE_PACK_VERSION
    capability_risk_model_version: str = CAPABILITY_RISK_MODEL_VERSION

    def __post_init__(self) -> None:
        if not self.agent_id.strip():
            raise ValueError("Capability Rule result agent_id must not be empty")
        if self.evaluated_rule_ids != tuple(sorted(set(self.evaluated_rule_ids))):
            raise ValueError("evaluated Capability Rule IDs must be sorted and unique")
        if any(not isinstance(item, CapabilityRuleFinding) for item in self.findings):
            raise TypeError("Capability Rule result contains an invalid Finding")
        finding_keys = tuple(finding.sort_key() for finding in self.findings)
        if finding_keys != tuple(sorted(set(finding_keys))):
            raise ValueError("Capability Findings must be sorted and unique")
        if self.failures != tuple(sorted(set(self.failures))):
            raise ValueError("Capability Rule failures must be sorted and unique")
        if any(
            failure.rule_id not in self.evaluated_rule_ids for failure in self.failures
        ):
            raise ValueError("Capability Rule failure was not evaluated")
        if self.capability_rule_pack_version != CAPABILITY_RULE_PACK_VERSION:
            raise ValueError("Capability Rule result Rule Pack version is unsupported")
        if self.capability_risk_model_version != CAPABILITY_RISK_MODEL_VERSION:
            raise ValueError("Capability Rule result Risk Model version is unsupported")

    @property
    def complete(self) -> bool:
        """Return whether every registered Rule evaluated successfully."""

        return not self.failures


@dataclass(frozen=True, slots=True)
class _RegisteredCapabilityRule:
    rule: CapabilityRule = dataclass_field(repr=False)
    metadata: CapabilityRuleMetadata


class DeterministicCapabilityRuleRunner:
    """Execute pure Manifest Rules with per-Rule failure isolation."""

    def __init__(self, rules: tuple[CapabilityRule, ...]) -> None:
        if not isinstance(rules, tuple) or not rules:
            raise CapabilityRuleRegistryError()
        registered: list[_RegisteredCapabilityRule] = []
        try:
            for rule in rules:
                metadata = rule.metadata
                if not isinstance(metadata, CapabilityRuleMetadata):
                    raise TypeError
                if not callable(getattr(rule, "evaluate", None)):
                    raise TypeError
                registered.append(
                    _RegisteredCapabilityRule(rule=rule, metadata=metadata)
                )
        except Exception:
            raise CapabilityRuleRegistryError() from None
        registered.sort(key=lambda item: item.metadata.rule_id)
        rule_ids = tuple(item.metadata.rule_id for item in registered)
        if len(set(rule_ids)) != len(rule_ids):
            raise CapabilityRuleRegistryError()
        self._rules = tuple(registered)

    def run(self, manifest: AgentManifest) -> CapabilityRuleRunResult:
        """Build one safe context and evaluate all registered Rules."""

        context = CapabilityRuleContext.from_manifest(manifest)
        findings: list[CapabilityRuleFinding] = []
        failures: list[CapabilityRuleFailure] = []
        for registered in self._rules:
            try:
                evaluation = registered.rule.evaluate(context)
                validated = CapabilityRuleEvaluation(candidates=evaluation.candidates)
                local_findings = tuple(
                    self._materialize(registered.metadata, context, candidate)
                    for candidate in validated.candidates
                )
            except Exception:
                failures.append(
                    CapabilityRuleFailure(rule_id=registered.metadata.rule_id)
                )
                continue
            findings.extend(local_findings)
        return CapabilityRuleRunResult(
            agent_id=manifest.identity.agent_id,
            evaluated_rule_ids=tuple(item.metadata.rule_id for item in self._rules),
            findings=self._deduplicate(tuple(findings)),
            failures=tuple(sorted(set(failures))),
        )

    @staticmethod
    def _materialize(
        metadata: CapabilityRuleMetadata,
        context: CapabilityRuleContext,
        candidate: CapabilityRuleCandidate,
    ) -> CapabilityRuleFinding:
        evidence = context.evidence_for(candidate.evidence)
        correlation = candidate.correlation
        likelihood = likelihood_for_correlation(correlation)
        impact = metadata.impact
        risk_level = nist_risk_level(likelihood, impact)
        score = agentsec_base_score(risk_level)
        finding_id = _finding_id(
            metadata.rule_id,
            correlation,
            candidate.related_ids,
            tuple(item.sort_key() for item in evidence),
        )
        return CapabilityRuleFinding(
            finding_id=finding_id,
            rule_id=metadata.rule_id,
            category=metadata.category,
            texts=metadata.texts,
            correlation=correlation,
            likelihood=likelihood,
            impact=impact,
            risk_level=risk_level,
            nist_semi_quantitative_value=nist_semi_quantitative_value(risk_level),
            score=score,
            severity=severity_for_score(score),
            confidence=confidence_for_correlation(correlation),
            hard_gate=False,
            related_ids=candidate.related_ids,
            evidence=evidence,
            likelihood_basis=candidate.likelihood_basis,
            impact_ratings=metadata.impact_ratings,
            limitations=candidate.limitations,
            mapping_basis=CAPABILITY_RISK_MAPPING_BASIS,
            capability_rule_pack_version=CAPABILITY_RULE_PACK_VERSION,
            capability_risk_model_version=CAPABILITY_RISK_MODEL_VERSION,
        )

    @staticmethod
    def _deduplicate(
        findings: tuple[CapabilityRuleFinding, ...],
    ) -> tuple[CapabilityRuleFinding, ...]:
        by_id: dict[str, CapabilityRuleFinding] = {}
        for finding in findings:
            previous = by_id.get(finding.finding_id)
            if previous is not None and previous != finding:
                raise CapabilityRulePipelineError(
                    "Capability Finding identity conflict detected safely."
                )
            by_id[finding.finding_id] = finding
        return tuple(sorted(by_id.values(), key=lambda item: item.sort_key()))


class CapabilityRuleRegistryError(RuntimeError):
    """Safe trusted-registry failure without Rule implementation details."""

    def __init__(self) -> None:
        super().__init__("Capability Rule registry validation failed safely.")


class CapabilityRulePipelineError(RuntimeError):
    """Safe Capability Rule orchestration failure."""


def _finding_id(
    rule_id: str,
    correlation: CapabilityCorrelation,
    related_ids: tuple[str, ...],
    evidence_keys: tuple[tuple[str, str, str, str, int, int, str], ...],
) -> str:
    payload = {
        "rule_id": rule_id,
        "correlation": correlation.value,
        "related_ids": related_ids,
        "evidence": evidence_keys,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"capability-finding-sha256:{hashlib.sha256(encoded).hexdigest()}"
