"""Safe fact-bundle evaluator used by the P2-CAL-02 seed replay."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from agentsec.capability_rules import BUILTIN_CAPABILITY_RULE_IDS, CapabilityCorrelation
from agentsec.domain import EvidenceConfidence

from .evaluation import CalibrationObservation
from .models import (
    CalibrationCase,
    CalibrationFact,
    CalibrationFactDimension,
    CalibrationFactState,
    CalibrationRuleExpectation,
    CalibrationRuleOutcome,
)

_MAX_FACT_BUNDLE_BYTES = 512 * 1024


class CalibrationEvaluationError(RuntimeError):
    """Safe evaluator failure without fixture values or host paths."""


@runtime_checkable
class CalibrationCaseEvaluator(Protocol):
    evaluator_id: str
    evaluator_version: str

    def evaluate(
        self,
        *,
        corpus_root: Path,
        case: CalibrationCase,
        expectation: CalibrationRuleExpectation,
    ) -> CalibrationObservation: ...


@dataclass(frozen=True, slots=True)
class _FactCondition:
    dimension: CalibrationFactDimension
    key: str
    allowed_states: tuple[CalibrationFactState, ...]


@dataclass(frozen=True, slots=True)
class _RuleSpec:
    conditions: tuple[_FactCondition, ...]
    correlation: CapabilityCorrelation
    confidence: EvidenceConfidence


def _condition(
    dimension: CalibrationFactDimension,
    key: str,
    *states: CalibrationFactState,
) -> _FactCondition:
    return _FactCondition(dimension=dimension, key=key, allowed_states=states)


P = CalibrationFactDimension.PERMISSION
C = CalibrationFactDimension.CONTROL
T = CalibrationFactDimension.TOOL
IDENTITY = CalibrationFactDimension.RUNTIME_IDENTITY
R = CalibrationFactDimension.RELATIONSHIP
V = CalibrationFactDimension.COVERAGE
PRESENT = CalibrationFactState.PRESENT
ABSENT = CalibrationFactState.ABSENT
UNKNOWN = CalibrationFactState.UNKNOWN
SAME = CapabilityCorrelation.SAME_TARGET
AGENT = CapabilityCorrelation.AGENT_WIDE
INCOMPLETE = CapabilityCorrelation.INCOMPLETE_COVERAGE
EXPLICIT = CapabilityCorrelation.EXPLICIT_RELATION

_RULE_SPECS: dict[str, _RuleSpec] = {
    "CAP-APPROVAL-001": _RuleSpec(
        (
            _condition(P, "state-changing", PRESENT),
            _condition(C, "human-approval", ABSENT, UNKNOWN),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-AUTONETWORK-001": _RuleSpec(
        (
            _condition(P, "network", PRESENT),
            _condition(C, "human-approval-allow", PRESENT),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-AUTOPROD-001": _RuleSpec(
        (
            _condition(P, "production-state-change", PRESENT),
            _condition(C, "human-approval-allow", PRESENT),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-AUTOSECRET-001": _RuleSpec(
        (
            _condition(P, "secret-access", PRESENT),
            _condition(C, "human-approval-allow", PRESENT),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-CHAIN-001": _RuleSpec(
        (
            _condition(P, "execute", PRESENT),
            _condition(P, "secret-access", PRESENT),
            _condition(P, "external-network", PRESENT),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-COVERAGE-001": _RuleSpec(
        (
            _condition(P, "high-impact", PRESENT),
            _condition(V, "relevant-dimension", UNKNOWN),
        ),
        INCOMPLETE,
        EvidenceConfidence.D,
    ),
    "CAP-DELEGATE-001": _RuleSpec(
        (
            _condition(R, "delegates-to", PRESENT),
            _condition(P, "powerful", PRESENT),
            _condition(C, "human-approval", ABSENT, UNKNOWN),
        ),
        AGENT,
        EvidenceConfidence.D,
    ),
    "CAP-DELEGATEEXTERNAL-001": _RuleSpec(
        (
            _condition(R, "delegates-to", PRESENT),
            _condition(P, "external-capability", PRESENT),
        ),
        AGENT,
        EvidenceConfidence.D,
    ),
    "CAP-DELEGATEPERSIST-001": _RuleSpec(
        (
            _condition(R, "delegates-to", PRESENT),
            _condition(R, "persists-memory", PRESENT),
        ),
        AGENT,
        EvidenceConfidence.D,
    ),
    "CAP-EXTERNAL-001": _RuleSpec(
        (
            _condition(T, "mcp-enabled-required", PRESENT),
            _condition(IDENTITY, "credentialed-external", PRESENT),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-EXTERNALEXEC-001": _RuleSpec(
        (_condition(P, "external-execute", PRESENT),), SAME, EvidenceConfidence.B
    ),
    "CAP-EXTERNALPRIVILEGED-001": _RuleSpec(
        (_condition(IDENTITY, "external-privileged", PRESENT),),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-EXTERNALUNVERIFIED-001": _RuleSpec(
        (_condition(IDENTITY, "external-runtime-verification", UNKNOWN),),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-EXTERNALWRITE-001": _RuleSpec(
        (_condition(P, "external-write", PRESENT),), SAME, EvidenceConfidence.B
    ),
    "CAP-MEMORYNETWORK-001": _RuleSpec(
        (_condition(R, "memory", PRESENT), _condition(P, "network", PRESENT)),
        AGENT,
        EvidenceConfidence.D,
    ),
    "CAP-MEMORYPROD-001": _RuleSpec(
        (
            _condition(R, "memory", PRESENT),
            _condition(P, "production-state-change", PRESENT),
        ),
        AGENT,
        EvidenceConfidence.D,
    ),
    "CAP-MEMORYSECRET-001": _RuleSpec(
        (_condition(R, "memory", PRESENT), _condition(P, "secret-access", PRESENT)),
        AGENT,
        EvidenceConfidence.D,
    ),
    "CAP-NONETWORKPOLICY-001": _RuleSpec(
        (
            _condition(P, "external-network", PRESENT),
            _condition(C, "network-policy", ABSENT, UNKNOWN),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-NOSANDBOX-001": _RuleSpec(
        (
            _condition(P, "high-impact", PRESENT),
            _condition(C, "sandbox", ABSENT, UNKNOWN),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-NOSECRET-001": _RuleSpec(
        (
            _condition(P, "secret-access", PRESENT),
            _condition(C, "secret-handling", ABSENT, UNKNOWN),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-PERSIST-001": _RuleSpec(
        (
            _condition(R, "persists-memory", PRESENT),
            _condition(P, "sensitive", PRESENT),
        ),
        AGENT,
        EvidenceConfidence.D,
    ),
    "CAP-PRODADMIN-001": _RuleSpec(
        (_condition(P, "production-admin", PRESENT),), SAME, EvidenceConfidence.B
    ),
    "CAP-PRODEXEC-001": _RuleSpec(
        (_condition(P, "production-execute", PRESENT),), SAME, EvidenceConfidence.B
    ),
    "CAP-PRODIDENTITY-001": _RuleSpec(
        (
            _condition(P, "production-state-change", PRESENT),
            _condition(IDENTITY, "external-session", PRESENT),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-PRODWRITE-001": _RuleSpec(
        (_condition(P, "production-write", PRESENT),), SAME, EvidenceConfidence.B
    ),
    "CAP-RELATIONUNKNOWN-001": _RuleSpec(
        (_condition(R, "high-impact", UNKNOWN),), EXPLICIT, EvidenceConfidence.C
    ),
    "CAP-REQUIREDNOFILTER-001": _RuleSpec(
        (
            _condition(T, "mcp-enabled-required", PRESENT),
            _condition(C, "tool-filter", ABSENT, UNKNOWN),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-REQUIREDNOTIMEOUT-001": _RuleSpec(
        (
            _condition(T, "mcp-enabled-required", PRESENT),
            _condition(C, "timeout", ABSENT, UNKNOWN),
        ),
        SAME,
        EvidenceConfidence.B,
    ),
    "CAP-SECRETPROD-001": _RuleSpec(
        (_condition(P, "production-secret-access", PRESENT),),
        SAME,
        EvidenceConfidence.B,
    ),
}


class DeterministicFactBundleEvaluator:
    """Replay normalized seed facts without executing or importing fixtures."""

    evaluator_id = "fact-bundle-rule-spec"
    evaluator_version = "0.1.0"

    def __init__(self) -> None:
        if set(_RULE_SPECS) != set(BUILTIN_CAPABILITY_RULE_IDS):
            raise CalibrationEvaluationError("fact evaluator Rule inventory is invalid")

    def evaluate(
        self,
        *,
        corpus_root: Path,
        case: CalibrationCase,
        expectation: CalibrationRuleExpectation,
    ) -> CalibrationObservation:
        facts = self._read_facts(corpus_root, case)
        spec = _RULE_SPECS.get(expectation.rule_id)
        if spec is None:
            raise CalibrationEvaluationError("calibration Rule is unsupported")
        matched_facts = tuple(
            self._matching_fact(facts, condition) for condition in spec.conditions
        )
        matched = all(item is not None for item in matched_facts)
        evidence_complete = all(
            item is not None and item.evidence for item in matched_facts
        )
        unknowns_visible = not case.ground_truth.unknown_dimensions or any(
            fact.state is CalibrationFactState.UNKNOWN for fact in facts
        )
        coverage_visible = case.ground_truth.coverage == "complete" or any(
            fact.dimension is CalibrationFactDimension.COVERAGE
            and fact.state is CalibrationFactState.UNKNOWN
            for fact in facts
        )
        if not matched:
            return CalibrationObservation(
                outcome=CalibrationRuleOutcome.NO_MATCH,
                evidence_complete=True,
                coverage_visible=coverage_visible,
                unknowns_visible=unknowns_visible,
                unknown_applicable=bool(case.ground_truth.unknown_dimensions),
            )
        return CalibrationObservation(
            outcome=CalibrationRuleOutcome.MATCH,
            correlations=(spec.correlation,),
            confidences=(spec.confidence,),
            finding_count=1,
            evidence_items=sum(len(item.evidence) for item in matched_facts if item),
            evidence_complete=evidence_complete,
            coverage_visible=coverage_visible,
            unknowns_visible=unknowns_visible,
            unknown_applicable=bool(case.ground_truth.unknown_dimensions),
        )

    @staticmethod
    def _matching_fact(
        facts: tuple[CalibrationFact, ...], condition: _FactCondition
    ) -> CalibrationFact | None:
        return next(
            (
                fact
                for fact in facts
                if fact.dimension is condition.dimension
                and fact.key == condition.key
                and fact.state in condition.allowed_states
            ),
            None,
        )

    @staticmethod
    def _read_facts(root: Path, case: CalibrationCase) -> tuple[CalibrationFact, ...]:
        path = (root / case.fixture.path).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as error:
            raise CalibrationEvaluationError(
                "fact fixture escapes corpus root"
            ) from error
        if path.is_symlink() or not path.is_file():
            raise CalibrationEvaluationError("fact fixture is missing or unsafe")
        data = path.read_bytes()
        if len(data) > _MAX_FACT_BUNDLE_BYTES:
            raise CalibrationEvaluationError("fact fixture exceeds bounded size")
        try:
            payload = json.loads(data.decode("utf-8"))
            raw_facts = payload["facts"]
            facts = tuple(CalibrationFact.model_validate(item) for item in raw_facts)
        except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
            raise CalibrationEvaluationError("fact fixture is invalid") from error
        if facts != case.ground_truth.facts:
            raise CalibrationEvaluationError("fact fixture does not match Case labels")
        return facts
