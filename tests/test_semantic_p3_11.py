"""P3-11B semantic quality qualification-gate tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agentsec.domain import FindingCategory
from agentsec.semantic import (
    SemanticProviderMetadata,
    SemanticProviderRequest,
    SemanticProviderResponse,
)
from agentsec.semantic.invocation import SemanticShadowInvocationAdapter
from agentsec.semantic.models import (
    SemanticCandidateDisposition,
    SemanticCandidateKind,
    SemanticModelCandidate,
    SemanticModelOutput,
)
from agentsec.semantic.promotion import ProviderQualityThresholds
from agentsec.semantic.quality_gate import (
    GoldLabelSet,
    QualityGateError,
    QualityGateStatus,
    SemanticQualityGate,
    encode_semantic_qualification_json,
    load_gold_labels,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GOLD_LABELS = (
    REPOSITORY_ROOT
    / "pilots"
    / "semantic-quality-p3-11"
    / "gold-labels"
    / "semantic-gold-labels.json"
)


def _gold() -> GoldLabelSet:
    assert GOLD_LABELS.exists(), "P3-11A gold labels must exist"
    return load_gold_labels(GOLD_LABELS)


def _output_for(
    request: SemanticProviderRequest,
    judgments: tuple[dict[str, str], ...],
    evidence_id: str,
) -> SemanticModelOutput:
    return SemanticModelOutput(
        analysis_id=request.analysis_id,
        analyzed_evidence_ids=(evidence_id,),
        candidates=tuple(
            SemanticModelCandidate(
                candidate_key=f"candidate-{index:02d}",
                kind=SemanticCandidateKind(item["kind"]),
                category=FindingCategory(item["category"]),
                disposition=SemanticCandidateDisposition(item["disposition"]),
                summary="Fixture judgment for qualification replay.",
                evidence_ids=(evidence_id,),
            )
            for index, item in enumerate(judgments, start=1)
        ),
    )


class _PerfectProvider:
    """Offline Provider echoing the gold judgments exactly."""

    def __init__(self, gold: GoldLabelSet) -> None:
        self._gold = gold
        self.metadata = SemanticProviderMetadata()

    def invoke(
        self, provider_request: SemanticProviderRequest
    ) -> SemanticProviderResponse:
        case = next(
            item
            for item in self._gold.cases
            if item.case_id == provider_request.analysis_id
        )
        judgments = tuple(
            {
                "kind": item.kind.value,
                "category": item.category,
                "disposition": item.disposition.value,
            }
            for item in case.expected
        )
        raw = json.dumps(
            _output_for(
                provider_request, judgments, case.expected[0].evidence_ids[0]
            ).model_dump(mode="json"),
            sort_keys=True,
        )
        return SemanticProviderResponse(
            request_id=provider_request.request_id,
            provider_id=provider_request.provider_id,
            model_id=provider_request.model_id,
            completion_status="complete",
            output_json=raw,
            output_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            input_tokens=1,
            output_tokens=1,
        )


class _DegradedProvider:
    """Offline Provider emitting one wrong category per case."""

    def __init__(self, gold: GoldLabelSet) -> None:
        self._gold = gold
        self.metadata = SemanticProviderMetadata()

    def invoke(
        self, provider_request: SemanticProviderRequest
    ) -> SemanticProviderResponse:
        case = next(
            item
            for item in self._gold.cases
            if item.case_id == provider_request.analysis_id
        )
        first = case.expected[0]
        degraded = []
        for index, item in enumerate(case.expected):
            category = item.category
            if index == 0:
                category = (
                    FindingCategory.OTHER.value
                    if item.category != FindingCategory.OTHER.value
                    else FindingCategory.SCAN_COVERAGE.value
                )
            degraded.append(
                {
                    "kind": item.kind.value,
                    "category": category,
                    "disposition": item.disposition.value,
                }
            )
        raw = json.dumps(
            _output_for(
                provider_request, tuple(degraded), first.evidence_ids[0]
            ).model_dump(mode="json"),
            sort_keys=True,
        )
        return SemanticProviderResponse(
            request_id=provider_request.request_id,
            provider_id=provider_request.provider_id,
            model_id=provider_request.model_id,
            completion_status="complete",
            output_json=raw,
            output_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            input_tokens=1,
            output_tokens=1,
        )


def _adapter(
    provider: _PerfectProvider | _DegradedProvider,
) -> SemanticShadowInvocationAdapter:
    return SemanticShadowInvocationAdapter(provider=provider)


def test_real_gold_labels_load_with_confirmed_provenance() -> None:
    gold = _gold()
    assert gold.case_count >= 20
    assert gold.reviewer_id
    assert gold.label_provenance.value in {
        "human_authored",
        "ai_draft_human_confirmed",
    }


def test_perfect_provider_qualifies_against_real_gold() -> None:
    gold = _gold()
    report = SemanticQualityGate().qualify(
        gold=gold,
        adapter=_adapter(_PerfectProvider(gold)),
        thresholds=ProviderQualityThresholds(min_case_count=20),
    )
    assert report.status is QualityGateStatus.QUALIFIED
    assert report.failed_checks == ()
    assert report.metrics["precision"] == 1.0
    assert report.metrics["recall"] == 1.0
    assert report.report_only is True
    assert report.policy_authority is False
    assert report.release_authority is False
    encoded = encode_semantic_qualification_json(report)
    assert "qualified" in encoded


def test_degraded_provider_is_not_qualified_with_visible_reasons() -> None:
    gold = _gold()
    report = SemanticQualityGate().qualify(
        gold=gold,
        adapter=_adapter(_DegradedProvider(gold)),
        thresholds=ProviderQualityThresholds(min_case_count=20),
    )
    assert report.status is QualityGateStatus.NOT_QUALIFIED
    assert "quality_metrics" in report.failed_checks
    assert "quality_threshold_not_met" in report.reasons
    assert report.metrics["precision"] < 1.0


def test_gate_bound_requires_adapter_and_gold_types() -> None:
    gold = _gold()
    with pytest.raises(TypeError):
        SemanticQualityGate().qualify(
            gold=gold,
            adapter="not-an-adapter",  # type: ignore[arg-type]
        )


def test_thresholds_impossible_high_fail_closed() -> None:
    gold = _gold()
    report = SemanticQualityGate().qualify(
        gold=gold,
        adapter=_adapter(_PerfectProvider(gold)),
        thresholds=ProviderQualityThresholds(min_case_count=1000),
    )
    assert report.status is QualityGateStatus.NOT_QUALIFIED
    assert "gold_labels_valid" in report.failed_checks


def test_load_gold_labels_rejects_wrong_shape(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(QualityGateError):
        load_gold_labels(bad)


def test_qualify_evaluation_report_matches_qualify_without_reinvoking() -> None:
    gold = _gold()
    perfect = _adapter(_PerfectProvider(gold))
    thresholds = ProviderQualityThresholds(min_case_count=20)
    direct = SemanticQualityGate().qualify(
        gold=gold, adapter=perfect, thresholds=thresholds
    )
    from agentsec.semantic.evaluation import SemanticEvaluationHarness

    evaluation = SemanticEvaluationHarness().evaluate(
        tuple(SemanticQualityGate()._build_cases(gold)), perfect
    )
    from_report = SemanticQualityGate().qualify_evaluation_report(
        gold=gold, report=evaluation, thresholds=thresholds
    )
    assert from_report.status is direct.status
    assert from_report.metrics == direct.metrics
    assert from_report.failed_checks == direct.failed_checks


def test_qualify_evaluation_report_rejects_bad_types() -> None:
    gold = _gold()
    with pytest.raises(TypeError):
        SemanticQualityGate().qualify_evaluation_report(
            gold=gold,
            report=None,  # type: ignore[arg-type]
        )


def test_live_output_limitations_and_candidates_normalize_value_neutrally() -> None:
    from agentsec.semantic.provider_specific import _normalize_output_limitations

    unordered = json.dumps(
        {
            "analysis_id": "case",
            "candidates": [
                {"candidate_key": "b-key", "limitations": ["z-note", "a-note"]},
                {"candidate_key": "a-key", "limitations": ["m-note"]},
            ],
            "limitations": ["y-top", "x-top"],
        }
    )
    normalized = json.loads(_normalize_output_limitations(unordered, None))  # type: ignore[arg-type]
    assert [c["candidate_key"] for c in normalized["candidates"]] == [
        "a-key",
        "b-key",
    ]
    assert normalized["candidates"][1]["limitations"] == ["a-note", "z-note"]
    assert normalized["limitations"] == ["x-top", "y-top"]

    passing = json.dumps({"analysis_id": "case", "candidates": []})
    assert _normalize_output_limitations(passing, None) == passing  # type: ignore[arg-type]
    assert _normalize_output_limitations("not json", None) == "not json"  # type: ignore[arg-type]
