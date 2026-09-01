"""P3-20 Provider Evaluation import and report-only Gate qualification wiring."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.semantic.evaluation import SemanticEvaluationReport
from agentsec.semantic.gate_corpus import SemanticGateHumanCorpus
from agentsec.semantic.gate_definition import (
    SemanticGateCandidate,
    SemanticGateEvidenceConfidence,
    SemanticGateQualificationReport,
    SemanticGateQualificationRunner,
)
from agentsec.semantic.promotion import (
    ProviderPromotionReport,
    ProviderQualityThresholds,
)
from agentsec.semantic.prompt import (
    SEMANTIC_PROMPT_VERSION,
    semantic_model_output_schema_sha256,
    semantic_system_prompt_sha256,
)
from agentsec.semantic.quality_gate import (
    GoldLabelProvenance,
    QualityGateReport,
    QualityGateStatus,
)
from agentsec.versioning import (
    SEMANTIC_GATE_EVALUATION_IMPORT_VERSION,
    SEMANTIC_GATE_PROMOTION_VERSION,
)

SEMANTIC_GATE_EVALUATION_IMPORT_FORMAT = "agentsec-semantic-gate-evaluation-import"
SEMANTIC_GATE_PROMOTION_FORMAT = "agentsec-semantic-gate-report-only-promotion"
_EVALUATION_IMPORT_ID_PATTERN = r"^semantic-gate-evaluation-import-sha256:[0-9a-f]{64}$"
_PROMOTION_ID_PATTERN = r"^semantic-gate-promotion-sha256:[0-9a-f]{64}$"
_CANDIDATE_ID_PATTERN = r"^semantic-gate-candidate-sha256:[0-9a-f]{64}$"
_CORPUS_ID_PATTERN = r"^semantic-gate-human-corpus-sha256:[0-9a-f]{64}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class SemanticGateEvaluationSource(StrEnum):
    EVALUATION_REPORT = "evaluation_report"
    REAL_PROVIDER_PILOT = "real_provider_pilot"


class SemanticGateEvaluationImport(_Strict):
    """A current, bound Provider evaluation accepted by P3-18."""

    format: Literal["agentsec-semantic-gate-evaluation-import"] = (
        "agentsec-semantic-gate-evaluation-import"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    evaluation_import_id: Annotated[str, Field(pattern=_EVALUATION_IMPORT_ID_PATTERN)]
    gate_id: Annotated[str, Field(pattern=r"^SG-[A-Z0-9][A-Z0-9._-]{2,63}$")]
    candidate_id: Annotated[str, Field(pattern=_CANDIDATE_ID_PATTERN)]
    corpus_id: Annotated[str, Field(pattern=_CORPUS_ID_PATTERN)]
    corpus_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    evaluation_report_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    provider_id: Annotated[str, Field(min_length=1, max_length=160)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    prompt_version: Literal["0.1.0"] = "0.1.0"
    system_prompt_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    output_schema_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    prompt_contract_sha256: Annotated[str, Field(pattern=_SHA256_PATTERN)]
    human_reviewer_ids: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...]
    source: SemanticGateEvaluationSource
    evaluation: SemanticEvaluationReport
    report_only: Literal[True] = True
    shadow_only: Literal[True] = True
    policy_authority: Literal[False] = False
    ci_authority: Literal[False] = False
    rule_authority: Literal[False] = False
    release_authority: Literal[False] = False
    runtime_verified: Literal[False] = False

    @model_validator(mode="after")
    def import_must_be_coherent(self) -> SemanticGateEvaluationImport:
        if self.evaluation.provider_id != self.provider_id:
            raise ValueError("evaluation Provider ID does not match import")
        if self.evaluation.model_id != self.model_id:
            raise ValueError("evaluation Model ID does not match import")
        if self.evaluation.metrics.case_count != len(self.evaluation.cases):
            raise ValueError("evaluation case count is inconsistent")
        case_ids = tuple(item.case_id for item in self.evaluation.cases)
        if case_ids != tuple(sorted(set(case_ids))):
            raise ValueError("evaluation case IDs must be sorted and unique")
        if self.evaluation_report_sha256 != _report_sha256(self.evaluation):
            raise ValueError("evaluation report digest is inconsistent")
        if self.system_prompt_sha256 != semantic_system_prompt_sha256():
            raise ValueError("system prompt digest is not current")
        if self.output_schema_sha256 != semantic_model_output_schema_sha256():
            raise ValueError("output schema digest is not current")
        if self.prompt_contract_sha256 != _prompt_contract_sha256(
            self.prompt_version,
            self.system_prompt_sha256,
            self.output_schema_sha256,
        ):
            raise ValueError("prompt contract digest is inconsistent")
        if self.human_reviewer_ids != tuple(sorted(set(self.human_reviewer_ids))):
            raise ValueError("human reviewer IDs must be sorted and unique")
        if not self.human_reviewer_ids:
            raise ValueError("at least one human reviewer is required")
        expected_id = _evaluation_import_id(self)
        if self.evaluation_import_id != expected_id:
            raise ValueError("evaluation import ID is inconsistent")
        if not (
            self.report_only
            and self.shadow_only
            and not self.policy_authority
            and not self.ci_authority
            and not self.release_authority
            and not self.runtime_verified
        ):
            raise ValueError("evaluation import authority boundary is invalid")
        return self

    def to_quality_report(
        self,
        *,
        corpus: SemanticGateHumanCorpus,
        thresholds: ProviderQualityThresholds | None = None,
    ) -> QualityGateReport:
        """Convert the imported evaluation into the existing P3-18 quality contract."""

        if not isinstance(corpus, SemanticGateHumanCorpus):
            raise TypeError("quality report conversion requires the bound corpus")
        if corpus.corpus_id != self.corpus_id:
            raise ValueError("evaluation import Corpus ID does not match corpus")
        if corpus.corpus_sha256 != self.corpus_sha256:
            raise ValueError("evaluation import Corpus digest does not match corpus")
        thresholds = thresholds or ProviderQualityThresholds()
        metrics = self.evaluation.metrics
        failed: list[str] = []
        reasons: list[str] = []
        if metrics.case_count < thresholds.min_case_count:
            failed.append("gold_labels_valid")
            reasons.append("evaluation_case_count_below_threshold")
        if metrics.failed_case_count:
            failed.append("completed_cases")
            reasons.append("evaluation_case_failures_present")
        if not (
            metrics.precision >= thresholds.min_precision
            and metrics.recall >= thresholds.min_recall
            and metrics.f1 >= thresholds.min_f1
            and metrics.evidence_binding_accuracy
            >= thresholds.min_evidence_binding_accuracy
            and metrics.complete_coverage_rate >= thresholds.min_complete_coverage_rate
        ):
            failed.append("quality_metrics")
            reasons.append("quality_threshold_not_met")
        return QualityGateReport(
            reviewer_id="joint:" + "+".join(self.human_reviewer_ids),
            label_provenance=GoldLabelProvenance.AI_DRAFT_HUMAN_CONFIRMED,
            provider_id=self.provider_id,
            model_id=self.model_id,
            status=QualityGateStatus.QUALIFIED
            if not failed
            else QualityGateStatus.NOT_QUALIFIED,
            thresholds=thresholds,
            metrics={
                "case_count": float(metrics.case_count),
                "completed": float(metrics.completed_case_count),
                "failed": float(metrics.failed_case_count),
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1": metrics.f1,
                "evidence_binding_accuracy": metrics.evidence_binding_accuracy,
                "complete_coverage_rate": metrics.complete_coverage_rate,
            },
            failed_checks=tuple(sorted(set(failed))),
            reasons=tuple(reasons),
        )


class SemanticGateReportOnlyPromotion(_Strict):
    """Explicit report-only promotion evidence, never a production authorization."""

    format: Literal["agentsec-semantic-gate-report-only-promotion"] = (
        "agentsec-semantic-gate-report-only-promotion"
    )
    schema_version: Literal["0.1.0"] = "0.1.0"
    promotion_id: Annotated[str, Field(pattern=_PROMOTION_ID_PATTERN)]
    gate_id: Annotated[str, Field(pattern=r"^SG-[A-Z0-9][A-Z0-9._-]{2,63}$")]
    candidate_id: Annotated[str, Field(pattern=_CANDIDATE_ID_PATTERN)]
    qualification_id: Annotated[
        str, Field(pattern=r"^semantic-gate-qualification-sha256:[0-9a-f]{64}$")
    ]
    qualification_status: Literal[
        "qualified", "conditionally_qualified", "not_qualified"
    ]
    promoted: bool
    report_only: Literal[True] = True
    blocks: Literal[False] = False
    can_block_ci: Literal[False] = False
    can_publish_rule: Literal[False] = False
    can_approve_waiver: Literal[False] = False
    can_grant_runtime_authority: Literal[False] = False

    @model_validator(mode="after")
    def promotion_must_be_coherent(self) -> SemanticGateReportOnlyPromotion:
        expected = _promotion_id(self)
        if self.promotion_id != expected:
            raise ValueError("report-only promotion ID is inconsistent")
        if self.promoted != (self.qualification_status == "qualified"):
            raise ValueError("report-only promotion status is inconsistent")
        return self


def build_semantic_gate_evaluation_import(
    *,
    candidate: SemanticGateCandidate,
    corpus: SemanticGateHumanCorpus,
    evaluation: SemanticEvaluationReport,
    source: SemanticGateEvaluationSource = (
        SemanticGateEvaluationSource.EVALUATION_REPORT
    ),
    human_reviewer_ids: tuple[str, ...] | None = None,
) -> SemanticGateEvaluationImport:
    """Bind an Evaluation Report to the current Candidate and Human Corpus."""

    if not isinstance(candidate, SemanticGateCandidate):
        raise TypeError("evaluation import requires a Semantic Gate candidate")
    if not isinstance(corpus, SemanticGateHumanCorpus):
        raise TypeError("evaluation import requires a Human Corpus")
    if not isinstance(evaluation, SemanticEvaluationReport):
        raise TypeError("evaluation import requires a Provider evaluation report")
    if not corpus.coverage.human_confirmed:
        raise ValueError("evaluation import requires a human-confirmed corpus")
    if corpus.coverage.unknown_count or corpus.coverage.unresolved_count:
        raise ValueError("evaluation import corpus has unknown or unresolved cases")
    expected_case_ids = tuple(case.case_id for case in corpus.cases)
    actual_case_ids = tuple(case.case_id for case in evaluation.cases)
    if actual_case_ids != expected_case_ids:
        raise ValueError("evaluation cases do not exactly match the Human Corpus")
    reviewers = human_reviewer_ids or tuple(
        item.reviewer_id for item in corpus.reviewers
    )
    reviewers = tuple(sorted(set(reviewers)))
    if not reviewers:
        raise ValueError("evaluation import requires human reviewer IDs")
    provisional = SemanticGateEvaluationImport.model_construct(
        evaluation_import_id="semantic-gate-evaluation-import-sha256:" + "0" * 64,
        gate_id=candidate.gate_id,
        candidate_id=candidate.candidate_id,
        corpus_id=corpus.corpus_id,
        corpus_sha256=corpus.corpus_sha256,
        evaluation_report_sha256=_report_sha256(evaluation),
        provider_id=evaluation.provider_id,
        model_id=evaluation.model_id,
        prompt_version=SEMANTIC_PROMPT_VERSION,
        system_prompt_sha256=semantic_system_prompt_sha256(),
        output_schema_sha256=semantic_model_output_schema_sha256(),
        prompt_contract_sha256=_prompt_contract_sha256(
            SEMANTIC_PROMPT_VERSION,
            semantic_system_prompt_sha256(),
            semantic_model_output_schema_sha256(),
        ),
        human_reviewer_ids=reviewers,
        source=source,
        evaluation=evaluation,
        report_only=True,
        shadow_only=True,
        policy_authority=False,
        ci_authority=False,
        rule_authority=False,
        release_authority=False,
        runtime_verified=False,
    )
    evaluation_import_id = _evaluation_import_id(provisional)
    return provisional.model_copy(update={"evaluation_import_id": evaluation_import_id})


def build_import_from_pilot_report(
    *,
    candidate: SemanticGateCandidate,
    corpus: SemanticGateHumanCorpus,
    pilot_report: BaseModel,
) -> SemanticGateEvaluationImport:
    """Import only a completed, live or injected Pilot report."""

    from agentsec.semantic.real_provider_pilot import (
        SemanticGatePilotReport,
        SemanticGatePilotStatus,
    )

    if not isinstance(pilot_report, SemanticGatePilotReport):
        raise TypeError("Pilot import requires SemanticGatePilotReport")
    if pilot_report.status is not SemanticGatePilotStatus.COMPLETED:
        raise ValueError("blocked or failed Pilot cannot be imported")
    if not pilot_report.live_invocation or pilot_report.evaluation is None:
        raise ValueError("Pilot does not contain a completed evaluation")
    if pilot_report.gate_id != candidate.gate_id:
        raise ValueError("Pilot Gate ID does not match candidate")
    if (
        pilot_report.corpus_id != corpus.corpus_id
        or pilot_report.corpus_sha256 != corpus.corpus_sha256
    ):
        raise ValueError("Pilot Corpus binding does not match corpus")
    return build_semantic_gate_evaluation_import(
        candidate=candidate,
        corpus=corpus,
        evaluation=pilot_report.evaluation,
        source=SemanticGateEvaluationSource.REAL_PROVIDER_PILOT,
    )


def qualify_semantic_gate_evaluation(
    *,
    candidate: SemanticGateCandidate,
    corpus: SemanticGateHumanCorpus,
    evaluation_import: SemanticGateEvaluationImport,
    provider_promotion: ProviderPromotionReport | None = None,
    evidence_confidence: SemanticGateEvidenceConfidence | None = None,
    thresholds: ProviderQualityThresholds | None = None,
) -> SemanticGateQualificationReport:
    """Run P3-18 qualification using a bound P3-20 Evaluation Import."""

    if evaluation_import.candidate_id != candidate.candidate_id:
        raise ValueError("evaluation import candidate binding does not match")
    if evaluation_import.gate_id != candidate.gate_id:
        raise ValueError("evaluation import Gate binding does not match")
    quality_report = evaluation_import.to_quality_report(
        corpus=corpus, thresholds=thresholds
    )
    coverage = corpus.coverage
    return SemanticGateQualificationRunner().qualify(
        candidate,
        quality_report=quality_report,
        provider_promotion=provider_promotion,
        evidence_confidence=evidence_confidence,
        human_corpus=corpus,
        positive_case_count=coverage.positive_count,
        eligible_negative_case_count=(
            coverage.eligible_negative_count + coverage.near_miss_count
        ),
    )


def promote_report_only(
    qualification: SemanticGateQualificationReport,
) -> SemanticGateReportOnlyPromotion:
    """Create explicit report-only promotion evidence from a qualification report."""

    if not isinstance(qualification, SemanticGateQualificationReport):
        raise TypeError("promotion requires a Semantic Gate qualification report")
    provisional = SemanticGateReportOnlyPromotion.model_construct(
        promotion_id="semantic-gate-promotion-sha256:" + "0" * 64,
        gate_id=qualification.gate_id,
        candidate_id=qualification.candidate_id,
        qualification_id=qualification.qualification_id,
        qualification_status=qualification.status.value,
        promoted=qualification.eligible_for_report_only_gate,
        report_only=True,
        blocks=False,
        can_block_ci=False,
        can_publish_rule=False,
        can_approve_waiver=False,
        can_grant_runtime_authority=False,
    )
    return provisional.model_copy(update={"promotion_id": _promotion_id(provisional)})


def encode_semantic_gate_evaluation_import_json(
    value: SemanticGateEvaluationImport,
) -> str:
    if not isinstance(value, SemanticGateEvaluationImport):
        raise TypeError(
            "evaluation import encoder requires SemanticGateEvaluationImport"
        )
    return _json(value)


def encode_semantic_gate_promotion_json(
    value: SemanticGateReportOnlyPromotion,
) -> str:
    if not isinstance(value, SemanticGateReportOnlyPromotion):
        raise TypeError("promotion encoder requires SemanticGateReportOnlyPromotion")
    return _json(value)


def render_semantic_gate_evaluation_import_text(
    value: SemanticGateEvaluationImport,
) -> str:
    if not isinstance(value, SemanticGateEvaluationImport):
        raise TypeError(
            "evaluation import renderer requires SemanticGateEvaluationImport"
        )
    metrics = value.evaluation.metrics
    return (
        "\n".join(
            (
                "AgentSec Semantic Gate Provider Evaluation Import",
                f"Gate: {value.gate_id}",
                f"Provider: {value.provider_id}",
                f"Model: {value.model_id}",
                f"Source: {value.source.value}",
                f"Cases: {metrics.case_count}",
                f"Precision: {metrics.precision:.3f}",
                f"Recall: {metrics.recall:.3f}",
                f"F1: {metrics.f1:.3f}",
                f"Corpus: {value.corpus_id}",
                "Authority: report_only=true; shadow_only=true; ci_authority=false",
            )
        )
        + "\n"
    )


def _report_sha256(report: SemanticEvaluationReport) -> str:
    return _canonical_hash(report.model_dump(mode="json"))


def _prompt_contract_sha256(
    prompt_version: str, system_prompt_sha256: str, output_schema_sha256: str
) -> str:
    return _canonical_hash(
        {
            "prompt_version": prompt_version,
            "system_prompt_sha256": system_prompt_sha256,
            "output_schema_sha256": output_schema_sha256,
        }
    )


def _evaluation_import_id(value: SemanticGateEvaluationImport) -> str:
    payload = value.model_dump(mode="json", exclude={"evaluation_import_id"})
    return f"semantic-gate-evaluation-import-sha256:{_canonical_hash(payload)}"


def _promotion_id(value: SemanticGateReportOnlyPromotion) -> str:
    payload = value.model_dump(mode="json", exclude={"promotion_id"})
    return f"semantic-gate-promotion-sha256:{_canonical_hash(payload)}"


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _json(value: BaseModel) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    )


__all__ = [
    "SEMANTIC_GATE_EVALUATION_IMPORT_FORMAT",
    "SEMANTIC_GATE_PROMOTION_FORMAT",
    "SEMANTIC_GATE_EVALUATION_IMPORT_VERSION",
    "SEMANTIC_GATE_PROMOTION_VERSION",
    "SemanticGateEvaluationImport",
    "SemanticGateEvaluationSource",
    "SemanticGateReportOnlyPromotion",
    "build_import_from_pilot_report",
    "build_semantic_gate_evaluation_import",
    "encode_semantic_gate_evaluation_import_json",
    "encode_semantic_gate_promotion_json",
    "promote_report_only",
    "qualify_semantic_gate_evaluation",
    "render_semantic_gate_evaluation_import_text",
]
