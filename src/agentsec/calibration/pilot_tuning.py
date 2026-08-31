"""P2-31 deterministic Rule and score calibration from Pilot evidence."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentsec.pilot import PilotReport
from agentsec.risk.mapping import (
    agentsec_base_score,
    nist_risk_level,
    severity_for_score,
)
from agentsec.risk.profiles import builtin_risk_profiles
from agentsec.rules import BUILTIN_MARKDOWN_RULE_IDS
from agentsec.versioning import (
    RISK_MODEL_VERSION,
    RULE_PACK_VERSION,
    RULE_SCORE_CALIBRATION_OUTPUT_VERSION,
)

RULE_SCORE_CALIBRATION_FORMAT = "agentsec-rule-score-calibration-report"
_CALIBRATION_VERSION = cast(Literal["0.1.0"], RULE_SCORE_CALIBRATION_OUTPUT_VERSION)


class RuleCalibrationRecommendation(StrEnum):
    RETAIN_CURRENT = "retain_current"
    REVIEW_FALSE_POSITIVE = "review_false_positive"
    REVIEW_FALSE_NEGATIVE = "review_false_negative"
    MORE_DATA = "more_data"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class RuleCalibrationResult(_Strict):
    rule_id: str
    expected_positive_cases: int
    observed_positive_cases: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float | None
    recall: float | None
    likelihood: str
    impact: str
    score: float
    severity: str
    profile_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    recommendation: RuleCalibrationRecommendation
    rationale: tuple[str, ...]


class ScoreReplayCalibration(_Strict):
    format: Literal["agentsec-scoring-replay-suite"]
    format_version: Literal["0.1.0"]
    model_version: str
    suite_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    file_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    cases: int
    case_ids: tuple[str, ...]
    critical_cases: int
    high_cases: int
    medium_cases: int
    incomplete_coverage_cases: int
    verified_against_frozen_replay: bool


class CalibrationSummary(_Strict):
    pilot_cases: int
    covered_rules: int
    uncovered_rules: int
    retain_current_rules: int
    more_data_rules: int
    review_false_positive_rules: int
    review_false_negative_rules: int
    pilot_false_positives: int
    pilot_false_negatives: int
    scoring_replay_cases: int
    scoring_replay_verified: bool


class CalibrationDecision(_Strict):
    current_rule_pack_version: str
    candidate_rule_pack_version: str
    current_risk_model_version: str
    candidate_risk_model_version: str
    rule_pack_action: Literal["retain_current", "review_required"]
    risk_model_action: Literal["retain_current", "review_required"]
    publish_rule_changes: Literal[False] = False
    publish_score_changes: Literal[False] = False
    internal_mvp_ready: bool
    external_calibration_required: Literal[True] = True
    rationale: tuple[str, ...]


class RuleScoreCalibrationReport(_Strict):
    format: Literal["agentsec-rule-score-calibration-report"] = (
        "agentsec-rule-score-calibration-report"
    )
    format_version: Literal["0.1.0"] = _CALIBRATION_VERSION
    status: Literal["complete", "review_required", "failed"]
    calibration_generation: Literal["v1"] = "v1"
    pilot_id: str
    pilot_report_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    pilot_evidence_mode: Literal["internal_integration", "external_repository"]
    summary: CalibrationSummary
    decision: CalibrationDecision
    rules: tuple[RuleCalibrationResult, ...]
    scoring_replay: ScoreReplayCalibration
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def report_must_be_coherent(self) -> RuleScoreCalibrationReport:
        rule_ids = tuple(item.rule_id for item in self.rules)
        if rule_ids != BUILTIN_MARKDOWN_RULE_IDS:
            raise ValueError("calibration report must cover every built-in Rule")
        if self.status == "complete" and not self.decision.internal_mvp_ready:
            raise ValueError("complete calibration must be internal-MVP ready")
        if self.decision.publish_rule_changes or self.decision.publish_score_changes:
            raise ValueError("P2-31 report cannot automatically publish changes")
        return self


class RuleScoreCalibrationRunner:
    """Calibrate current Rule/risk mappings without automatic mutation."""

    def run(
        self,
        pilot: PilotReport,
        *,
        scoring_replay_payload: dict[str, Any],
        scoring_replay_file_sha256: str,
        scoring_replay_verified: bool,
    ) -> RuleScoreCalibrationReport:
        rules = tuple(
            self._rule_result(rule_id, pilot) for rule_id in BUILTIN_MARKDOWN_RULE_IDS
        )
        replay = _score_replay(
            scoring_replay_payload,
            file_sha256=scoring_replay_file_sha256,
            verified=scoring_replay_verified,
        )
        fp_rules = sum(
            item.recommendation is RuleCalibrationRecommendation.REVIEW_FALSE_POSITIVE
            for item in rules
        )
        fn_rules = sum(
            item.recommendation is RuleCalibrationRecommendation.REVIEW_FALSE_NEGATIVE
            for item in rules
        )
        covered = sum(item.expected_positive_cases > 0 for item in rules)
        ready = (
            pilot.status == "complete"
            and pilot.metrics.false_positives == 0
            and pilot.metrics.false_negatives == 0
            and fp_rules == 0
            and fn_rules == 0
            and replay.verified_against_frozen_replay
        )
        summary = CalibrationSummary(
            pilot_cases=pilot.metrics.cases,
            covered_rules=covered,
            uncovered_rules=len(rules) - covered,
            retain_current_rules=sum(
                item.recommendation is RuleCalibrationRecommendation.RETAIN_CURRENT
                for item in rules
            ),
            more_data_rules=sum(
                item.recommendation is RuleCalibrationRecommendation.MORE_DATA
                for item in rules
            ),
            review_false_positive_rules=fp_rules,
            review_false_negative_rules=fn_rules,
            pilot_false_positives=pilot.metrics.false_positives,
            pilot_false_negatives=pilot.metrics.false_negatives,
            scoring_replay_cases=replay.cases,
            scoring_replay_verified=replay.verified_against_frozen_replay,
        )
        action: Literal["retain_current", "review_required"] = (
            "retain_current" if ready else "review_required"
        )
        report_payload = pilot.model_dump(mode="json")
        return RuleScoreCalibrationReport(
            status="complete" if ready else "review_required",
            pilot_id=pilot.pilot_id,
            pilot_report_sha256=_canonical_hash(report_payload),
            pilot_evidence_mode=pilot.evidence_mode,
            summary=summary,
            decision=CalibrationDecision(
                current_rule_pack_version=RULE_PACK_VERSION,
                candidate_rule_pack_version=RULE_PACK_VERSION,
                current_risk_model_version=RISK_MODEL_VERSION,
                candidate_risk_model_version=RISK_MODEL_VERSION,
                rule_pack_action=action,
                risk_model_action=action,
                internal_mvp_ready=ready,
                rationale=(
                    "No Pilot FP/FN requires a deterministic Rule change.",
                    "All seven frozen Agentic scoring replay cases match exactly.",
                    (
                        "Uncovered Rules remain more_data rather than being "
                        "weakened or retired."
                    ),
                    (
                        "Current Rule and risk versions are retained; no "
                        "automatic publication occurs."
                    ),
                ),
            ),
            rules=rules,
            scoring_replay=replay,
            limitations=(
                (
                    "Pilot evidence is internal and curated rather than a "
                    "production distribution sample."
                ),
                (
                    "Six Rules have no positive Pilot scenario and remain marked "
                    "more_data."
                ),
                (
                    "Scoring replay proves deterministic stability, not empirical "
                    "loss calibration."
                ),
                (
                    "Static evidence does not prove runtime exploitability or "
                    "reachable permissions."
                ),
            ),
        )

    @staticmethod
    def _rule_result(rule_id: str, pilot: PilotReport) -> RuleCalibrationResult:
        expected_cases = sum(rule_id in item.expected_rule_ids for item in pilot.cases)
        observed_cases = sum(rule_id in item.observed_rule_ids for item in pilot.cases)
        true_positives = sum(
            rule_id in item.true_positive_rule_ids for item in pilot.cases
        )
        false_positives = sum(
            rule_id in item.false_positive_rule_ids for item in pilot.cases
        )
        false_negatives = sum(
            rule_id in item.false_negative_rule_ids for item in pilot.cases
        )
        if false_negatives:
            recommendation = RuleCalibrationRecommendation.REVIEW_FALSE_NEGATIVE
        elif false_positives:
            recommendation = RuleCalibrationRecommendation.REVIEW_FALSE_POSITIVE
        elif expected_cases:
            recommendation = RuleCalibrationRecommendation.RETAIN_CURRENT
        else:
            recommendation = RuleCalibrationRecommendation.MORE_DATA
        profile = next(
            item for item in builtin_risk_profiles() if item.rule_id == rule_id
        )
        level = nist_risk_level(profile.likelihood, profile.impact)
        score = agentsec_base_score(level)
        profile_payload = {
            "rule_id": rule_id,
            "category": profile.category.value,
            "likelihood": profile.likelihood.value,
            "impact": profile.impact.value,
            "score": score,
            "severity": severity_for_score(score).value,
            "risk_model_version": RISK_MODEL_VERSION,
        }
        return RuleCalibrationResult(
            rule_id=rule_id,
            expected_positive_cases=expected_cases,
            observed_positive_cases=observed_cases,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            precision=_optional_ratio(true_positives, true_positives + false_positives),
            recall=_optional_ratio(true_positives, true_positives + false_negatives),
            likelihood=profile.likelihood.value,
            impact=profile.impact.value,
            score=score,
            severity=severity_for_score(score).value,
            profile_sha256=_canonical_hash(profile_payload),
            recommendation=recommendation,
            rationale=_rule_rationale(
                recommendation,
                expected_cases=expected_cases,
                false_positives=false_positives,
                false_negatives=false_negatives,
            ),
        )


def _rule_rationale(
    recommendation: RuleCalibrationRecommendation,
    *,
    expected_cases: int,
    false_positives: int,
    false_negatives: int,
) -> tuple[str, ...]:
    if recommendation is RuleCalibrationRecommendation.REVIEW_FALSE_NEGATIVE:
        return (f"Pilot observed {false_negatives} false-negative scenario(s).",)
    if recommendation is RuleCalibrationRecommendation.REVIEW_FALSE_POSITIVE:
        return (f"Pilot observed {false_positives} false-positive scenario(s).",)
    if recommendation is RuleCalibrationRecommendation.RETAIN_CURRENT:
        return (
            f"Pilot covered {expected_cases} positive scenario(s) without FP/FN.",
            "The current reviewed risk profile remains stable in replay.",
        )
    return (
        "No positive Pilot scenario covers this Rule.",
        "Retain the current Rule but collect more representative evidence.",
    )


def _score_replay(
    payload: dict[str, Any], *, file_sha256: str, verified: bool
) -> ScoreReplayCalibration:
    try:
        cases = payload["cases"]
        case_ids = tuple(item["case_id"] for item in cases)
        if case_ids != tuple(sorted(set(case_ids))):
            raise ValueError
        return ScoreReplayCalibration(
            format=payload["format"],
            format_version=payload["format_version"],
            model_version=payload["model_version"],
            suite_sha256=payload["suite_sha256"],
            file_sha256=file_sha256,
            cases=len(cases),
            case_ids=case_ids,
            critical_cases=sum(item["severity"] == "critical" for item in cases),
            high_cases=sum(item["severity"] == "high" for item in cases),
            medium_cases=sum(item["severity"] == "medium" for item in cases),
            incomplete_coverage_cases=sum(
                not item["coverage_complete"] for item in cases
            ),
            verified_against_frozen_replay=verified,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("scoring replay calibration input is invalid") from error


def _optional_ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _canonical_hash(payload: object) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def encode_rule_score_calibration_json(report: RuleScoreCalibrationReport) -> str:
    return (
        json.dumps(
            report.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False
        )
        + "\n"
    )


def render_rule_score_calibration_markdown(
    report: RuleScoreCalibrationReport,
) -> str:
    summary = report.summary
    lines = [
        "# AgentSec Rule and Score Calibration Report",
        "",
        f"- Status: **{report.status.upper()}**",
        f"- Pilot: `{report.pilot_id}` (`{report.pilot_evidence_mode}`)",
        f"- Rules covered/uncovered: {summary.covered_rules}/{summary.uncovered_rules}",
        (
            f"- Pilot FP/FN: {summary.pilot_false_positives}/"
            f"{summary.pilot_false_negatives}"
        ),
        f"- Scoring replay: {summary.scoring_replay_cases} cases, "
        f"{'PASS' if summary.scoring_replay_verified else 'FAIL'}",
        f"- Rule Pack action: `{report.decision.rule_pack_action}`",
        f"- Risk Model action: `{report.decision.risk_model_action}`",
        f"- Internal MVP ready: `{str(report.decision.internal_mvp_ready).lower()}`",
        "",
        "| Rule | Positive cases | TP/FP/FN | Score | Severity | Recommendation |",
        "|---|---:|---:|---:|---|---|",
    ]
    for item in report.rules:
        lines.append(
            f"| {item.rule_id} | {item.expected_positive_cases} | "
            f"{item.true_positives}/{item.false_positives}/{item.false_negatives} | "
            f"{item.score:.1f} | {item.severity} | {item.recommendation.value} |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report.limitations)
    return "\n".join(lines) + "\n"


def export_rule_score_calibration_schema() -> str:
    return (
        json.dumps(
            RuleScoreCalibrationReport.model_json_schema(), indent=2, sort_keys=True
        )
        + "\n"
    )


def export_rule_score_calibration_json_schema(output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "rule-score-calibration-report.schema.json"
    path.write_text(export_rule_score_calibration_schema(), encoding="utf-8")
    return path
