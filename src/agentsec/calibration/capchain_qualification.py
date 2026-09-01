"""Report-only qualification of the HG-CAPCHAIN-001 40-case subset."""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, cast

from agentsec.calibration.corpus import LoadedCalibrationCorpus, load_calibration_corpus
from agentsec.calibration.evaluator import DeterministicFactBundleEvaluator

QUALIFICATION_FORMAT = "agentsec-gate-scoped-qualification-report"
QUALIFICATION_SCHEMA_VERSION = "0.1.0"
QUALIFICATION_GATE_ID = "HG-CAPCHAIN-001"
QUALIFICATION_RULE_ID = "CAP-CHAIN-001"
QUALIFICATION_HUMAN_EVIDENCE_FORMAT = "agentsec-gate-scoped-human-resolution-set"
QUALIFICATION_CONFIDENCE_FORMAT = "agentsec-gate-scoped-human-confidence-set"
BLINDING_SALT = "agentsec-p2-cal-04a-reviewer-pack-v2"
REVIEW_CASE_PREFIX = "review-case-"
MIN_POSITIVE_SAMPLES = 20
MIN_NEGATIVE_SAMPLES = 20
MIN_PRECISION = 0.95
MIN_RECALL = 0.90
MIN_REVIEWER_KAPPA = 0.80
MIN_CONFIDENCE_CALIBRATION = 0.90
MAX_JSON_BYTES = 8 * 1024 * 1024


class CapchainQualificationError(ValueError):
    """Raised when the bounded qualification input is invalid."""


def _canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _content_hash_id(payload: dict[str, Any], prefix: str) -> str:
    unsigned = dict(payload)
    unsigned["artifact_id"] = None
    return prefix + hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()


def _artifact_id(payload: dict[str, Any]) -> str:
    return _content_hash_id(payload, "qualification-report-sha256:")


def _human_artifact_id(payload: dict[str, Any]) -> str:
    return _content_hash_id(payload, "human-evidence-sha256:")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CapchainQualificationError(f"{label} is missing or unsafe")
    data = path.read_bytes()
    if len(data) > MAX_JSON_BYTES:
        raise CapchainQualificationError(f"{label} exceeds the bounded size")
    try:
        payload: object = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise CapchainQualificationError(f"{label} is invalid JSON") from error
    if not isinstance(payload, dict):
        raise CapchainQualificationError(f"{label} must be a JSON object")
    return cast(dict[str, Any], payload)


def _write_private(path: Path, text: str) -> None:
    if path.exists() or path.is_symlink():
        raise CapchainQualificationError(f"output already exists: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
    except OSError as error:
        path.unlink(missing_ok=True)
        raise CapchainQualificationError(
            "qualification output cannot be created"
        ) from error


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return round(2 * precision * recall / (precision + recall), 6)


def _kappa(pairs: list[tuple[str, str]]) -> float | None:
    if not pairs:
        return None
    categories = sorted({value for pair in pairs for value in pair})
    n = len(pairs)
    observed = sum(left == right for left, right in pairs) / n
    left_counts = Counter(left for left, _ in pairs)
    right_counts = Counter(right for _, right in pairs)
    expected = sum(
        left_counts[category] * right_counts[category] for category in categories
    ) / (n * n)
    if expected == 1:
        return 1.0 if observed == 1 else 0.0
    return round((observed - expected) / (1 - expected), 6)


def _review_case_map(corpus: LoadedCalibrationCorpus) -> dict[str, Any]:
    return {
        REVIEW_CASE_PREFIX
        + hashlib.sha256(
            f"{BLINDING_SALT}:{corpus.index.corpus_id}:{case.case_id}".encode()
        ).hexdigest()[:20]: case
        for case in corpus.cases
    }


def _validate_common_artifact(
    payload: dict[str, Any], *, expected_format: str, package_id: str, selection_id: str
) -> None:
    if (
        payload.get("format") != expected_format
        or payload.get("schema_version") != "0.1.0"
        or payload.get("gate_id") != QUALIFICATION_GATE_ID
        or payload.get("rule_id") != QUALIFICATION_RULE_ID
        or payload.get("package_id") != package_id
        or payload.get("selection_id") != selection_id
        or payload.get("evidence_mode") != "human"
    ):
        raise CapchainQualificationError("Human Evidence artifact binding is invalid")
    boundary = payload.get("boundary")
    if not isinstance(boundary, dict):
        raise CapchainQualificationError("Human Evidence boundary is invalid")
    if (
        boundary.get("formal_human_evidence") is not True
        or boundary.get("gate_qualification") is not False
        or boundary.get("hard_gate") is not False
        or boundary.get("ci_blocking") is not False
        or boundary.get("ground_truth_used") is not False
        or boundary.get("runtime_capability_verified") is not False
    ):
        raise CapchainQualificationError("Human Evidence boundary is unsafe")
    artifact_id = payload.get("artifact_id")
    if not isinstance(artifact_id, str):
        raise CapchainQualificationError("Human Evidence artifact ID is missing")
    if artifact_id != _human_artifact_id(payload):
        raise CapchainQualificationError("Human Evidence artifact ID is invalid")


def _load_human_evidence(
    evidence_dir: Path,
    confidence_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    resolutions = _read_json(
        evidence_dir / "human-capchain-40-resolutions.json", "Human Resolutions"
    )
    confidence = _read_json(
        confidence_path or evidence_dir / "human-capchain-40-confidence.json",
        "Human Confidence",
    )
    adjudications = _read_json(
        evidence_dir / "human-capchain-40-adjudications.json", "Human Adjudications"
    )
    package_id = resolutions.get("package_id")
    selection_id = resolutions.get("selection_id")
    if not isinstance(package_id, str) or not isinstance(selection_id, str):
        raise CapchainQualificationError("Human Resolution package identity is missing")
    _validate_common_artifact(
        resolutions,
        expected_format=QUALIFICATION_HUMAN_EVIDENCE_FORMAT,
        package_id=package_id,
        selection_id=selection_id,
    )
    _validate_common_artifact(
        confidence,
        expected_format=QUALIFICATION_CONFIDENCE_FORMAT,
        package_id=package_id,
        selection_id=selection_id,
    )
    _validate_common_artifact(
        adjudications,
        expected_format="agentsec-gate-scoped-adjudication-set",
        package_id=package_id,
        selection_id=selection_id,
    )
    resolution_rows = resolutions.get("resolutions")
    confidence_rows = confidence.get("reviews")
    final_confidence = confidence.get("final")
    if (
        not isinstance(resolution_rows, list)
        or len(resolution_rows) != 40
        or not isinstance(confidence_rows, list)
        or len(confidence_rows) != 80
        or not isinstance(final_confidence, list)
        or len(final_confidence) != 40
    ):
        raise CapchainQualificationError("Human Evidence row counts are invalid")
    if len({row.get("review_case_id") for row in resolution_rows}) != 40:
        raise CapchainQualificationError("Human Resolution Case IDs are not unique")
    if len(adjudications.get("adjudications", [])) != 5:
        raise CapchainQualificationError("Human Adjudication count must be five")
    return resolutions, confidence, adjudications


def _qualification_text(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    confusion = report["confusion_matrix"]
    confidence = report["confidence_calibration"]
    agreement = report["reviewer_agreement"]
    qualification = report["qualification"]
    lines = [
        "AgentSec HG-CAPCHAIN-001 Gate Qualification Report",
        "=" * 54,
        "",
        f"Status: {qualification['status']}",
        f"Report-only eligible: {qualification['eligible_for_report_only_gate']}",
        "",
        "Sample scope",
        "------------",
        f"Cases: {report['sample_scope']['case_count']}",
        f"Human Positive: {report['sample_scope']['positive_count']}",
        (
            "Human Negative/Near-miss: "
            f"{report['sample_scope']['negative_or_near_miss_count']}"
        ),
        f"Coverage complete: {report['sample_scope']['coverage_complete']}",
        f"Relevant Unknown free: {report['sample_scope']['unknown_free']}",
        "",
        "Detector metrics",
        "---------------",
        f"TP={confusion['true_positive']} FP={confusion['false_positive']} "
        f"FN={confusion['false_negative']} TN={confusion['true_negative']}",
        f"Precision: {metrics['precision']}",
        f"Recall: {metrics['recall']}",
        f"F1: {metrics['f1']}",
        f"False positive rate: {metrics['false_positive_rate']}",
        "",
        "Evidence Confidence",
        "-------------------",
        f"Human confidence distribution: {confidence['human_distribution']}",
        (
            "Detector match confidence distribution: "
            f"{confidence['detector_distribution']}"
        ),
        (
            "Human vs detector agreement: "
            f"{confidence['human_vs_detector_agreement_rate']}"
        ),
        f"Reviewer Confidence Kappa: {confidence['reviewer_confidence_kappa']}",
        (
            "Correlation agreement before adjudication: "
            f"{agreement['correlation_agreement_rate_before_adjudication']}"
        ),
        (
            "Correlation Kappa before adjudication: "
            f"{agreement['correlation_kappa_before_adjudication']}"
        ),
        "",
        "Qualification checks",
        "--------------------",
    ]
    for name, result in qualification["checks"].items():
        lines.append(f"{name}: {result['status']} ({result['detail']})")
    lines.extend(["", "Blocking reasons"])
    lines.extend(f"- {reason}" for reason in qualification["blocking_reasons"])
    lines.extend(
        [
            "",
            "Policy",
            "------",
            "enforcement_mode: report_only",
            "hard_gate: false",
            "ci_blocking: false",
            "runtime_capability_verified: false",
        ]
    )
    return "\n".join(lines) + "\n"


def build_qualification_report(
    *,
    corpus_path: Path,
    package_dir: Path,
    human_evidence_dir: Path,
    output_json: Path,
    confidence_path: Path | None = None,
    output_text: Path,
) -> dict[str, Any]:
    """Evaluate 40 final human labels against the deterministic Rule replay."""
    corpus = load_calibration_corpus(corpus_path)
    selection = _read_json(package_dir / "selection.json", "subset selection")
    resolutions, confidence, adjudications = _load_human_evidence(
        human_evidence_dir, confidence_path=confidence_path
    )
    if selection.get("selection_id") != resolutions.get("selection_id"):
        raise CapchainQualificationError("selection and Human Evidence IDs differ")
    resolution_by_case = {
        row["review_case_id"]: row for row in resolutions["resolutions"]
    }
    confidence_reviews = confidence["reviews"]
    confidence_final = {row["review_case_id"]: row for row in confidence["final"]}
    reviewer_pairs: dict[str, dict[str, dict[str, Any]]] = {}
    for row in confidence_reviews:
        reviewer_pairs.setdefault(row["review_case_id"], {})[row["reviewer_id"]] = row
    case_map = _review_case_map(corpus)
    evaluator = DeterministicFactBundleEvaluator()
    case_results: list[dict[str, Any]] = []
    confusion = Counter[str]()
    human_confidence: Counter[str] = Counter()
    detector_confidence: Counter[str] = Counter()
    confidence_pairs: list[tuple[str, str]] = []
    reviewer_confidence_pairs: list[tuple[str, str]] = []
    correlation_pairs: list[tuple[str, str]] = []
    coverage_complete = True
    unknown_free = True
    for item in selection.get("items", []):
        if not isinstance(item, dict):
            raise CapchainQualificationError("selection item is invalid")
        review_case_id = item.get("review_case_id")
        if not isinstance(review_case_id, str) or review_case_id not in case_map:
            raise CapchainQualificationError(
                "selection Case cannot be mapped to Corpus"
            )
        human = resolution_by_case.get(review_case_id)
        if human is None:
            raise CapchainQualificationError("Human Resolution is missing a Case")
        case = case_map[review_case_id]
        expectation = next(
            (
                value
                for value in case.ground_truth.rule_expectations
                if value.rule_id == QUALIFICATION_RULE_ID
            ),
            None,
        )
        if expectation is None:
            raise CapchainQualificationError("Corpus Case lacks CAP-CHAIN-001")
        observation = evaluator.evaluate(
            corpus_root=corpus.root,
            case=case,
            expectation=expectation,
        )
        human_label = human.get("human_condition_label")
        detector_label = observation.outcome.value
        if human_label not in {"match", "no_match"}:
            raise CapchainQualificationError(
                "uncertain Human Resolution cannot qualify"
            )
        if human_label == "match" and detector_label == "match":
            classification = "true_positive"
        elif human_label == "match" and detector_label == "no_match":
            classification = "false_negative"
        elif human_label == "no_match" and detector_label == "match":
            classification = "false_positive"
        else:
            classification = "true_negative"
        confusion[classification] += 1
        coverage_value = case.ground_truth.coverage
        coverage = str(getattr(coverage_value, "value", coverage_value))
        unknowns = [
            str(getattr(item, "value", item))
            for item in case.ground_truth.unknown_dimensions
        ]
        coverage_complete = coverage_complete and coverage == "complete"
        unknown_free = unknown_free and not unknowns
        final_confidence_row = confidence_final.get(review_case_id)
        if final_confidence_row is None:
            raise CapchainQualificationError("final Confidence is missing a Case")
        human_confidence_value = final_confidence_row["confidence"]
        human_confidence[human_confidence_value] += 1
        match_detector_confidence = (
            observation.confidences[0].value if observation.confidences else None
        )
        if human_label == "match":
            if match_detector_confidence is None:
                raise CapchainQualificationError("detector match lacks Confidence")
            detector_confidence[match_detector_confidence] += 1
            confidence_pairs.append((human_confidence_value, match_detector_confidence))
        pair = reviewer_pairs.get(review_case_id, {})
        if set(pair) != {"reviewer-a", "reviewer-b"}:
            raise CapchainQualificationError("Confidence artifact lacks A/B pair")
        reviewer_confidence_pairs.append(
            (pair["reviewer-a"]["confidence"], pair["reviewer-b"]["confidence"])
        )
        correlation_pairs.append(
            (pair["reviewer-a"]["correlation"], pair["reviewer-b"]["correlation"])
        )
        if final_confidence_row["rule_id"] != QUALIFICATION_RULE_ID:
            raise CapchainQualificationError("final Confidence Rule binding is invalid")
        case_results.append(
            {
                "sequence": item.get("sequence"),
                "review_case_id": review_case_id,
                "corpus_case_id": case.case_id,
                "case_kind": case.case_kind.value,
                "human_condition_label": human_label,
                "detector_outcome": detector_label,
                "classification": classification,
                "coverage": coverage,
                "unknown_dimensions": unknowns,
                "human_confidence": human_confidence_value,
                "detector_confidence": match_detector_confidence,
                "final_correlation": human["correlation"],
                "adjudication_required": human["adjudication_required"],
            }
        )
    positive_count = sum(
        row["human_condition_label"] == "match" for row in case_results
    )
    negative_count = sum(
        row["human_condition_label"] == "no_match" for row in case_results
    )
    precision = _rate(
        confusion["true_positive"],
        confusion["true_positive"] + confusion["false_positive"],
    )
    recall = _rate(
        confusion["true_positive"],
        confusion["true_positive"] + confusion["false_negative"],
    )
    f1 = _f1(precision, recall)
    false_positive_rate = _rate(
        confusion["false_positive"],
        confusion["false_positive"] + confusion["true_negative"],
    )
    reviewer_kappa = _kappa(reviewer_confidence_pairs)
    confidence_calibration_rate = _rate(
        sum(left == right for left, right in confidence_pairs), len(confidence_pairs)
    )
    correlation_agreement_rate = _rate(
        sum(left == right for left, right in correlation_pairs), len(correlation_pairs)
    )
    correlation_kappa = _kappa(correlation_pairs)
    d_confidence_count = sum(value == "D" for value in human_confidence.elements())
    checks: dict[str, dict[str, Any]] = {
        "sample_threshold": {
            "status": "pass"
            if positive_count >= MIN_POSITIVE_SAMPLES
            and negative_count >= MIN_NEGATIVE_SAMPLES
            else "fail",
            "detail": (
                f"positive={positive_count}/{MIN_POSITIVE_SAMPLES}, "
                "negative_or_near_miss="
                f"{negative_count}/{MIN_NEGATIVE_SAMPLES}"
            ),
        },
        "precision": {
            "status": "pass"
            if precision is not None and precision >= MIN_PRECISION
            else "fail",
            "detail": f"{precision} >= {MIN_PRECISION}",
        },
        "recall": {
            "status": "pass" if recall is not None and recall >= MIN_RECALL else "fail",
            "detail": f"{recall} >= {MIN_RECALL}",
        },
        "reviewer_confidence_kappa": {
            "status": "pass"
            if reviewer_kappa is not None and reviewer_kappa >= MIN_REVIEWER_KAPPA
            else "fail",
            "detail": f"{reviewer_kappa} >= {MIN_REVIEWER_KAPPA}",
        },
        "coverage": {
            "status": "pass" if coverage_complete else "fail",
            "detail": str(coverage_complete),
        },
        "relevant_unknowns": {
            "status": "pass" if unknown_free else "fail",
            "detail": str(unknown_free),
        },
        "d_confidence_exclusion": {
            "status": "pass" if d_confidence_count == 0 else "fail",
            "detail": f"D confidence count={d_confidence_count}",
        },
        "confidence_calibration": {
            "status": "pass"
            if confidence_calibration_rate is not None
            and confidence_calibration_rate >= MIN_CONFIDENCE_CALIBRATION
            else "fail",
            "detail": (
                f"human_vs_detector={confidence_calibration_rate} >= "
                f"{MIN_CONFIDENCE_CALIBRATION}"
            ),
        },
    }
    blocking_reasons = [
        f"{name}-below-threshold"
        for name, value in checks.items()
        if value["status"] == "fail"
    ]
    qualification_status = "accepted" if not blocking_reasons else "more_data_required"
    report: dict[str, Any] = {
        "format": QUALIFICATION_FORMAT,
        "schema_version": QUALIFICATION_SCHEMA_VERSION,
        "status": "complete",
        "gate_id": QUALIFICATION_GATE_ID,
        "rule_id": QUALIFICATION_RULE_ID,
        "evidence_mode": "human",
        "package_id": resolutions["package_id"],
        "selection_id": resolutions["selection_id"],
        "human_evidence_artifact_id": resolutions["artifact_id"],
        "source_corpus_id": corpus.index.corpus_id,
        "detector": {
            "evaluator_id": evaluator.evaluator_id,
            "evaluator_version": evaluator.evaluator_version,
        },
        "thresholds": {
            "min_positive_samples": MIN_POSITIVE_SAMPLES,
            "min_negative_or_near_miss_samples": MIN_NEGATIVE_SAMPLES,
            "min_precision": MIN_PRECISION,
            "min_recall": MIN_RECALL,
            "min_reviewer_kappa": MIN_REVIEWER_KAPPA,
            "min_confidence_calibration": MIN_CONFIDENCE_CALIBRATION,
        },
        "sample_scope": {
            "case_count": len(case_results),
            "positive_count": positive_count,
            "negative_or_near_miss_count": negative_count,
            "coverage_complete": coverage_complete,
            "unknown_free": unknown_free,
            "adjudication_count": len(adjudications.get("adjudications", [])),
            "case_kinds": dict(
                sorted(Counter(row["case_kind"] for row in case_results).items())
            ),
        },
        "confusion_matrix": {
            "true_positive": confusion["true_positive"],
            "false_positive": confusion["false_positive"],
            "false_negative": confusion["false_negative"],
            "true_negative": confusion["true_negative"],
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": false_positive_rate,
        },
        "reviewer_agreement": {
            "decision_field_agreement_after_adjudication": 1.0,
            "confidence_agreement_rate": _rate(
                sum(left == right for left, right in reviewer_confidence_pairs),
                len(reviewer_confidence_pairs),
            ),
            "confidence_kappa": reviewer_kappa,
            "correlation_agreement_rate_before_adjudication": (
                correlation_agreement_rate
            ),
            "correlation_kappa_before_adjudication": correlation_kappa,
            "adjudication_count": len(adjudications.get("adjudications", [])),
        },
        "confidence_calibration": {
            "human_distribution": dict(sorted(human_confidence.items())),
            "detector_distribution": dict(sorted(detector_confidence.items())),
            "items": len(confidence_pairs),
            "human_vs_detector_agreement_count": sum(
                left == right for left, right in confidence_pairs
            ),
            "human_vs_detector_agreement_rate": confidence_calibration_rate,
            "human_vs_detector_kappa": _kappa(confidence_pairs),
            "reviewer_confidence_kappa": reviewer_kappa,
        },
        "qualification": {
            "status": qualification_status,
            "eligible_for_report_only_gate": qualification_status == "accepted",
            "checks": checks,
            "blocking_reasons": blocking_reasons,
        },
        "policy": {
            "enforcement_mode": "report_only",
            "hard_gate": False,
            "ci_blocking": False,
            "fail_on": False,
            "runtime_capability_verified": False,
            "llm_used": False,
        },
        "limitations": [
            (
                "This is a 40-case minimum pilot subset, not the complete "
                "431-case independent-review population."
            ),
            (
                "The deterministic evaluator is fact-bundle replay and does not "
                "measure parser or Framework Adapter recall."
            ),
            "Runtime Tool, OAuth, Permission, and exploitability were not verified.",
            "A static Capability Rule cannot authorize a production action.",
        ],
        "cases": case_results,
        "artifact_id": None,
    }
    report["artifact_id"] = _artifact_id(report)
    _write_private(
        output_json,
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    try:
        _write_private(output_text, _qualification_text(report))
    except Exception:
        output_json.unlink(missing_ok=True)
        raise
    return report
