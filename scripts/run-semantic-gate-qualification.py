#!/usr/bin/env python3
"""Run deterministic, report-only P3-18 Semantic Gate qualification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.semantic import (  # noqa: E402
    ProviderPromotionReport,
    QualityGateReport,
    SemanticCandidateCalibrationReport,
    SemanticFindingPromotionReport,
    SemanticGateCandidate,
    SemanticGateEvaluationImport,
    SemanticGateEvidenceConfidence,
    SemanticGateHumanCorpus,
    SemanticGateQualificationRunner,
    SemanticRulePromotionReport,
    encode_semantic_gate_promotion_json,
    encode_semantic_gate_qualification_json,
    promote_report_only,
    qualify_semantic_gate_evaluation,
    render_semantic_gate_qualification_text,
)


def _load[T](path: Path, model: type[T]) -> T:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
        raise ValueError("qualification input is missing, unsafe, or oversized")
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("qualification input is unreadable") from error
    return model.model_validate(payload)  # type: ignore[union-attr]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--quality-report", type=Path)
    parser.add_argument("--evaluation-import", type=Path)
    parser.add_argument("--provider-promotion", type=Path)
    parser.add_argument("--candidate-calibration", type=Path)
    parser.add_argument("--finding-promotion", type=Path)
    parser.add_argument("--rule-staging", type=Path)
    parser.add_argument("--evidence-confidence", type=Path)
    parser.add_argument("--human-corpus", type=Path)
    parser.add_argument("--positive-cases", type=int)
    parser.add_argument("--eligible-negative-cases", type=int)
    parser.add_argument("--unevaluated-cases", type=int, default=0)
    parser.add_argument("--format", choices=("json", "text"), default="text")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--promotion-output", type=Path)
    args = parser.parse_args()
    try:
        candidate: SemanticGateCandidate = _load(args.candidate, SemanticGateCandidate)
        if args.evaluation_import is not None:
            if args.human_corpus is None:
                raise ValueError("--human-corpus is required with --evaluation-import")
            corpus: SemanticGateHumanCorpus = _load(
                args.human_corpus, SemanticGateHumanCorpus
            )
            imported: SemanticGateEvaluationImport = _load(
                args.evaluation_import, SemanticGateEvaluationImport
            )
            report = qualify_semantic_gate_evaluation(
                candidate=candidate,
                corpus=corpus,
                evaluation_import=imported,
                provider_promotion=(
                    _load(args.provider_promotion, ProviderPromotionReport)
                    if args.provider_promotion
                    else None
                ),
                evidence_confidence=(
                    _load(args.evidence_confidence, SemanticGateEvidenceConfidence)
                    if args.evidence_confidence
                    else None
                ),
            )
        else:
            if args.quality_report is None:
                raise ValueError("--quality-report or --evaluation-import is required")
            if args.positive_cases is None or args.eligible_negative_cases is None:
                raise ValueError(
                    "--positive-cases and --eligible-negative-cases are required "
                    "without --evaluation-import"
                )
            report = SemanticGateQualificationRunner().qualify(
                candidate,
                quality_report=_load(args.quality_report, QualityGateReport),
                provider_promotion=(
                    _load(args.provider_promotion, ProviderPromotionReport)
                    if args.provider_promotion
                    else None
                ),
                candidate_calibration=(
                    _load(
                        args.candidate_calibration, SemanticCandidateCalibrationReport
                    )
                    if args.candidate_calibration
                    else None
                ),
                finding_promotion=(
                    _load(args.finding_promotion, SemanticFindingPromotionReport)
                    if args.finding_promotion
                    else None
                ),
                rule_staging=(
                    _load(args.rule_staging, SemanticRulePromotionReport)
                    if args.rule_staging
                    else None
                ),
                evidence_confidence=(
                    _load(args.evidence_confidence, SemanticGateEvidenceConfidence)
                    if args.evidence_confidence
                    else None
                ),
                human_corpus=(
                    _load(args.human_corpus, SemanticGateHumanCorpus)
                    if args.human_corpus
                    else None
                ),
                positive_case_count=args.positive_cases,
                eligible_negative_case_count=args.eligible_negative_cases,
                unevaluated_case_count=args.unevaluated_cases,
            )
        rendered = (
            encode_semantic_gate_qualification_json(report)
            if args.format == "json"
            else render_semantic_gate_qualification_text(report)
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        if args.promotion_output is not None:
            promotion = promote_report_only(report)
            if args.promotion_output.exists() or args.promotion_output.is_symlink():
                raise ValueError("promotion output already exists")
            args.promotion_output.parent.mkdir(parents=True, exist_ok=True)
            args.promotion_output.write_text(
                encode_semantic_gate_promotion_json(promotion), encoding="utf-8"
            )
            args.promotion_output.chmod(0o600)
    except (OSError, TypeError, ValueError) as error:
        print(f"P3-18 qualification failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
