#!/usr/bin/env python3
"""Bind a Provider Evaluation or completed P3-19 Pilot to a Gate Corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.semantic import (  # noqa: E402
    SemanticGateCandidate,
    SemanticGateEvaluationSource,
    SemanticGateHumanCorpus,
    build_import_from_pilot_report,
    build_semantic_gate_evaluation_import,
    encode_semantic_gate_evaluation_import_json,
    render_semantic_gate_evaluation_import_text,
)
from agentsec.semantic.evaluation import SemanticEvaluationReport  # noqa: E402
from agentsec.semantic.real_provider_pilot import SemanticGatePilotReport  # noqa: E402


def _load(path: Path, model: type[Any]) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4_000_000:
        raise ValueError("evaluation input is missing, unsafe, or oversized")
    try:
        payload: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("evaluation input is unreadable") from error
    return model.model_validate(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--human-corpus", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--evaluation-report", type=Path)
    source.add_argument("--pilot-report", type=Path)
    parser.add_argument("--format", choices=("json", "text"), default="json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        candidate: SemanticGateCandidate = _load(args.candidate, SemanticGateCandidate)
        corpus: SemanticGateHumanCorpus = _load(
            args.human_corpus, SemanticGateHumanCorpus
        )
        if args.pilot_report is not None:
            pilot = _load(args.pilot_report, SemanticGatePilotReport)
            imported = build_import_from_pilot_report(
                candidate=candidate, corpus=corpus, pilot_report=pilot
            )
        else:
            evaluation = _load(args.evaluation_report, SemanticEvaluationReport)
            imported = build_semantic_gate_evaluation_import(
                candidate=candidate,
                corpus=corpus,
                evaluation=evaluation,
                source=SemanticGateEvaluationSource.EVALUATION_REPORT,
            )
        rendered = (
            encode_semantic_gate_evaluation_import_json(imported)
            if args.format == "json"
            else render_semantic_gate_evaluation_import_text(imported)
        )
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output already exists")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        args.output.chmod(0o600)
        print(f"Semantic Gate evaluation import written: {args.output}")
        return 0
    except (OSError, TypeError, ValueError) as error:
        print(f"P3-20 evaluation import failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
