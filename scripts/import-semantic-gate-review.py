#!/usr/bin/env python3
"""Import independent P3-19 Semantic Gate reviews and adjudications."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.semantic import (  # noqa: E402
    SemanticGateAdjudication,
    SemanticGateHumanCorpus,
    encode_semantic_gate_human_corpus_json,
    import_semantic_gate_review,
    load_semantic_gate_human_corpus,
    load_semantic_gate_review_submission,
)


def _read_adjudications(path: Path) -> tuple[SemanticGateAdjudication, ...]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise ValueError("adjudication input is missing, unsafe, or oversized")
    try:
        payload: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("adjudication input is unreadable") from error
    if isinstance(payload, dict):
        payload = payload.get("adjudications")
    if not isinstance(payload, list):
        raise ValueError("adjudication input must contain an adjudications array")
    return tuple(SemanticGateAdjudication.model_validate(item) for item in payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--review", type=Path, action="append", required=True)
    parser.add_argument("--adjudications", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        corpus: SemanticGateHumanCorpus = load_semantic_gate_human_corpus(args.corpus)
        submissions = tuple(
            load_semantic_gate_review_submission(path) for path in args.review
        )
        adjudications = (
            _read_adjudications(args.adjudications)
            if args.adjudications is not None
            else ()
        )
        imported = import_semantic_gate_review(
            corpus,
            reviewer_submissions=submissions,
            adjudications=adjudications,
        )
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output already exists")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            encode_semantic_gate_human_corpus_json(imported), encoding="utf-8"
        )
        args.output.chmod(0o600)
        print(f"Semantic Gate human corpus written: {args.output}")
        return 0
    except (OSError, TypeError, ValueError) as error:
        print(f"P3-19 review import failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
