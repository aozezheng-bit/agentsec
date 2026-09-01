#!/usr/bin/env python3
"""Create a digest-bound P3-18 Semantic Gate candidate definition."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.semantic import (  # noqa: E402
    EvidenceConfidenceGrade,
    SemanticGateInput,
    build_semantic_gate_candidate,
    encode_semantic_gate_candidate_json,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--signal", required=True)
    parser.add_argument(
        "--require-human-corpus",
        action="store_true",
        help="Require the P3-19 Gate-scoped human corpus during qualification.",
    )
    parser.add_argument(
        "--minimum-evidence-confidence",
        choices=tuple(item.value for item in EvidenceConfidenceGrade),
        default=EvidenceConfidenceGrade.C.value,
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        candidate = build_semantic_gate_candidate(
            gate_id=args.gate_id,
            title=args.title,
            description=args.description,
            signal=args.signal,
            required_inputs=(
                (
                    SemanticGateInput.HUMAN_CONFIDENCE,
                    SemanticGateInput.HUMAN_CORPUS,
                    SemanticGateInput.PROVIDER_PROMOTION,
                    SemanticGateInput.PROVIDER_QUALITY,
                )
                if args.require_human_corpus
                else None
            ),
            minimum_evidence_confidence=EvidenceConfidenceGrade(
                args.minimum_evidence_confidence
            ),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            encode_semantic_gate_candidate_json(candidate), encoding="utf-8"
        )
    except (OSError, TypeError, ValueError) as error:
        print(f"P3-18 candidate creation failed: {error}", file=sys.stderr)
        return 2
    print(f"Semantic Gate candidate written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
