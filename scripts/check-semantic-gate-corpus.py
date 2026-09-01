#!/usr/bin/env python3
"""Validate and summarize a P3-19 Gate-scoped human corpus."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.semantic import (  # noqa: E402
    encode_semantic_gate_human_corpus_json,
    load_semantic_gate_human_corpus,
    render_semantic_gate_corpus_text,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--format", choices=("json", "text"), default="text")
    args = parser.parse_args()
    try:
        corpus = load_semantic_gate_human_corpus(args.corpus)
        rendered = (
            encode_semantic_gate_human_corpus_json(corpus)
            if args.format == "json"
            else render_semantic_gate_corpus_text(corpus)
        )
    except (OSError, TypeError, ValueError) as error:
        print(f"P3-19 corpus validation failed: {error}", file=sys.stderr)
        return 2
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
