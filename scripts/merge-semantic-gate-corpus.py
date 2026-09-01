#!/usr/bin/env python3
"""Merge a reviewed P3-19 supplemental corpus into the final corpus."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentsec.semantic import (  # noqa: E402
    encode_semantic_gate_human_corpus_json,
    load_semantic_gate_human_corpus,
    merge_semantic_gate_human_corpora,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--supplement", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        base = load_semantic_gate_human_corpus(args.base)
        supplement = load_semantic_gate_human_corpus(args.supplement)
        merged = merge_semantic_gate_human_corpora(base, supplement)
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output already exists")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            encode_semantic_gate_human_corpus_json(merged), encoding="utf-8"
        )
        args.output.chmod(0o600)
        print(f"Semantic Gate human corpus written: {args.output}")
        return 0
    except (OSError, TypeError, ValueError) as error:
        print(f"P3-19 corpus merge failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
