#!/usr/bin/env python3
"""Import one complete independent P2-EXIT-06 Homi review submission."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentsec.external_pilot import (
    ExternalPilotWorkflowError,
    import_external_review_submission,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACK = (
    REPOSITORY_ROOT / "pilots" / "external-homi-demo" / "final-pilot" / "reviewer-pack"
)
DEFAULT_OUTPUT = (
    REPOSITORY_ROOT / "pilots" / "external-homi-demo" / "final-pilot" / "human-evidence"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewer-pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    try:
        args.output_root.resolve().relative_to(REPOSITORY_ROOT.resolve())
        report = import_external_review_submission(
            reviewer_pack_root=args.reviewer_pack,
            submission_path=args.submission,
            output_root=args.output_root,
        )
    except (OSError, RuntimeError, ValueError, ExternalPilotWorkflowError) as error:
        print(f"Review import failed safely: {error}")
        return 5
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(
            f"Imported {report['reviewed_cases']} independently reviewed cases "
            f"from reviewer {report['reviewer_id']}."
        )
        print(f"Human labels: {args.output_root / 'human-labels.json'}")
        print("Final acceptance replay is still required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
