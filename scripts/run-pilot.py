#!/usr/bin/env python3
"""Run a bounded P2-30 AgentSec pilot and write JSON/Markdown evidence."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from agentsec.pilot import (
    PilotError,
    PilotRunner,
    encode_pilot_report_json,
    load_human_labels,
    load_pilot_plan,
    render_pilot_report_markdown,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = REPOSITORY_ROOT / "pilots" / "internal-release-agent" / "pilot.yaml"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "pilots" / "internal-release-agent" / "results"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--agentsec",
        type=Path,
        default=REPOSITORY_ROOT / ".venv" / "bin" / "agentsec",
    )
    parser.add_argument(
        "--target-root",
        type=Path,
        help=(
            "External Agent repository root. Required when the plan uses "
            "evidence_mode=external_repository."
        ),
    )
    parser.add_argument(
        "--trust-root",
        type=Path,
        help=(
            "Protected Policy root, separate from the external target root. "
            "Required for external pilots."
        ),
    )
    parser.add_argument(
        "--human-labels",
        type=Path,
        help="Independent human TP/FP/FN labels JSON under the AgentSec control root.",
    )
    parser.add_argument(
        "--expect-policy-sha256",
        help="Protected SHA-256 pin for the external Pilot Policy.",
    )
    parser.add_argument(
        "--allow-evidence-pending",
        action="store_true",
        help=(
            "Return success for a report-only collection run whose external "
            "human evidence is not complete yet."
        ),
    )
    return parser.parse_args()


def _write(path: Path, content: str) -> None:
    if path.exists() and path.is_symlink():
        raise PilotError(f"refusing symbolic-link pilot report: {path}")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    args = _arguments()
    try:
        loaded = load_pilot_plan(
            args.plan,
            repository_root=REPOSITORY_ROOT,
            target_root=args.target_root,
            trust_root=args.trust_root,
        )
        human_labels = (
            load_human_labels(args.human_labels, repository_root=REPOSITORY_ROOT)
            if args.human_labels is not None
            else None
        )
        output_dir = args.output_dir.resolve()
        if output_dir.exists() and output_dir.is_symlink():
            raise PilotError("pilot report output cannot be a symbolic link")
        output_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="agentsec-pilot-evidence-"
        ) as temporary:
            report = PilotRunner().run(
                loaded,
                repository_root=REPOSITORY_ROOT,
                agentsec_executable=args.agentsec,
                output_root=Path(temporary),
                target_root=args.target_root,
                trust_root=args.trust_root,
                expect_policy_sha256=args.expect_policy_sha256,
                human_labels=human_labels,
            )
        _write(output_dir / "pilot-report.json", encode_pilot_report_json(report))
        _write(output_dir / "pilot-report.md", render_pilot_report_markdown(report))
    except (OSError, PilotError) as error:
        print(f"Pilot failed safely: {error}")
        return 5

    print(
        f"Pilot {report.pilot_id}: {report.metrics.passed_cases}/"
        f"{report.metrics.cases} cases passed; "
        f"FP={report.metrics.false_positives}, "
        f"FN={report.metrics.false_negatives}, "
        f"p95={report.metrics.p95_duration_ms} ms."
    )
    print(f"Reports: {output_dir}")
    if report.status == "complete":
        return 0
    if report.status == "evidence_pending" and args.allow_evidence_pending:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
