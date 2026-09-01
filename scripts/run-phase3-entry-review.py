"""Run the deterministic P2-EXIT-08A Phase 3 promotion state machine."""

from __future__ import annotations

import argparse
from pathlib import Path

from agentsec.exit_codes import ExitCode
from agentsec.release_review import (
    DeterministicPhase3EntryReview,
    Phase3EntryReviewRequest,
    Phase3ReviewLanguage,
    Phase3ReviewStage,
    encode_phase3_entry_review_json,
    render_phase3_entry_review_text,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path("."),
        help="AgentSec control/repository root.",
    )
    parser.add_argument(
        "--stage",
        choices=tuple(item.value for item in Phase3ReviewStage),
        default=Phase3ReviewStage.ENTRY_READINESS.value,
        help="Review entry readiness or candidate acceptance.",
    )
    parser.add_argument(
        "--external-pilot-report",
        type=Path,
        help="Reviewed external Pilot JSON for entry_readiness.",
    )
    parser.add_argument(
        "--entry-readiness-report",
        type=Path,
        help="Approved 0.2.0 entry-readiness JSON for candidate_acceptance.",
    )
    parser.add_argument(
        "--candidate-verification-report",
        type=Path,
        help="Candidate package verification JSON for candidate_acceptance.",
    )
    parser.add_argument(
        "--reconciled-candidate-report",
        type=Path,
        help=(
            "P3-REL-03 byte-level reconciliation report for the current "
            "source-reconciled candidate."
        ),
    )
    parser.add_argument(
        "--release-provenance-bundle",
        type=Path,
        help="P3-REL-04 release manifest/provenance bundle JSON.",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--language", choices=("en", "zh"), default="en")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = DeterministicPhase3EntryReview().run(
            Phase3EntryReviewRequest(
                repository_root=args.repository_root,
                stage=Phase3ReviewStage(args.stage),
                external_pilot_report=args.external_pilot_report,
                entry_readiness_report=args.entry_readiness_report,
                candidate_verification_report=args.candidate_verification_report,
                reconciled_candidate_report=args.reconciled_candidate_report,
                release_provenance_bundle=args.release_provenance_bundle,
            )
        )
        rendered = (
            encode_phase3_entry_review_json(report)
            if args.format == "json"
            else render_phase3_entry_review_text(
                report,
                language=Phase3ReviewLanguage(args.language),
            )
        )
        if args.output is None:
            print(rendered, end="")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
    except (OSError, TypeError, ValueError) as error:
        print(f"Phase 3 review configuration error: {error}")
        return int(ExitCode.CONFIGURATION_ERROR)
    return int(
        ExitCode.SUCCESS if report.acceptance_ready else ExitCode.SCAN_INCOMPLETE
    )


if __name__ == "__main__":
    raise SystemExit(main())
