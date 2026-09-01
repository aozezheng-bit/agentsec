#!/usr/bin/env python3
"""Run the P3-19 opt-in Real Provider Semantic Gate Pilot.

Without --allow-live this command intentionally exits after a fail-closed
preflight report.  It never stores credentials, prompts, or model responses.
"""

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
    SemanticGatePilotConfig,
    SemanticGatePilotRunner,
    SemanticGatePilotStatus,
    encode_semantic_gate_pilot_json,
    load_semantic_gate_human_corpus,
    render_semantic_gate_pilot_text,
)


def _load_candidate(path: Path) -> SemanticGateCandidate:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
        raise ValueError("Gate candidate is missing, unsafe, or oversized")
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Gate candidate is unreadable") from error
    return SemanticGateCandidate.model_validate(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--gate-candidate", type=Path)
    parser.add_argument("--provider-id", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--endpoint")
    parser.add_argument("--credential-env", required=True)
    parser.add_argument("--allow-live", action="store_true")
    parser.add_argument("--data-residency-approved", action="store_true")
    parser.add_argument("--retention-policy-approved", action="store_true")
    parser.add_argument("--cost-approved", action="store_true")
    parser.add_argument("--review-owner-id")
    parser.add_argument("--approval-id")
    parser.add_argument("--max-cases", type=int, default=40)
    parser.add_argument("--max-calls", type=int, default=40)
    parser.add_argument("--timeout-ms", type=int, default=30_000)
    parser.add_argument("--format", choices=("json", "text"), default="text")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        corpus = load_semantic_gate_human_corpus(args.corpus)
        candidate = (
            _load_candidate(args.gate_candidate) if args.gate_candidate else None
        )
        config = SemanticGatePilotConfig(
            endpoint_url=args.endpoint,
            provider_id=args.provider_id,
            model_id=args.model_id,
            credential_env=args.credential_env,
            corpus_path=str(args.corpus),
            gate_candidate_path=str(args.gate_candidate)
            if args.gate_candidate
            else None,
            max_cases=args.max_cases,
            max_calls=args.max_calls,
            timeout_ms=args.timeout_ms,
            allow_live=args.allow_live,
            data_residency_approved=args.data_residency_approved,
            retention_policy_approved=args.retention_policy_approved,
            cost_approved=args.cost_approved,
            review_owner_id=args.review_owner_id,
            approval_id=args.approval_id,
        )
        report = SemanticGatePilotRunner().run(config, corpus, candidate=candidate)
        rendered = (
            encode_semantic_gate_pilot_json(report)
            if args.format == "json"
            else render_semantic_gate_pilot_text(report)
        )
        if args.output is None:
            print(rendered, end="")
        else:
            if args.output.exists():
                raise ValueError("Pilot output already exists; choose a new path")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
            args.output.chmod(0o600)
            print(f"Pilot report written: {args.output}")
        return 0 if report.status is SemanticGatePilotStatus.COMPLETED else 2
    except (OSError, TypeError, ValueError):
        print("P3-19 Pilot failed safely.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
