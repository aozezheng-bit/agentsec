#!/usr/bin/env python3
"""Import a completed P3-11A human semantic-label submission.

Validates structure, coverage, enum membership, evidence binding, and
deduplication, then emits a machine-readable gold-label case set for
P3-11B. Fails closed on any defect. The submission is read as JSON data
only; no corpus text is copied into the output.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACK = REPOSITORY_ROOT / "pilots" / "semantic-quality-p3-11" / "reviewer-pack"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "pilots" / "semantic-quality-p3-11" / "gold-labels"

VALID_KINDS = {
    "capability_declaration",
    "control_weakening",
    "semantic_conflict",
    "cross_file_chain",
    "risky_intent",
    "ambiguity",
}
VALID_DISPOSITIONS = {"supported", "not_supported", "uncertain"}
VALID_CATEGORIES = {
    "instruction_integrity",
    "human_approval",
    "code_execution",
    "network_access",
    "secret_access",
    "privileged_access",
    "destructive_action",
    "persistent_memory",
    "self_modification",
    "obfuscation",
    "external_tooling",
    "scan_coverage",
    "other",
}


def _fail(message: str) -> int:
    print(f"import failed: {message}")
    return 5


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    pack_cases = json.loads((args.pack / "cases.json").read_text(encoding="utf-8"))[
        "cases"
    ]
    expected_ids = [case["case_id"] for case in pack_cases]
    evidence_lookup = {case["case_id"]: case["evidence_id"] for case in pack_cases}

    try:
        submission = json.loads(args.submission.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return _fail(f"unreadable submission: {error}")

    reviewer_id = submission.get("reviewer_id")
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        return _fail("reviewer_id missing")

    independence_statement = submission.get("independence_statement")
    if (
        not isinstance(independence_statement, str)
        or len(independence_statement.strip()) < 20
    ):
        return _fail("independence_statement missing or too short")

    label_provenance = submission.get("label_provenance", "unspecified")
    if label_provenance not in {
        "human_authored",
        "ai_draft_human_confirmed",
        "ai_assisted",
    }:
        return _fail(f"invalid label_provenance: {label_provenance}")

    cases = submission.get("cases")
    if not isinstance(cases, list) or len(cases) != len(expected_ids):
        return _fail(f"case count mismatch: expected {len(expected_ids)}")

    seen_ids: list[str] = []
    gold: list[dict[str, Any]] = []
    for entry, expected_id in zip(cases, expected_ids, strict=True):
        case_id = entry.get("case_id")
        if case_id != expected_id:
            return _fail(f"case order/id mismatch at {expected_id}: got {case_id}")
        seen_ids.append(case_id)
        expected_evidence = evidence_lookup[case_id]
        if entry.get("evidence_id") != expected_evidence:
            return _fail(f"evidence binding mismatch at {case_id}")
        judgments = entry.get("expected")
        if not isinstance(judgments, list) or not judgments:
            return _fail(f"empty judgments at {case_id}")
        judgment_ids: list[str] = []
        for judgment in judgments:
            judgment_id = judgment.get("judgment_id")
            kind = judgment.get("kind")
            category = judgment.get("category")
            disposition = judgment.get("disposition")
            evidence_ids = judgment.get("evidence_ids")
            if not isinstance(judgment_id, str) or not judgment_id.strip():
                return _fail(f"bad judgment_id at {case_id}")
            if judgment_id in judgment_ids:
                return _fail(f"duplicate judgment_id {judgment_id} at {case_id}")
            judgment_ids.append(judgment_id)
            if kind not in VALID_KINDS:
                return _fail(f"invalid kind {kind} at {case_id}/{judgment_id}")
            if category not in VALID_CATEGORIES:
                return _fail(f"invalid category {category} at {case_id}/{judgment_id}")
            if disposition not in VALID_DISPOSITIONS:
                return _fail(
                    f"invalid disposition {disposition} at {case_id}/{judgment_id}"
                )
            if not isinstance(evidence_ids, list) or not evidence_ids:
                return _fail(f"empty evidence_ids at {case_id}/{judgment_id}")
            for evidence_id in evidence_ids:
                if evidence_id != expected_evidence:
                    return _fail(
                        f"evidence reference {evidence_id} not bound to case {case_id}"
                    )
        gold.append(
            {
                "case_id": case_id,
                "evidence_id": expected_evidence,
                "expected": judgments,
            }
        )

    args.output.mkdir(parents=True, exist_ok=True)
    output_path = args.output / "semantic-gold-labels.json"
    output_path.write_text(
        json.dumps(
            {
                "format": "agentsec-p3-11-semantic-gold-labels",
                "format_version": "0.1.0",
                "reviewer_id": reviewer_id,
                "independence_statement": independence_statement,
                "label_provenance": label_provenance,
                "case_count": len(gold),
                "authority": {"report_only": True, "blocks": False},
                "cases": gold,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"imported {len(gold)} labeled cases from {reviewer_id}")
    print(f"gold labels: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
