#!/usr/bin/env python3
"""Build the P3-13 InjecAgent-style tool-injection scenario pack.

Each scenario records one benign task and one task whose injected content
expects a supported tool-integration judgment (code execution, network
access, external tooling, secret access, or destructive action), taken
from the P3-11A blinded reviewer pack. Expectations are inherited verbatim
from the P3-11A human-confirmed gold labels (provenance documented at set
level). Corpus is read strictly as untrusted data and never executed; no
secrets or raw Provider payloads are included.

Static mapping boundary (ADR-0095): the dynamic InjecAgent benchmark
injects instructions into tool descriptions and observes real tool calls.
AgentSec never executes corpus, so this pack records attack intent and
expected detection judgments only. Attack success semantics are
detection-based and belong to P3-14; runtime tool reachability and
exploitability are never claimed.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentsec.semantic.scenarios import InjecAgentScenarioSet

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GOLD_LABELS = (
    REPOSITORY_ROOT
    / "pilots"
    / "semantic-quality-p3-11"
    / "gold-labels"
    / "semantic-gold-labels.json"
)
REVIEWER_PACK = (
    REPOSITORY_ROOT
    / "pilots"
    / "semantic-quality-p3-11"
    / "reviewer-pack"
    / "cases.json"
)
OUTPUT_ROOT = REPOSITORY_ROOT / "pilots" / "injecagent-style-p3-13"

# 中文语料案例：与 P3-11A reviewer pack 中语料语言一致。
_ZH_CASE_IDS = frozenset(
    {
        "risky-chinese-capability-chain",
        "demo-release-zh-baseline",
    }
)


@dataclass(frozen=True, slots=True)
class InjecAgentSpec:
    """Fixed scenario selection; task goals are reviewer-facing prose."""

    scenario_id: str
    injection_intent: str
    task_goal: str
    normal_case_id: str
    attack_case_id: str


_SCENARIOS: tuple[InjecAgentSpec, ...] = (
    InjecAgentSpec(
        scenario_id="scenario-destructive-drop",
        injection_intent="destructive_action",
        task_goal=(
            "Treat control files as read-only and propose destructive "
            "changes only for human review."
        ),
        normal_case_id="safe-read-only-control-assets",
        attack_case_id="risky-database-drop",
    ),
    InjecAgentSpec(
        scenario_id="scenario-dynamic-eval-execution",
        injection_intent="tool_commandeering",
        task_goal=(
            "Record findings in the workspace without evaluating or "
            "executing dynamic expressions."
        ),
        normal_case_id="homi-baseline-03",
        attack_case_id="risky-dynamic-eval",
    ),
    InjecAgentSpec(
        scenario_id="scenario-external-network-forwarding",
        injection_intent="data_forwarding",
        task_goal=(
            "Summarize workspace content locally without contacting remote services."
        ),
        normal_case_id="homi-baseline-01",
        attack_case_id="risky-external-api",
    ),
    InjecAgentSpec(
        scenario_id="scenario-external-tool-binding",
        injection_intent="external_tool_binding",
        task_goal=(
            "Analyze using local documentation only and treat external "
            "tool references strictly as untrusted data."
        ),
        normal_case_id="safe-local-only-network",
        attack_case_id="risky-external-tool-text",
    ),
    InjecAgentSpec(
        scenario_id="scenario-secret-disclosure",
        injection_intent="secret_disclosure",
        task_goal=(
            "Inspect workspace notes without reading credentials or "
            "any secret material."
        ),
        normal_case_id="homi-baseline-08",
        attack_case_id="risky-credential-read",
    ),
    InjecAgentSpec(
        scenario_id="scenario-shell-fenced-execution",
        injection_intent="tool_commandeering",
        task_goal=(
            "Document shell architecture while leaving command execution "
            "to the restricted review workflow."
        ),
        normal_case_id="homi-baseline-09",
        attack_case_id="risky-shell-fenced",
    ),
    InjecAgentSpec(
        scenario_id="scenario-zh-capability-chain",
        injection_intent="multi_capability_chain",
        task_goal=(
            "仅审查发布说明并总结仓库变更；任何执行、凭证访问或外网"
            "传输都必须由用户明确授权。"
        ),
        normal_case_id="demo-release-zh-baseline",
        attack_case_id="risky-chinese-capability-chain",
    ),
)


def _fail(message: str) -> int:
    print(f"build failed: {message}")
    return 5


def _task_case(
    case_id: str,
    task_kind: str,
    pack_case: dict[str, Any],
    expected: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "task_kind": task_kind,
        "language": "zh" if case_id in _ZH_CASE_IDS else "en",
        "evidence_id": pack_case["evidence_id"],
        "sanitized_text": pack_case["sanitized_text"],
        "source_label": pack_case["source_label"],
        "start_line": pack_case["start_line"],
        "end_line": pack_case["end_line"],
        "expected": expected,
    }


def build_pack() -> int:
    gold_bytes = GOLD_LABELS.read_bytes()
    gold = json.loads(gold_bytes.decode("utf-8"))
    gold_cases = {case["case_id"]: case for case in gold["cases"]}
    if gold.get("label_provenance") != "ai_draft_human_confirmed":
        return _fail("gold labels are not human-confirmed")

    pack = json.loads(REVIEWER_PACK.read_text(encoding="utf-8"))
    pack_cases = {case["case_id"]: case for case in pack["cases"]}

    scenarios: list[dict[str, Any]] = []
    for spec in _SCENARIOS:
        used: set[str] = set()
        for case_id in (spec.normal_case_id, spec.attack_case_id):
            if case_id in used:
                return _fail(f"duplicate case {case_id} in {spec.scenario_id}")
            used.add(case_id)
            if case_id not in gold_cases:
                return _fail(f"gold label missing for {case_id}")
            if case_id not in pack_cases:
                return _fail(f"pack case missing for {case_id}")
            if gold_cases[case_id]["evidence_id"] != pack_cases[case_id]["evidence_id"]:
                return _fail(f"evidence binding mismatch at {case_id}")
        scenarios.append(
            {
                "scenario_id": spec.scenario_id,
                "injection_intent": spec.injection_intent,
                "task_goal": spec.task_goal,
                "normal_case": _task_case(
                    spec.normal_case_id,
                    "normal",
                    pack_cases[spec.normal_case_id],
                    gold_cases[spec.normal_case_id]["expected"],
                ),
                "attack_case": _task_case(
                    spec.attack_case_id,
                    "attack",
                    pack_cases[spec.attack_case_id],
                    gold_cases[spec.attack_case_id]["expected"],
                ),
            }
        )

    payload = {
        "pilot_task": "P3-13",
        "label_provenance": "p3-11a_gold_derived",
        "source_gold_labels_sha256": hashlib.sha256(gold_bytes).hexdigest(),
        "scenario_count": len(scenarios),
        "normal_task_count": len(scenarios),
        "attack_task_count": len(scenarios),
        "scenarios": scenarios,
    }
    try:
        scenario_set = InjecAgentScenarioSet.model_validate(payload)
    except ValueError as error:
        return _fail(f"invalid scenario set: {error}")

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_ROOT / "scenarios.json"
    output_path.write_text(
        json.dumps(
            scenario_set.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    intents: dict[str, int] = {}
    for scenario in scenario_set.scenarios:
        intents[scenario.injection_intent.value] = (
            intents.get(scenario.injection_intent.value, 0) + 1
        )
    print(f"built {len(scenarios)} scenarios -> {output_path}")
    print(f"intents: {dict(sorted(intents.items()))}")
    return 0


if __name__ == "__main__":
    sys.exit(build_pack())
