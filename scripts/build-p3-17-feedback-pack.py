#!/usr/bin/env python3
"""Build the P3-17 semantic feedback draft pack for human review.

Derives deterministic false-positive/false-negative draft rows from one
Shadow adapter run over the frozen P3-12/P3-13 scenario packs: every
expected judgment the run missed becomes a draft false-negative row and
every unpredicted judgment becomes a draft false-positive row. The shipped
draft uses an explicit offline fixture provider that echoes no candidates,
so every expected judgment is recorded as a false-negative suspect — an
honest, reproducible starting point for reviewer confirmation.

Corpus is read strictly as untrusted data and never executed; no secrets,
raw request/response payloads, or model summaries are stored. The draft
grants no authority and awaits per-row human confirmation (ADR-0106).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from agentsec.semantic import (
    SemanticShadowInvocationAdapter,
    load_agent_dojo_scenario_set,
    load_injecagent_scenario_set,
)
from agentsec.semantic.feedback import build_semantic_feedback_draft
from agentsec.semantic.models import SemanticModelOutput
from agentsec.semantic.provider import (
    SemanticProviderMetadata,
    SemanticProviderResponse,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
P3_12_PACK = REPOSITORY_ROOT / "pilots" / "agentdojo-style-p3-12" / "scenarios.json"
P3_13_PACK = REPOSITORY_ROOT / "pilots" / "injecagent-style-p3-13" / "scenarios.json"
OUTPUT_ROOT = REPOSITORY_ROOT / "pilots" / "semantic-feedback-p3-17" / "draft"


class _EmptyFixtureProvider:
    """Approved-identity fixture predicting no candidates for any case."""

    def __init__(self) -> None:
        self.metadata = SemanticProviderMetadata()

    def invoke(self, request: Any) -> SemanticProviderResponse:
        model = SemanticModelOutput.model_validate(
            {
                "analysis_id": request.analysis_id,
                "analyzed_evidence_ids": [],
                "candidates": [],
            }
        )
        raw = json.dumps(
            model.model_dump(mode="json"), ensure_ascii=False, sort_keys=True
        )
        return SemanticProviderResponse(
            request_id=request.request_id,
            provider_id=request.provider_id,
            model_id=request.model_id,
            completion_status="complete",
            output_json=raw,
            output_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            input_tokens=1,
            output_tokens=1,
        )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_pack() -> int:
    p12 = load_agent_dojo_scenario_set(P3_12_PACK)
    p13 = load_injecagent_scenario_set(P3_13_PACK)
    adapter = SemanticShadowInvocationAdapter(provider=_EmptyFixtureProvider())
    draft = build_semantic_feedback_draft(
        (p12, p13),
        adapter,
        source_pack_sha256=(_sha256(P3_12_PACK), _sha256(P3_13_PACK)),
    )

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    payload = draft.model_dump(mode="json")
    for row in payload["rows"]:
        row["status"] = "draft"
        row["note"] = None
    submission = {
        "format": "agentsec-p3-17-feedback-submission",
        "format_version": "0.1.0",
        "reviewer_id": None,
        "independence_statement": None,
        "label_provenance": "ai_draft_human_confirmed",
        "context": payload["context"],
        "draft_rows": payload["rows"],
        "draft_sha256": payload["draft_sha256"],
    }
    submission_path = OUTPUT_ROOT / "feedback-draft-submission.template.json"
    submission_path.write_text(
        json.dumps(submission, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    worksheet_lines = [
        "# P3-17 人工反馈复核表（FP/FN 草稿）",
        "",
        "- 任务：P3-17 人工反馈与标签（ADR-0106）",
        f"- 日期：2026-08-31；草稿摘要：`{payload['draft_sha256']}`",
        f"- 草稿来源：offline fixture 回放（echo 无判断），案例数 "
        f"{payload['context']['evaluation_case_count']}，Provider/Model = "
        f"{payload['context']['evaluation_provider_id']}/"
        f"{payload['context']['evaluation_model_id']}",
        "- 背景：P3-11C 真实 Provider 试路（theta-public|Kimi-K3-256K）在 45 例"
        "金标准上 Precision=0.394 / Recall=0.378（FP=57 / FN=61）；本表为"
        "FP/FN 反馈闭环的确认入口。",
        "",
        "## 复核说明",
        "",
        "1. 以下每行是 AI 起草的 false_negative 疑似行（fixture 未输出任何"
        "判断，因此全部预期判断均计为漏报候选）。",
        "2. 请逐行判断：确认（confirm）或拒绝（reject）。",
        "3. 填写 `feedback-draft-submission.template.json` 中的 "
        "`reviewer_id` 与 `independence_statement`，并把每行 `status` 改为 "
        "`confirmed` 或 `rejected`；可填写 `note`。",
        "4. 运行导入脚本生成确认后的反馈集：",
        "",
        "```bash",
        ".venv/bin/python scripts/import-p3-17-feedback.py \\",
        "  --submission pilots/semantic-feedback-p3-17/draft/"
        "feedback-draft-submission.template.json \\",
        "  --output pilots/semantic-feedback-p3-17/confirmed",
        "```",
        "",
        "本表及后续确认集均为 report-only；不授予校准、规则发布、Policy、CI、"
        "Hard Gate 或运行时权限。",
        "",
        "## 草稿行（按 row_id 排序）",
        "",
        "| # | row_id | issue | kind | category | disposition | 判断 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for index, row in enumerate(payload["rows"], start=1):
        worksheet_lines.append(
            f"| {index} | `{row['row_id']}` | {row['issue_type']} | "
            f"{row['kind']} | {row['category']} | {row['disposition']} | "
            "☐ 确认 / ☐ 拒绝 |"
        )
    worksheet_lines.append("")
    worksheet_path = OUTPUT_ROOT / "REVIEW-WORKSHEET.zh.md"
    worksheet_path.write_text("\n".join(worksheet_lines), encoding="utf-8")

    print(f"draft rows: {draft.draft_row_count}")
    print(f"false positives: {draft.false_positive_row_count}")
    print(f"false negatives: {draft.false_negative_row_count}")
    print(f"submission: {submission_path}")
    print(f"worksheet: {worksheet_path}")
    return 0


if __name__ == "__main__":
    sys.exit(build_pack())
