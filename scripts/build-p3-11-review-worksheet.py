#!/usr/bin/env python3
"""Render the P3-11A human review worksheet from the AI draft submission.

For every case the worksheet shows the sanitized evidence text and the
AI-drafted judgments side by side so a human reviewer can confirm or modify
each label. Corpus text is rendered as read-only data.
"""

from __future__ import annotations

import json
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PACK_ROOT = REPOSITORY_ROOT / "pilots" / "semantic-quality-p3-11" / "reviewer-pack"
WORKSHEET = PACK_ROOT / "REVIEW-WORKSHEET.zh.md"

_KIND_ZH = {
    "capability_declaration": "能力声明",
    "control_weakening": "控制弱化",
    "semantic_conflict": "语义冲突",
    "cross_file_chain": "跨文件链",
    "risky_intent": "风险意图",
    "ambiguity": "歧义",
}
_DISPOSITION_ZH = {
    "supported": "文本支持该语义",
    "not_supported": "文本否定该语义（表述触及但被否定）",
    "uncertain": "歧义/上下文不足",
}
_CATEGORY_ZH = {
    "instruction_integrity": "指令完整性",
    "human_approval": "人工审批",
    "code_execution": "代码执行",
    "network_access": "网络访问",
    "secret_access": "凭据访问",
    "privileged_access": "特权访问",
    "destructive_action": "破坏性操作",
    "persistent_memory": "持久化记忆",
    "self_modification": "自我修改",
    "obfuscation": "混淆",
    "external_tooling": "外部工具",
    "scan_coverage": "扫描覆盖操纵",
    "other": "其他",
}


def _render() -> int:
    cases = json.loads((PACK_ROOT / "cases.json").read_text(encoding="utf-8"))["cases"]
    submission = json.loads(
        (PACK_ROOT / "review-submission.ai-draft.json").read_text(encoding="utf-8")
    )
    by_id = {entry["case_id"]: entry for entry in submission["cases"]}

    lines: list[str] = [
        "# P3-11A 人工复核工作表（AI 底稿对照）",
        "",
        "- 用途：逐案例确认或修改 AI 起草的语义判断，形成可采信的人工金标准",
        "- 复核对象：`review-submission.completed.json`（可直接编辑）",
        "- 底稿存档：`review-submission.ai-draft.json`（只读对照，勿改）",
        "- 每案例判断字段含义见 `LABELING-GUIDE.zh.md`",
        "",
        "## 复核规则",
        "",
        "1. 逐案例阅读【证据文本】与每条【AI 底稿判断】；",
        "2. **同意** → 该案例不动；**不同意** → 直接在",
        "   `review-submission.completed.json` 中修改对应 case 的 judgment 字段",
        "   （可增删 judgment，judgment_id 在案例内保持唯一）；",
        "3. 认为整条判断多余 → 删除；认为遗漏语义 → 追加 j-XX；",
        "4. 全部复核完成后：`reviewer_id` 改为你的稳定标识；",
        "   `independence_statement` 用下方【粘贴用声明】；新增字段",
        '   `"label_provenance": "ai_draft_human_confirmed"`；',
        "5. 自检：`python3 -m json.tool review-submission.completed.json "
        "> /dev/null`。",
        "",
        "## 粘贴用 independence_statement（直接替换原值）",
        "",
        "```text",
        "本人逐案例复核了 CodeFuse 起草的 45 个语义判断（对照 cases.json 脱敏文本，",
        "未查看任何扫描报告、规则实现、testdata 原始文件或其他 Scanner 输出），",
        "并亲自确认或修改了每条最终判断；同意见 AI 底稿保留原判断，不同处已按本人",
        "判断改写。本表为 AI 起草、人工逐条确认的金标准，判断责任在签署人。",
        "```",
        "",
        "## 案例总览（45 个）",
        "",
        "| # | case_id | 判断数 |",
        "| --- | --- | --- |",
    ]
    for index, case in enumerate(cases, start=1):
        entry = by_id.get(case["case_id"], {})
        judgments = entry.get("expected", [])
        lines.append(f"| {index} | {case['case_id']} | {len(judgments)} |")

    lines += ["", "---", "", "## 逐案例明细", ""]
    for index, case in enumerate(cases, start=1):
        entry = by_id.get(case["case_id"], {})
        judgments = entry.get("expected", [])
        lines += [
            f"### {index}. {case['case_id']}",
            "",
            f"- 来源：`{case['source_label']}`"
            f"（L{case['start_line']}~L{case['end_line']}）",
            "",
            "**证据文本（只读）：**",
            "",
            "```text",
            case["sanitized_text"],
            "```",
            "",
            "**AI 底稿判断：**",
            "",
            "| judgment | kind | category | disposition |",
            "| --- | --- | --- | --- |",
        ]
        for judgment in judgments:
            kind = judgment.get("kind") or "?"
            category = judgment.get("category") or "?"
            disposition = judgment.get("disposition") or "?"
            lines.append(
                f"| {judgment.get('judgment_id', '?')} "
                f"| {kind}（{_KIND_ZH.get(kind, '')}） "
                f"| {category}（{_CATEGORY_ZH.get(category, '')}） "
                f"| {disposition}（{_DISPOSITION_ZH.get(disposition, '')}） |"
            )
        lines += ["", "**人工结论：** 同意 ☐ / 修改（说明改法）：________", ""]

    WORKSHEET.write_text("\n".join(lines), encoding="utf-8")
    print(f"worksheet written: {WORKSHEET} ({len(cases)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_render())
