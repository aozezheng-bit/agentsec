#!/usr/bin/env python3
"""Interactive expert review workflow for the P3-17 feedback draft.

Walks the reviewer through every draft FP/FN row with the case's
sanitized evidence text as context, records confirm/reject decisions
(resumable through a progress file), finalizes the completed submission
(reviewer id + independence statement), and optionally runs the
fail-closed importer to produce the confirmed feedback set.

The corpus text is displayed read-only and never executed; the tool only
records per-row decisions and never edits the draft template itself.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from agentsec.semantic import (
    build_injecagent_evaluation_cases,
    build_scenario_evaluation_cases,
    load_agent_dojo_scenario_set,
    load_injecagent_scenario_set,
    load_semantic_feedback_set,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUBMISSION = (
    REPOSITORY_ROOT
    / "pilots"
    / "semantic-feedback-p3-17"
    / "draft"
    / "feedback-draft-submission.template.json"
)
PILOT_ROOT = REPOSITORY_ROOT / "pilots" / "semantic-feedback-p3-17"
DEFAULT_PROGRESS = PILOT_ROOT / "draft" / "review-progress.json"
DEFAULT_COMPLETED = PILOT_ROOT / "review-submission.completed.json"
DEFAULT_CONFIRMED_DIR = PILOT_ROOT / "confirmed"

P3_12_PACK = REPOSITORY_ROOT / "pilots" / "agentdojo-style-p3-12" / "scenarios.json"
P3_13_PACK = REPOSITORY_ROOT / "pilots" / "injecagent-style-p3-13" / "scenarios.json"

DEFAULT_REVIEWER = "internal-reviewer"
DEFAULT_STATEMENT = (
    "本人逐行复核了 AI 起草的 false_positive/false_negative 反馈行，"
    "对照各案例脱敏文本独立判断并确认每行结论；判断责任在签署人。"
)
_MAX_NOTE_CHARACTERS = 512
_EXCERPT_CHARACTERS = 200

INTERACTIVE_HINT = """键位：
  c      确认本行（漏报判断成立，应进入反馈闭环）
  r      拒绝本行（可附一行备注说明理由）
  n / 回车  跳过本行（不做决定，保留 draft）
  p      上一行
  <数字>   跳到第 N 行
  s      查看统计
  a      将全部剩余行确认为 confirmed（需再输入 yes）
  q      保存进度并退出
  h      显示本帮助
评审中随时可对已判定行重新判定（跳转后再按 c/r 即覆盖）。"""


def _fail(message: str) -> int:
    print(f"review failed: {message}")
    return 5


def _load_case_map() -> dict[str, Any]:
    p12 = load_agent_dojo_scenario_set(P3_12_PACK)
    p13 = load_injecagent_scenario_set(P3_13_PACK)
    merged: dict[str, Any] = {}
    for case in build_scenario_evaluation_cases(
        p12
    ) + build_injecagent_evaluation_cases(p13):
        merged.setdefault(case.case_id, case)
    return merged


def _excerpt(text: str) -> str:
    flat = " ⏎ ".join(line.strip() for line in text.splitlines() if line.strip())
    return flat[:_EXCERPT_CHARACTERS]


def _show_row(
    index: int,
    total: int,
    row: dict[str, Any],
    case_map: dict[str, Any],
    decision: str | None,
) -> None:
    case = case_map.get(row["case_id"])
    text = (
        _excerpt(case.semantic_input.evidence[0].text)
        if case is not None
        else "<案例文本缺失>"
    )
    status = decision or "draft"
    print()
    print(f"—— [{index + 1}/{total}] {row['row_id']}")
    print(f"   案例 {row['case_id']}（{case.language if case else '?'}）")
    if row["issue_type"] == "false_negative":
        print("   判定 漏报（FN）：起草运行未产出下方预期判断。")
        print("   预期判断来自 P3-11A 人工确认金标准。")
    else:
        print("   判定 误报（FP）：起草运行多产出了下方判断。")
    print(
        f"   判断 = kind:{row['kind']} category:{row['category']} "
        f"disposition:{row['disposition']}"
    )
    print(f"   当前进度标记：{status}")
    print(f"   案例文本（脱敏摘要）：{text}")
    print("   [c]确认  [r]拒绝  [n]跳过  [p]上一  [s]统计  [a]全确认  [q]退出  [h]帮助")


def _stats(rows: list[dict[str, Any]], decisions: dict[str, str]) -> None:
    decided = {row_id: decision for row_id, decision in decisions.items()}
    confirmed = sum(decision == "confirmed" for decision in decided.values())
    rejected = sum(decision == "rejected" for decision in decided.values())
    pending = len(rows) - confirmed - rejected
    categories: dict[str, int] = {}
    for row in rows:
        categories[row["category"]] = categories.get(row["category"], 0) + 1
    print()
    print(
        f"统计：共 {len(rows)} 行 ｜ confirmed {confirmed} ｜ "
        f"rejected {rejected} ｜ 待定 {pending}"
    )
    top = sorted(categories.items(), key=lambda item: (-item[1], item[0]))[:8]
    print("类别分布：" + "，".join(f"{k} {v}" for k, v in top))
    print("进度文件会随每次动作自动保存。")


def _save_progress(path: Path, decisions: dict[str, Any]) -> None:
    payload = {
        "format": "agentsec-p3-17-review-progress",
        "decision_count": len(decisions),
        "decisions": [
            {
                "row_id": row_id,
                "decision": entry["decision"],
                **({"note": entry["note"]} if entry.get("note") else {}),
            }
            for row_id, entry in sorted(decisions.items())
        ],
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _load_progress(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        entry["row_id"]: {
            "decision": entry["decision"],
            "note": entry.get("note"),
        }
        for entry in payload.get("decisions", [])
    }


def _ask(prompt: str) -> str | None:
    try:
        answer = input(prompt)
    except EOFError:
        return None
    return answer.strip()


def _decide(
    decisions: dict[str, dict[str, Any]],
    row: dict[str, Any],
    decision: str,
    note: str | None,
) -> None:
    entry: dict[str, Any] = {"decision": decision}
    if note:
        entry["note"] = note
    decisions[row["row_id"]] = entry


def _run_interactive(
    rows: list[dict[str, Any]],
    case_map: dict[str, Any],
    decisions: dict[str, dict[str, Any]],
    progress_path: Path,
) -> bool:
    """Drive the menu loop; returns True when every row is decided."""

    index = 0
    while index < len(rows):
        row = rows[index]
        decision = decisions.get(row["row_id"], {}).get("decision")
        _show_row(index, len(rows), row, case_map, decision)
        answer = _ask("> ")
        if answer is None:
            _save_progress(progress_path, decisions)
            print("输入结束：进度已保存，可随时重新运行继续。")
            return False
        command = answer.lower()
        if command in {"c", "confirm", "y"}:
            _decide(decisions, row, "confirmed", None)
            index += 1
        elif command in {"r", "reject"}:
            note = _ask("  拒绝备注（回车跳过，<=512 字符）：")
            if note is None:
                _save_progress(progress_path, decisions)
                return False
            if len(note) > _MAX_NOTE_CHARACTERS:
                print("  备注过长，本行保持未判定。")
                continue
            _decide(decisions, row, "rejected", note or None)
            index += 1
        elif command in {"n", ""}:
            index += 1
        elif command == "p":
            index = max(0, index - 1)
        elif command.isdigit():
            target = int(command) - 1
            if 0 <= target < len(rows):
                index = target
            else:
                print("  行号超出范围。")
        elif command == "s":
            _stats(rows, {k: v["decision"] for k, v in decisions.items()})
        elif command == "a":
            confirm = _ask(
                "  将确认全部剩余未判定行（跳过人工逐行复核），输入 yes 执行："
            )
            if confirm is None:
                return False
            if confirm.lower() == "yes":
                for pending_row in rows:
                    if pending_row["row_id"] not in decisions:
                        _decide(decisions, pending_row, "confirmed", None)
                print("  已全部确认。")
            else:
                print("  已取消。")
        elif command in {"q", "quit", "w"}:
            _save_progress(progress_path, decisions)
            print(f"进度已保存：{progress_path}")
            return False
        elif command == "h":
            print(INTERACTIVE_HINT)
        else:
            print("  无法识别的命令（h 查看帮助）。")
        _save_progress(progress_path, decisions)
    return True


def _finalized_submission(
    submission: dict[str, Any],
    rows: list[dict[str, Any]],
    decisions: dict[str, dict[str, Any]],
    reviewer: str,
    statement: str,
) -> tuple[dict[str, Any], int]:
    confirmed = 0
    for row in rows:
        entry = decisions.get(row["row_id"])
        if entry is None:
            continue
        row["status"] = entry["decision"]
        row["note"] = entry.get("note")
        if entry["decision"] == "confirmed":
            confirmed += 1
    submission["reviewer_id"] = reviewer
    submission["independence_statement"] = statement
    return submission, confirmed


def _run_import(completed_path: Path, confirmed_dir: Path) -> int:
    command = [
        sys.executable,
        str(REPOSITORY_ROOT / "scripts" / "import-p3-17-feedback.py"),
        "--submission",
        str(completed_path),
        "--output",
        str(confirmed_dir),
    ]
    result = subprocess.run(command, check=False)
    return result.returncode


def _verify(confirmed_dir: Path) -> bool:
    set_path = confirmed_dir / "semantic-feedback-set.json"
    if not set_path.exists():
        return False
    feedback_set = load_semantic_feedback_set(set_path)
    print()
    print("确认集已生成并加载校验通过：")
    print(f"  路径            {set_path}")
    print(f"  行数            {feedback_set.row_count}")
    print(
        f"  FP/FN           {feedback_set.false_positive_row_count}/"
        f"{feedback_set.false_negative_row_count}"
    )
    print(f"  复核人          {feedback_set.reviewer_id}")
    print(f"  溯源            {feedback_set.label_provenance.value}")
    print(f"  feedback_sha256 {feedback_set.feedback_sha256}")
    print("  权限            report_only; blocks=false; 全部授权位 false")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission", type=Path, default=DEFAULT_SUBMISSION)
    parser.add_argument("--progress", type=Path, default=DEFAULT_PROGRESS)
    parser.add_argument("--completed", type=Path, default=DEFAULT_COMPLETED)
    parser.add_argument("--confirmed-dir", type=Path, default=DEFAULT_CONFIRMED_DIR)
    parser.add_argument("--reviewer", default=DEFAULT_REVIEWER)
    parser.add_argument("--statement-file", type=Path, default=None)
    parser.add_argument("--auto-import", action="store_true")
    args = parser.parse_args()

    try:
        submission = json.loads(args.submission.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return _fail(f"unreadable submission: {error}")
    rows = submission.get("draft_rows")
    if not isinstance(rows, list) or not rows:
        return _fail("submission has no draft rows")

    decisions = _load_progress(args.progress)
    decided_count = sum(
        row["row_id"] in decisions
        and decisions[row["row_id"]].get("decision") in {"confirmed", "rejected"}
        for row in rows
    )
    print(f"草稿 {len(rows)} 行；已有判定 {decided_count} 行。")

    case_map = _load_case_map()
    if sys.stdin.isatty():
        print(INTERACTIVE_HINT)
    complete = _run_interactive(rows, case_map, decisions, args.progress)
    if not complete and not sys.stdin.isatty():
        return _fail("non-interactive input ended before all rows were decided")

    pending = [row for row in rows if row["row_id"] not in decisions]
    if pending:
        _save_progress(args.progress, decisions)
        print(
            f"仍有 {len(pending)} 行未判定；请重新运行继续"
            f"（进度已保存在 {args.progress}）。"
        )
        return 1

    statement = (
        args.statement_file.read_text(encoding="utf-8").strip()
        if args.statement_file is not None
        else DEFAULT_STATEMENT
    )
    if len(statement) < 20:
        return _fail("independence_statement is too short (>= 20 chars)")
    if not args.reviewer.strip():
        return _fail("reviewer_id is empty")

    completed, confirmed_count = _finalized_submission(
        submission, rows, decisions, args.reviewer, statement
    )
    args.completed.write_text(
        json.dumps(completed, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print()
    print(
        f"完成提交：{len(rows)} 行已判定（confirmed {confirmed_count}｜"
        f"rejected {len(rows) - confirmed_count}）"
    )
    print(f"提交文件：{args.completed}")
    print(f"独立性声明：{statement}")

    if args.auto_import or not sys.stdin.isatty():
        code = _run_import(args.completed, args.confirmed_dir)
        if code != 0:
            return code
        if not _verify(args.confirmed_dir):
            return _fail("confirmed set missing after import")
        print()
        print("下一步（可选）：闭环比较——")
        print("  evaluate_feedback_resolution(feedback_set, packs, adapter)")
    else:
        print()
        print("下一步：运行导入脚本生成确认集：")
        print(
            "  .venv/bin/python scripts/import-p3-17-feedback.py "
            f"--submission {args.completed} "
            f"--output {args.confirmed_dir}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
