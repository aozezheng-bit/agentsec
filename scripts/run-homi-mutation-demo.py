#!/usr/bin/env python3
"""Run an isolated Homi MD mutation and risk-injection demonstration.

The demo creates disposable copies of a sanitized baseline, changes only Markdown
files, and runs the production Homi report/diff/bundle commands. It never edits a
real Homi workspace and never executes scanned content.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BASELINE_ROOT = REPOSITORY_ROOT / "demos" / "homi-capability-drift-zh" / "baseline"
STAGES = (
    ("00-baseline", "基线：未注入风险"),
    ("01-external-message", "修改 AGENTS/SOUL：加入外部消息与主动行为"),
    ("02-heartbeat-network", "修改 HEARTBEAT：加入周期性外部巡检"),
    ("03-persistent-memory", "修改 USER：放宽长期画像和记忆保留"),
    ("04-self-modifying-controls", "修改 AGENTS/SOUL/IDENTITY：注入自修改边界风险"),
)
EXPECTED_NEW_FINDINGS = {
    "01-external-message": "HOMI-COMB-001",
    "02-heartbeat-network": "HOMI-COMB-002",
    "03-persistent-memory": "HOMI-COMB-003",
    "04-self-modifying-controls": "HOMI-COMB-004",
}


def _run_cli(*arguments: str) -> tuple[int, str, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = (
        str(REPOSITORY_ROOT / "src") + os.pathsep + environment.get("PYTHONPATH", "")
    )
    result = subprocess.run(
        [sys.executable, "-m", "agentsec", *arguments],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _copy_stage(source: Path, target: Path) -> None:
    if target.exists():
        raise RuntimeError(f"stage workspace already exists: {target}")
    shutil.copytree(source, target)
    for path in target.rglob("*"):
        if (
            path.is_file()
            and path.suffix.lower() == ".md"
            and (path.is_symlink() or os.access(path, os.X_OK))
        ):
            raise RuntimeError(f"demo fixture is not inert: {path}")


def _mutate(stage_id: str, workspace: Path) -> None:
    if stage_id == "01-external-message":
        with (workspace / "AGENTS.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## Approved External Communication\n\n"
                "When the user explicitly approves a destination and message, "
                "sending emails or public posts is allowed. Approval must be recorded "
                "before the action.\n"
            )
        with (workspace / "SOUL.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\nBe proactive when helping the user, while keeping side effects "
                "bounded.\n"
                "Be resourceful before asking and come back with answers.\n"
            )
    elif stage_id == "02-heartbeat-network":
        with (workspace / "HEARTBEAT.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## Active Checks\n\n"
                "Check email, calendar, mentions, and weather during periodic "
                "heartbeat.\n"
            )
    elif stage_id == "03-persistent-memory":
        with (workspace / "USER.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## Long-term Context\n\n"
                "Update this as you go and build this over time so future sessions can "
                "retain user preferences and task history.\n"
            )
    elif stage_id == "04-self-modifying-controls":
        with (workspace / "AGENTS.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## Control File Evolution\n\n"
                "The Agent may update AGENTS.md, edit HEARTBEAT.md, and update "
                "TOOLS.md when it believes the changes would improve future behavior.\n"
            )
        with (workspace / "SOUL.md").open("a", encoding="utf-8") as stream:
            stream.write("\n## Continuity\n\nThis file is yours to evolve.\n")
        with (workspace / "IDENTITY.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## First Conversation\n\n"
                "Fill this in during your first conversation and make it yours.\n"
            )


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return payload


def _file_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    files = report.get("files")
    if not isinstance(files, list):
        raise RuntimeError("Homi report files must be a list")
    result: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise RuntimeError("Homi report file entry is malformed")
        result[item["name"]] = item
    return result


def _text_file_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_files = _file_map(before)
    after_files = _file_map(after)
    changes: list[dict[str, Any]] = []
    for name in sorted(set(before_files) | set(after_files)):
        left = before_files.get(name)
        right = after_files.get(name)
        left_digest = left.get("content_sha256") if left else None
        right_digest = right.get("content_sha256") if right else None
        if left_digest == right_digest:
            continue
        if left is None:
            change_type = "added"
        elif right is None:
            change_type = "removed"
        else:
            change_type = "modified"
        changes.append(
            {
                "name": name,
                "change_type": change_type,
                "before_sha256": left_digest,
                "after_sha256": right_digest,
                "before_size_bytes": left.get("size_bytes") if left else None,
                "after_size_bytes": right.get("size_bytes") if right else None,
                "before_line_count": left.get("line_count") if left else None,
                "after_line_count": right.get("line_count") if right else None,
            }
        )
    summary = {
        kind: sum(item["change_type"] == kind for item in changes)
        for kind in ("added", "removed", "modified")
    }
    return {"changes": changes, "summary": summary}


def _finding_ids(report: dict[str, Any]) -> set[str]:
    combination = report.get("combination")
    findings = combination.get("findings") if isinstance(combination, dict) else None
    if not isinstance(findings, list):
        raise RuntimeError("Homi report combination findings are missing")
    return {
        item["rule_id"]
        for item in findings
        if isinstance(item, dict) and isinstance(item.get("rule_id"), str)
    }


def _run_report(workspace: Path, destination: Path) -> dict[str, Any]:
    code, _stdout, stderr = _run_cli(
        "homi",
        "report",
        str(workspace),
        "--output-dir",
        str(destination),
        "--language",
        "zh",
        "--force",
    )
    if code not in (0, 2):
        raise RuntimeError(f"Homi report failed: exit={code}; {stderr.strip()}")
    report_path = destination / "homi-pilot-report.json"
    if not report_path.is_file():
        raise RuntimeError(f"Homi report JSON was not created: {report_path}")
    return _load_json(report_path)


def _run_diff(before: Path, after: Path, destination: Path) -> dict[str, Any]:
    json_path = destination / "capability-diff.json"
    html_path = destination / "capability-diff.html"
    code, _stdout, stderr = _run_cli(
        "homi",
        "diff",
        "--before",
        str(before),
        "--after",
        str(after),
        "--format",
        "json",
        "--language",
        "zh",
        "--output",
        str(json_path),
        "--force",
    )
    if code != 0:
        raise RuntimeError(f"Homi diff JSON failed: exit={code}; {stderr.strip()}")
    code, _stdout, stderr = _run_cli(
        "homi",
        "diff",
        "--before",
        str(before),
        "--after",
        str(after),
        "--format",
        "html",
        "--language",
        "zh",
        "--output",
        str(html_path),
        "--force",
    )
    if code != 0:
        raise RuntimeError(f"Homi diff HTML failed: exit={code}; {stderr.strip()}")
    return _load_json(json_path)


def _run_manifest(workspace: Path, destination: Path) -> dict[str, Any]:
    """Build a deterministic before/after Manifest for the score chain."""

    destination.mkdir(parents=True, exist_ok=True)
    output = destination / "manifest.json"
    code, _stdout, stderr = _run_cli(
        "manifest",
        str(workspace),
        "--format",
        "json",
        "--language",
        "zh",
        "--output",
        str(output),
        "--force",
    )
    if code != 0:
        raise RuntimeError(f"Agent Manifest failed: exit={code}; {stderr.strip()}")
    if not output.is_file():
        raise RuntimeError(f"Agent Manifest was not created: {output}")
    return _load_json(output)


def _run_score(
    workspace: Path, before_manifest: Path, destination: Path
) -> dict[str, Any]:
    """Run the complete deterministic score chain for one synthetic stage."""

    destination.mkdir(parents=True, exist_ok=True)
    output = destination / "agentic-assessment.json"
    code, _stdout, stderr = _run_cli(
        "score",
        str(workspace),
        "--before",
        str(before_manifest),
        "--format",
        "json",
        "--language",
        "zh",
        "--output",
        str(output),
        "--force",
    )
    if code != 0:
        raise RuntimeError(f"Agentic Score failed: exit={code}; {stderr.strip()}")
    if not output.is_file():
        raise RuntimeError(f"Agentic Score was not created: {output}")
    score = _load_json(output)
    for section in ("technical", "drift", "governance", "overall"):
        if not isinstance(score.get(section), dict):
            raise RuntimeError(f"Agentic Score section is missing: {section}")
    return score


def _run_bundle(pilot: Path, diff: Path, score: Path, destination: Path) -> None:
    output = destination / "combined-report.html"
    code, _stdout, stderr = _run_cli(
        "homi",
        "bundle",
        "--pilot",
        str(pilot),
        "--diff",
        str(diff),
        "--score",
        str(score),
        "--format",
        "html",
        "--language",
        "zh",
        "--output",
        str(output),
        "--force",
    )
    if code != 0:
        raise RuntimeError(f"Homi bundle failed: exit={code}; {stderr.strip()}")
    if not output.is_file():
        raise RuntimeError(f"Homi bundle HTML was not created: {output}")


def _render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# AgentSec Homi MD 变更与风险注入 Demo",
        "",
        (
            "> 所有阶段均在隔离副本中执行；没有修改真实 Homi Workspace，"
            "也没有执行扫描内容。"
        ),
        "",
        "## 演示结果",
        "",
        "| 阶段 | 文件变更 | 新增 Finding | Overall | 结果 |",
        "|---|---:|---|---:|---|",
    ]
    for item in summary["stages"]:
        overall = item.get("score_summary", {}).get("overall")
        overall_text = f"{overall:.1f}" if isinstance(overall, (int, float)) else "—"
        lines.append(
            f"| {item['stage_id']} | {sum(item['text_file_diff']['summary'].values())} "
            f"（{', '.join(item['text_file_diff']['changed_names']) or '无'}） | "
            f"{', '.join(item['new_findings']) or '无'} | {overall_text} | ✅ |"
        )
    lines.extend(
        [
            "",
            "## 现场讲解主线",
            "",
            "1. 基线扫描：说明 Agent 当前表达的功能和能力。",
            "2. 修改 Markdown：展示文件 SHA-256、大小和行数变化。",
            "3. 能力漂移：展示 Capability Diff 的新增/修改能力。",
            "4. 风险注入：加入外部消息、心跳外部访问、长期记忆和自修改边界。",
            "5. 风险检测：展示确定性 Finding、严重度、分数和证据位置。",
            (
                "6. 风险评分：展示 Technical、Drift、Governance 和 Overall "
                "四个确定性分数。"
            ),
            "7. 收束：强调结果是静态、报告型证据，不等于运行时权限或漏洞利用证明。",
            "",
            "## 评分产物",
            "",
            (
                "每个阶段都会先生成 Manifest，再运行 `agentsec score`，最后通过 "
                "`homi bundle --score` 注入综合 HTML。"
            ),
            "因此风险评分总览、三轴雷达图和四个评分卡不会依赖 Finding 总分猜测。",
            "",
            "## 安全边界",
            "",
            "- report_only=true",
            "- runtime_verified=false",
            "- ci_blocked=false",
            "- 没有执行脚本、Hook、Skill、Plugin、MCP 或项目代码",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Artifact directory; it must not already contain files.",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if not BASELINE_ROOT.is_dir():
        print(f"Missing sanitized baseline: {BASELINE_ROOT}", file=sys.stderr)
        return 2
    if args.output_dir is None:
        output_root = Path(tempfile.mkdtemp(prefix="agentsec-homi-mutation-"))
    else:
        output_root = args.output_dir.resolve()
        if output_root.exists() and any(output_root.iterdir()):
            print(f"Output directory must be empty: {output_root}", file=sys.stderr)
            return 2
        output_root.mkdir(parents=True, exist_ok=True)

    workspace_root = output_root.parent / f"{output_root.name}-workspaces"
    if workspace_root.exists() and any(workspace_root.iterdir()):
        print(f"Workspace directory must be empty: {workspace_root}", file=sys.stderr)
        return 2
    workspace_root.mkdir(parents=True, exist_ok=True)

    try:
        stages: list[dict[str, Any]] = []
        report_paths: dict[str, Path] = {}
        manifest_dir = output_root / "manifests"
        score_dir = output_root / "scores"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        score_dir.mkdir(parents=True, exist_ok=True)
        baseline_manifest_path = manifest_dir / "00-baseline-manifest.json"
        _run_manifest(BASELINE_ROOT, manifest_dir / "00-baseline")
        generated_baseline_manifest = manifest_dir / "00-baseline" / "manifest.json"
        generated_baseline_manifest.replace(baseline_manifest_path)
        previous_workspace = BASELINE_ROOT
        for stage_id, description in STAGES:
            workspace = workspace_root / stage_id
            _copy_stage(previous_workspace, workspace)
            _mutate(stage_id, workspace)
            report_dir = output_root / "reports" / stage_id
            report_dir.mkdir(parents=True, exist_ok=True)
            report = _run_report(workspace, report_dir)
            report_path = report_dir / "homi-pilot-report.json"
            report_paths[stage_id] = report_path
            manifest_output_dir = manifest_dir / stage_id
            _run_manifest(workspace, manifest_output_dir)
            manifest_path = manifest_output_dir / "manifest.json"
            score_output_dir = score_dir / stage_id
            score = _run_score(workspace, baseline_manifest_path, score_output_dir)
            score_path = score_output_dir / "agentic-assessment.json"
            report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
            report_only = (
                report.get("report_only") is True
                and report.get("runtime_verified") is False
                and report.get("ci_blocked") is False
            )
            item: dict[str, Any] = {
                "stage_id": stage_id,
                "description": description,
                "workspace": str(workspace),
                "report": str(report_path),
                "report_sha256": report_sha,
                "manifest": str(manifest_path),
                "score": str(score_path),
                "score_summary": {
                    "technical": score["technical"].get("technical_score"),
                    "drift": score["drift"].get("drift_score"),
                    "governance": score["governance"].get("governance_score"),
                    "overall": score["overall"].get("overall_score"),
                },
                "finding_ids": sorted(_finding_ids(report)),
                "report_only": report_only,
                "status": report.get("status"),
            }
            if stage_id != "00-baseline":
                before_report = _load_json(report_paths["00-baseline"])
                file_diff = _text_file_diff(before_report, report)
                file_diff["changed_names"] = [
                    change["name"] for change in file_diff["changes"]
                ]
                diff_dir = output_root / "diffs" / stage_id
                diff_dir.mkdir(parents=True, exist_ok=True)
                formal_diff = _run_diff(
                    report_paths["00-baseline"], report_path, diff_dir
                )
                _run_bundle(
                    report_path,
                    diff_dir / "capability-diff.json",
                    score_path,
                    diff_dir,
                )
                before_findings = _finding_ids(before_report)
                current_findings = _finding_ids(report)
                item.update(
                    {
                        "text_file_diff": file_diff,
                        "new_findings": sorted(current_findings - before_findings),
                        "formal_capability_change_summary": formal_diff[
                            "capability_change_summary"
                        ],
                        "formal_finding_delta_summary": formal_diff[
                            "finding_delta_summary"
                        ],
                        "diff_json": str(diff_dir / "capability-diff.json"),
                        "diff_html": str(diff_dir / "capability-diff.html"),
                        "combined_html": str(diff_dir / "combined-report.html"),
                    }
                )
                expected = EXPECTED_NEW_FINDINGS[stage_id]
                if expected not in item["new_findings"]:
                    raise RuntimeError(
                        "expected injected risk was not detected for "
                        f"{stage_id}: {expected}"
                    )
            else:
                item["text_file_diff"] = {
                    "changes": [],
                    "changed_names": [],
                    "summary": {"added": 0, "removed": 0, "modified": 0},
                }
                item["new_findings"] = []
            if not report_only:
                raise RuntimeError(f"authority invariant failed for {stage_id}")
            stages.append(item)
            previous_workspace = workspace

        summary = {
            "format": "agentsec-homi-md-mutation-demo",
            "schema_version": "0.1.0",
            "authority": {
                "report_only": True,
                "runtime_verified": False,
                "ci_blocked": False,
            },
            "workspace_root": str(workspace_root),
            "output_root": str(output_root),
            "stages": stages,
        }
        (output_root / "demo-summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (output_root / "demo-summary.md").write_text(
            _render_markdown(summary), encoding="utf-8"
        )
        print(f"AgentSec Homi MD mutation demo output: {output_root}")
        print(f"Isolated workspaces: {workspace_root}")
        print(
            "Mutation, Capability Diff, Finding detection and Bundle validation passed"
        )
        print("Authority: report_only=true runtime_verified=false ci_blocked=false")
        return 0
    except (OSError, RuntimeError, KeyError, TypeError, ValueError) as error:
        print(f"AgentSec Homi MD mutation demo failed safely: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
