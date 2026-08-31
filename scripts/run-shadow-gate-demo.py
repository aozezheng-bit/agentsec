"""Run the P2-15A-PILOT-03 Shadow Gate Demo and coverage report.

The demo executes only AgentSec's deterministic in-memory analysis over inert,
synthetic manifests. It never executes a scanned project, script, Skill, Hook,
MCP server, or network request. The calibration section delegates validation to
the existing bounded Gate Coverage Check and reports seeded expected
match/no-match metadata separately from live Shadow Gate results.

Exit codes:
  0 = demo passed and calibration coverage is ready
  2 = demo passed but calibration coverage remains incomplete
  4 = input, argument, or output artifact error
  5 = deterministic demo execution or contract failure
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

from agentsec.application import AgentAnalysisPipeline, AgentAnalysisRequest
from agentsec.capability_rules import (
    CapabilityRuleRunResult,
    DeterministicCapabilityRuleRunner,
    DeterministicCapabilityShadowGateEngine,
    builtin_capability_rules,
)
from agentsec.manifests import (
    AgentManifest,
    ManifestPermission,
    ManifestPermissionAction,
    ManifestPermissionEffect,
    ManifestResourceKind,
    ManifestResourceScope,
    ManifestTool,
    ManifestToolAvailability,
    ManifestToolKind,
    ManifestToolSideEffect,
    UnknownExtractor,
)
from agentsec.versioning import CAPABILITY_SHADOW_GATE_VERSION

EXIT_READY = 0
EXIT_INCOMPLETE = 2
EXIT_INVALID = 4
EXIT_FAILED = 5

REPORT_FORMAT = "agentsec-capability-shadow-gate-demo"
REPORT_SCHEMA_VERSION = "0.1.0"
GATE_ID = "HG-CAPCHAIN-001"
COMPONENT_RULE_ID = "CAP-CHAIN-001"
GATE_FLOOR = "high"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _project(project: Path) -> None:
    project.mkdir()
    _write(project / "AGENTS.md", "# Inert Shadow Gate Demo Agent\n")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.remote]
url = "https://example.invalid/mcp"
enabled = true
required = true
auth = "oauth"
bearer_token_env_var = "REMOTE_TOKEN"
default_tools_approval_mode = "prompt"
""".lstrip(),
    )


def _analyze(project: Path) -> AgentManifest:
    return (
        AgentAnalysisPipeline()
        .analyze(AgentAnalysisRequest(project_root=project, agent_id="demo-agent"))
        .manifest
    )


def _explicit_chain_manifest(project: Path) -> AgentManifest:
    """Build a complete same-target chain from a bounded static Manifest."""

    manifest = _analyze(project)
    source = next(
        permission.sources[0]
        for permission in manifest.permissions.permissions
        if permission.target == "mcp-server:remote"
    )
    payload: dict[str, Any] = manifest.model_dump(mode="python")
    permissions = []
    for permission in manifest.permissions.permissions:
        item = permission.model_dump(mode="python")
        item["effect"] = ManifestPermissionEffect.ALLOW
        permissions.append(item)
    permissions.append(
        ManifestPermission(
            permission_id="permission:execute:mcp-server:remote:synthetic",
            action=ManifestPermissionAction.EXECUTE,
            effect=ManifestPermissionEffect.ALLOW,
            resource=ManifestResourceKind.SHELL,
            scope=ManifestResourceScope.EXTERNAL,
            target="mcp-server:remote",
            sources=(source,),
        ).model_dump(mode="python")
    )
    permissions.sort(key=lambda item: item["permission_id"])
    payload["permissions"] = {
        **payload["permissions"],
        "resolution": "resolved",
        "permissions": permissions,
    }
    identities = []
    for identity in payload["runtime_identities"]["identities"]:
        item = dict(identity)
        item["privileged"] = False
        identities.append(item)
    payload["runtime_identities"] = {
        **payload["runtime_identities"],
        "resolution": "resolved",
        "identities": identities,
    }
    for key in ("instructions", "configuration", "tools", "controls", "relationships"):
        if isinstance(payload.get(key), dict) and "resolution" in payload[key]:
            payload[key]["resolution"] = "resolved"
    payload["unknowns"] = ()
    return UnknownExtractor().extract(AgentManifest.model_validate(payload))


def _parent_child_chain_manifest(project: Path) -> AgentManifest:
    """Build a complete chain split between an MCP server and child tool."""

    manifest = _explicit_chain_manifest(project)
    source = next(
        permission.sources[0]
        for permission in manifest.permissions.permissions
        if permission.action is ManifestPermissionAction.EXECUTE
    )
    payload: dict[str, Any] = manifest.model_dump(mode="python")
    child_id = "mcp-tool:remote:execute"
    child = ManifestTool(
        tool_id=child_id,
        name="execute",
        kind=ManifestToolKind.MCP_TOOL,
        availability=ManifestToolAvailability.ENABLED,
        side_effects=(ManifestToolSideEffect.EXECUTE,),
        parent_tool_id="mcp-server:remote",
        sources=(source,),
    ).model_dump(mode="python")
    tools = [*payload["tools"]["tools"], child]
    tools.sort(key=lambda item: item["tool_id"])
    payload["tools"] = {**payload["tools"], "tools": tools}
    permissions = []
    for permission in payload["permissions"]["permissions"]:
        item = dict(permission)
        if item["action"] is ManifestPermissionAction.EXECUTE:
            item["target"] = child_id
        permissions.append(item)
    permissions.sort(key=lambda item: item["permission_id"])
    payload["permissions"] = {
        **payload["permissions"],
        "permissions": permissions,
    }
    payload["unknowns"] = ()
    return UnknownExtractor().extract(AgentManifest.model_validate(payload))


def _agent_wide_manifest(project: Path) -> AgentManifest:
    """Keep the three facts visible but unrelated to one target family."""

    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.remote]
url = "https://example.invalid/mcp"
enabled = true
required = true
auth = "oauth"
bearer_token_env_var = "REMOTE_TOKEN"
default_tools_approval_mode = "prompt"

[mcp_servers.local]
command = "local-server"
enabled = true
default_tools_approval_mode = "prompt"
""".lstrip(),
    )
    return _analyze(project)


def _unknown_chain_manifest(project: Path) -> AgentManifest:
    """Build a same-target chain with an Unknown execute effect."""

    manifest = _analyze(project)
    source = next(
        permission.sources[0]
        for permission in manifest.permissions.permissions
        if permission.target == "mcp-server:remote"
    )
    payload: dict[str, Any] = manifest.model_dump(mode="python")
    permissions = [
        *payload["permissions"]["permissions"],
        ManifestPermission(
            permission_id="permission:execute:mcp-server:remote:unknown-demo",
            action=ManifestPermissionAction.EXECUTE,
            effect=ManifestPermissionEffect.UNKNOWN,
            resource=ManifestResourceKind.SHELL,
            scope=ManifestResourceScope.EXTERNAL,
            target="mcp-server:remote",
            sources=(source,),
        ).model_dump(mode="python"),
    ]
    permissions.sort(key=lambda item: item["permission_id"])
    payload["permissions"] = {
        **payload["permissions"],
        "permissions": permissions,
    }
    payload["unknowns"] = ()
    return UnknownExtractor().extract(AgentManifest.model_validate(payload))


def _incomplete_manifest(project: Path) -> AgentManifest:
    manifest = _explicit_chain_manifest(project)
    payload: dict[str, Any] = manifest.model_dump(mode="python")
    payload["coverage"] = {
        **payload["coverage"],
        "complete": False,
        "discovered_assets": payload["coverage"]["inspected_assets"] + 1,
        "skipped_assets": 1,
        "issues": (
            {
                "code": "unreadable",
                "root_id": "project",
                "path": "skipped.md",
            },
        ),
    }
    payload["unknowns"] = ()
    return UnknownExtractor().extract(AgentManifest.model_validate(payload))


def _run_rules(manifest: AgentManifest) -> CapabilityRuleRunResult:
    return DeterministicCapabilityRuleRunner(builtin_capability_rules()).run(manifest)


def _rejection_reasons(gate: Any, finding: Any) -> list[str]:
    if gate.matched:
        return ["matched"]
    reasons: list[str] = []
    if not gate.coverage_complete:
        reasons.append("incomplete_coverage")
    if gate.relevant_unknowns:
        reasons.append("relevant_unknown")
    if finding.correlation.value not in {"same_target", "parent_child"}:
        reasons.append("ineligible_correlation")
    return reasons or ["no_match"]


def _scenario(
    scenario_id: str,
    title: str,
    manifest: AgentManifest,
    expected_match: bool,
) -> dict[str, Any]:
    plain = _run_rules(manifest)
    gated = DeterministicCapabilityShadowGateEngine().apply(manifest, plain)
    finding = next(item for item in gated.findings if item.rule_id == COMPONENT_RULE_ID)
    plain_finding = next(
        item for item in plain.findings if item.finding_id == finding.finding_id
    )
    gate = finding.capability_shadow_gate
    if gate is None:
        raise RuntimeError("Shadow Gate demo did not attach a Gate assessment")
    rejection_reasons = _rejection_reasons(gate, finding)
    return {
        "scenario_id": scenario_id,
        "title": title,
        "expected_match": expected_match,
        "actual_match": gate.matched,
        "passed": gate.matched is expected_match,
        "finding_correlation": finding.correlation.value,
        "rejection_reason": ",".join(rejection_reasons),
        "rejection_reasons": rejection_reasons,
        "coverage_complete": gate.coverage_complete,
        "relevant_unknowns": gate.relevant_unknowns,
        "related_ids": list(finding.related_ids),
        "gate_id": gate.gate_id,
        "gate_version": gate.gate_version,
        "mode": gate.mode,
        "qualification": gate.qualification,
        "blocks": gate.blocks,
        "hard_gate": finding.hard_gate,
        "risk_unchanged": {
            "finding_id_unchanged": finding.finding_id == plain_finding.finding_id,
            "score_unchanged": finding.score == plain_finding.score,
            "severity_unchanged": finding.severity is plain_finding.severity,
            "confidence_unchanged": finding.confidence is plain_finding.confidence,
            "hard_gate_remains_false": finding.hard_gate is False,
        },
    }


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is missing or unsafe")
    data = path.read_bytes()
    if len(data) > 4 * 1024 * 1024:
        raise ValueError(f"{label} exceeds the bounded size")
    payload: object = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return cast(dict[str, Any], payload)


def _coverage(
    repository_root: Path,
    corpus: Path,
    matrix: Path | None,
) -> tuple[int, dict[str, Any], list[dict[str, Any]]]:
    coverage_script = repository_root / "scripts" / "check-gate-calibration-coverage.py"
    command = [
        sys.executable,
        str(coverage_script),
        "--corpus",
        str(corpus),
        "--format",
        "json",
    ]
    if matrix is not None:
        command.extend(("--matrix", str(matrix)))
    environment = dict(os.environ)
    source_root = repository_root / "src"
    environment["PYTHONPATH"] = (
        str(source_root) + os.pathsep + environment.get("PYTHONPATH", "")
    )
    completed = subprocess.run(
        command,
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode not in {EXIT_READY, EXIT_INCOMPLETE}:
        raise ValueError("Gate Coverage Check failed")
    coverage_report = json.loads(completed.stdout)
    if not isinstance(coverage_report, dict):
        raise ValueError("Gate Coverage Check returned an invalid report")
    gate = next(
        item
        for item in coverage_report.get("gates", ())
        if isinstance(item, dict) and item.get("gate_id") == GATE_ID
    )
    matrix_path = matrix or corpus / "gate-coverage-matrix.json"
    matrix_payload = _load_json(matrix_path, "Gate coverage matrix")
    rows = matrix_payload.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Gate coverage matrix rows are invalid")
    gate_rows = [
        cast(dict[str, Any], row)
        for row in rows
        if isinstance(row, dict) and row.get("gate_id") == GATE_ID
    ]
    expected_match = sum(
        row.get("expected_gate_condition") == "match" for row in gate_rows
    )
    expected_no_match = sum(
        row.get("expected_gate_condition") == "no_match" for row in gate_rows
    )
    expected_no_match_eligible = sum(
        row.get("expected_gate_condition") == "no_match"
        and row.get("is_eligible_negative") is True
        for row in gate_rows
    )
    expected_no_match_unknown = sum(
        row.get("expected_gate_condition") == "no_match"
        and row.get("has_unknown") is True
        for row in gate_rows
    )
    gate_summary = {
        **gate,
        "matrix_expected_match_count": expected_match,
        "matrix_expected_no_match_count": expected_no_match,
        "matrix_expected_no_match_eligible_count": expected_no_match_eligible,
        "matrix_expected_no_match_unknown_count": expected_no_match_unknown,
    }
    return completed.returncode, gate_summary, gate_rows


def _build_report(
    repository_root: Path, corpus: Path, matrix: Path | None
) -> dict[str, Any]:
    coverage_exit, coverage, matrix_rows = _coverage(repository_root, corpus, matrix)
    with tempfile.TemporaryDirectory(prefix="agentsec-shadow-gate-demo-") as temporary:
        root = Path(temporary)
        scenarios = (
            _scenario(
                "same-target-match",
                "Complete same-target chain",
                _explicit_chain_manifest(_scenario_project(root, "same-target")),
                True,
            ),
            _scenario(
                "parent-child-match",
                "Complete parent-child chain",
                _parent_child_chain_manifest(_scenario_project(root, "parent-child")),
                True,
            ),
            _scenario(
                "agent-wide-no-match",
                "Agent-wide declarations without target reachability",
                _agent_wide_manifest(_scenario_project(root, "agent-wide")),
                False,
            ),
            _scenario(
                "unknown-no-match",
                "Relevant Unknown prevents a match",
                _unknown_chain_manifest(_scenario_project(root, "unknown")),
                False,
            ),
            _scenario(
                "incomplete-coverage-no-match",
                "Incomplete Coverage prevents a match",
                _incomplete_manifest(_scenario_project(root, "incomplete")),
                False,
            ),
        )
    matches = sum(item["actual_match"] is True for item in scenarios)
    no_matches = len(scenarios) - matches
    demo_passed = all(item["passed"] is True for item in scenarios)
    return {
        "format": REPORT_FORMAT,
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "passed" if demo_passed else "failed",
        "gate": {
            "gate_id": GATE_ID,
            "component_rule_id": COMPONENT_RULE_ID,
            "floor": GATE_FLOOR,
            "gate_version": CAPABILITY_SHADOW_GATE_VERSION,
            "mode": "shadow",
            "qualification": "pilot_only",
            "blocks": False,
        },
        "coverage": coverage,
        "match_no_match": {
            "demo_match_count": matches,
            "demo_no_match_count": no_matches,
            "matrix_rows": matrix_rows,
        },
        "scenarios": list(scenarios),
        "summary": {
            "demo_scenario_count": len(scenarios),
            "demo_match_count": matches,
            "demo_no_match_count": no_matches,
            "coverage_exit_code": coverage_exit,
            "coverage_status": coverage["coverage_status"],
            "ci_blocking_enabled": False,
            "hard_gate_enabled": False,
            "fail_on_enabled": False,
        },
        "boundary": {
            "enforcement_mode": "report_only",
            "runtime_capability_verified": False,
            "global_safety_claimed": False,
            "ci_blocking_enabled": False,
            "hard_gate_enabled": False,
            "fail_on_enabled": False,
            "ground_truth_used_for_demo": False,
            "matrix_labels_are_seeded_expected_metadata": True,
        },
    }


def _render_text(report: dict[str, Any], language: str) -> str:
    coverage = report["coverage"]
    summary = report["summary"]
    chinese = language == "zh"
    scenario_titles_zh = {
        "same-target-match": "同一目标上的完整能力链",
        "parent-child-match": "同一父子工具族中的完整能力链",
        "agent-wide-no-match": "Agent-wide 声明无法证明目标可达性",
        "unknown-no-match": "相关 Unknown 阻止命中",
        "incomplete-coverage-no-match": "Coverage 不完整阻止命中",
    }
    rejection_reasons_zh = {
        "matched": "条件成立",
        "incomplete_coverage": "Coverage 不完整",
        "relevant_unknown": "存在相关 Unknown",
        "ineligible_correlation": "关联类型不具备 Gate 资格",
        "no_match": "条件不成立",
    }
    lines = [
        "AgentSec Capability Shadow Gate Demo"
        if not chinese
        else "AgentSec Capability Shadow Gate 演示",
        f"Status: {report['status'].upper()}"
        if not chinese
        else f"状态：{'通过' if report['status'] == 'passed' else '失败'}",
        f"Gate: {report['gate']['gate_id']} [{report['gate']['floor']}]",
        "Policy: shadow/report-only; blocks=false; hard_gate=false; CI blocking=false"
        if not chinese
        else "策略：Shadow/仅报告；blocks=false；hard_gate=false；不阻断 CI",
        "",
        "Coverage Statistics" if not chinese else "Coverage 统计",
        (
            f"  Matrix match: {coverage['matrix_expected_match_count']}"
            if not chinese
            else f"  矩阵期望 Match：{coverage['matrix_expected_match_count']}"
        ),
        (
            f"  Matrix no-match: {coverage['matrix_expected_no_match_count']}"
            if not chinese
            else f"  矩阵期望 No-match：{coverage['matrix_expected_no_match_count']}"
        ),
        (
            "  Eligible no-match: "
            f"{coverage['matrix_expected_no_match_eligible_count']}"
            if not chinese
            else "  可计入 No-match："
            f"{coverage['matrix_expected_no_match_eligible_count']}"
        ),
        (
            f"  Unknown boundary: {coverage['matrix_expected_no_match_unknown_count']}"
            if not chinese
            else f"  Unknown 边界：{coverage['matrix_expected_no_match_unknown_count']}"
        ),
        (
            f"  Positive samples: {coverage['positive_count']}"
            if not chinese
            else f"  正例样本：{coverage['positive_count']}"
        ),
        (
            "  Eligible negative samples: "
            f"{coverage['eligible_negative_or_near_miss_count']}"
            if not chinese
            else f"  可计入负例：{coverage['eligible_negative_or_near_miss_count']}"
        ),
        (
            f"  Coverage status: {coverage['coverage_status']}"
            if not chinese
            else f"  Coverage 状态：{coverage['coverage_status']}"
        ),
        "",
        "Live Match / No-match Scenarios"
        if not chinese
        else "实时 Match / No-match 场景",
    ]
    for item in report["scenarios"]:
        state = (
            ("MATCH" if item["actual_match"] else "NO-MATCH")
            if not chinese
            else ("命中" if item["actual_match"] else "未命中")
        )
        title = scenario_titles_zh[item["scenario_id"]] if chinese else item["title"]
        reason = (
            "、".join(
                rejection_reasons_zh[value] for value in item["rejection_reasons"]
            )
            if chinese
            else item["rejection_reason"]
        )
        lines.append(
            f"  [{state}] {item['scenario_id']}: {title} "
            f"correlation={item['finding_correlation']} "
            f"{'原因' if chinese else 'reason'}={reason}"
        )
    lines.extend(
        (
            "",
            (
                "Demo matches: "
                f"{summary['demo_match_count']}; "
                f"no-match: {summary['demo_no_match_count']}"
            ),
            "Boundary: static deterministic evidence only; no runtime proof, "
            "authorization, or CI enforcement.",
        )
    )
    if chinese:
        lines[-2] = (
            f"Demo 命中：{summary['demo_match_count']}；"
            f"未命中：{summary['demo_no_match_count']}"
        )
        lines[-1] = "边界：仅静态确定性证据；不证明运行时能力、授权或 CI 阻断。"
    return "\n".join(lines) + "\n"


def _scenario_project(root: Path, name: str) -> Path:
    project = root / name
    _project(project)
    return project


def _write_output(path: Path, content: str) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("calibration"))
    parser.add_argument("--matrix", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--language", choices=("en", "zh"), default="en")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[1]
    try:
        report = _build_report(repository_root, args.corpus, args.matrix)
        rendered = (
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            if args.format == "json"
            else _render_text(report, args.language)
        )
        if args.output is None:
            print(rendered, end="")
        else:
            _write_output(args.output, rendered)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        if isinstance(error, ValueError) and str(error) == "output already exists":
            message = "shadow Gate demo output already exists"
        else:
            message = f"shadow Gate demo failed safely: {type(error).__name__}"
        print(message, file=sys.stderr)
        raise SystemExit(EXIT_INVALID) from error
    except Exception as error:  # noqa: BLE001 - bounded fail-closed CLI
        print(
            f"shadow Gate demo failed safely: {type(error).__name__}", file=sys.stderr
        )
        raise SystemExit(EXIT_FAILED) from error

    if report["status"] != "passed":
        raise SystemExit(EXIT_FAILED)
    if report["summary"]["coverage_status"] != "ready":
        raise SystemExit(EXIT_INCOMPLETE)
    raise SystemExit(EXIT_READY)


if __name__ == "__main__":
    main()
