"""Contract tests for the packaged Homi AgentSec Skill."""

from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "integrations" / "homi" / "skill" / "agentsec-security-audit"


def test_homi_skill_contains_required_contract_files() -> None:
    required = (
        "SKILL.md",
        "README.md",
        "agents/openai.yaml",
        "references/integration-contract.md",
        "references/report-interpretation.md",
        "references/security-boundary.md",
        "schemas/request.schema.json",
        "schemas/response.schema.json",
        "commands/scan.sh",
        "commands/report.sh",
        "commands/manifest.sh",
        "commands/capability.sh",
        "commands/diff.sh",
        "commands/score.sh",
        "commands/attack-graph.sh",
        "commands/homi-diff.sh",
        "tests/smoke.sh",
    )
    for relative in required:
        path = SKILL / relative
        assert path.is_file(), relative


def test_homi_skill_entrypoint_has_valid_frontmatter_and_no_scaffold() -> None:
    content = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    assert content.startswith("---\n")
    assert "name: agentsec-security-audit" in content
    assert "description:" in content
    assert "TODO" not in content
    assert "report_only" in content
    assert "runtime_verified" in content
    assert "ci_blocked" in content


def test_homi_skill_ui_metadata_is_explicit() -> None:
    content = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
    assert 'display_name: "AgentSec Security Audit"' in content
    assert "allow_implicit_invocation: true" in content
    assert "$agentsec-security-audit" in content


def test_homi_skill_schemas_are_valid_json() -> None:
    for path in (SKILL / "schemas").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["$schema"]
        assert payload["type"] == "object"
        assert payload["additionalProperties"] is False


def test_homi_skill_shell_entrypoints_are_executable_and_do_not_use_eval() -> None:
    for path in (SKILL / "commands").glob("*.sh"):
        assert os.access(path, os.X_OK), path
        assert "eval " not in path.read_text(encoding="utf-8")


def test_homi_capability_diff_schema_is_strict_and_versioned() -> None:
    path = SKILL / "schemas" / "capability-diff.schema.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert payload["$id"].endswith("/homi-capability-diff.schema.json")
    assert payload["additionalProperties"] is False
    assert payload["properties"]["format"]["const"] == ("agentsec-homi-capability-diff")
    assert payload["properties"]["format_version"]["const"] == "0.1.0"
    assert set(payload["required"]) == {
        "format",
        "format_version",
        "complete",
        "before_report_sha256",
        "after_report_sha256",
        "before_status",
        "after_status",
        "before_coverage_metrics",
        "after_coverage_metrics",
        "capability_changes",
        "capability_change_summary",
        "finding_deltas",
        "finding_delta_summary",
        "risk_score",
        "authority",
    }
    assert payload["$defs"]["ReportOnlyAuthority"]["additionalProperties"] is False
