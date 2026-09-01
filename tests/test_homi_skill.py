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
