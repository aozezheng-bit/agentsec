"""P2-15B policy-controlled Capability CI enforcement tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.cli import ExitCode, app
from agentsec.policy import PolicyError, load_policy

runner = CliRunner()


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("# Safe agent\n", encoding="utf-8")
    return project


def _policy(enabled: bool = False, mode: str = "report_only") -> dict[str, object]:
    return {
        "format": "agentsec-capability-ci-policy",
        "schema_version": "0.2.0",
        "policy_id": "test-policy",
        "policy_version": "0.1.0",
        "enabled": enabled,
        "enforcement_mode": mode,
        "fail_on": {"qualified_gates": []},
        "coverage": {"require_complete": True, "require_unknown_free": False},
        "safety": {
            "allow_llm_authority": False,
            "allow_runtime_unverified_authority": False,
        },
    }


def test_policy_rejects_unknown_fields_and_unsafe_authority(tmp_path: Path) -> None:
    policy = _policy()
    policy["unexpected"] = "reject me"
    path = tmp_path / "policy.json"
    _write(path, policy)
    with pytest.raises(PolicyError):
        load_policy(path)

    policy = _policy(enabled=True, mode="enforce")
    policy["safety"] = {"allow_llm_authority": True}
    _write(path, policy)
    with pytest.raises(PolicyError):
        load_policy(path)


def test_enforce_is_explicit_and_report_only_does_not_block(tmp_path: Path) -> None:
    project = _project(tmp_path)
    policy_path = tmp_path / "policy.json"
    _write(policy_path, _policy())
    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(project),
            "--agent-id",
            "test-agent",
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.SUCCESS
    payload = json.loads(result.stdout)
    assert payload["decision"] == "allow"
    assert payload["policy"]["enabled"] is False
    assert payload["boundary"]["hard_gate"] is False


def test_enforce_rejects_policy_configuration_before_analysis(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    policy = _policy(enabled=True, mode="enforce")
    policy["fail_on"] = {"qualified_gates": ["HG-UNKNOWN-001"]}
    _write(policy_path, policy)
    result = runner.invoke(
        app,
        ["capability", "enforce", str(tmp_path), "--policy", str(policy_path)],
    )
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR
    assert "policy error" in result.stderr.lower()
