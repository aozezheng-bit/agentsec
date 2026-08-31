"""P2-29 executable CI example acceptance tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPOSITORY_ROOT / "scripts" / "run-agentsec-ci.sh"
VALIDATOR = REPOSITORY_ROOT / "scripts" / "validate-ci-examples.py"
AGENTSEC = REPOSITORY_ROOT / ".venv" / "bin" / "agentsec"


def test_ci_runner_is_executable_and_usage_is_stable() -> None:
    assert RUNNER.is_file()
    assert os.access(RUNNER, os.X_OK)

    result = subprocess.run(
        [str(RUNNER)],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 64
    assert "Usage:" in result.stderr


def test_github_workflow_preserves_then_enforces_exit_code() -> None:
    workflow = REPOSITORY_ROOT / ".github" / "workflows" / "agentsec.yml"
    text = workflow.read_text(encoding="utf-8")
    payload = yaml.load(text, Loader=yaml.BaseLoader)

    assert isinstance(payload, dict)
    assert set(payload["on"]) == {"pull_request", "workflow_dispatch"}
    assert "continue-on-error" not in text
    assert "scripts/run-agentsec-ci.sh" in text
    assert "actions/upload-artifact@v4" in text
    assert "github/codeql-action/upload-sarif@v4" in text
    assert "Enforce the preserved AgentSec exit code" in text
    assert text.count("if: always()") >= 2
    assert text == (
        REPOSITORY_ROOT / "docs" / "examples" / "ci" / "github-actions.yml"
    ).read_text(encoding="utf-8")


def test_trusted_github_workflow_separates_target_and_trust_sources() -> None:
    example = (
        REPOSITORY_ROOT / "docs" / "examples" / "ci" / "github-actions-trusted.yml"
    )
    text = example.read_text(encoding="utf-8")
    payload = yaml.load(text, Loader=yaml.BaseLoader)

    assert isinstance(payload, dict)
    assert text.count("actions/checkout@v5") >= 2
    assert "AGENTSEC_TRUST_ROOT" in text
    assert "AGENTSEC_EXPECT_POLICY_SHA256" in text
    assert "persist-credentials: false" in text
    assert "continue-on-error" not in text


def test_gitlab_example_uploads_reports_even_on_policy_failure() -> None:
    example = REPOSITORY_ROOT / "docs" / "examples" / "ci" / "gitlab-ci.yml"
    payload = yaml.safe_load(example.read_text(encoding="utf-8"))

    assert payload["agentsec"]["artifacts"]["when"] == "always"
    assert payload["agentsec"]["script"] == [
        'scripts/run-agentsec-ci.sh "$AGENTSEC_PROJECT_ROOT" '
        '"$AGENTSEC_POLICY_PATH" "$AGENTSEC_OUTPUT_DIR"'
    ]


def test_ci_examples_replay_documented_decision_matrix() -> None:
    result = subprocess.run(
        [str(AGENTSEC.parent / "python"), str(VALIDATOR), "--agentsec", str(AGENTSEC)],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS safe-allow: exit 0" in result.stdout
    assert "PASS risky-block: exit 1" in result.stdout
    assert "PASS incomplete-fail-closed: exit 2" in result.stdout
    assert "PASS invalid-policy: exit 3" in result.stdout
    assert "PASS active-waiver-allow: exit 0" in result.stdout
    assert "PASS expired-waiver-block: exit 1" in result.stdout
    assert "PASS trusted-pin-block: exit 1" in result.stdout
    assert "PASS trusted-pin-mismatch: exit 3" in result.stdout
    assert "PASS trusted-root-block: exit 1" in result.stdout
