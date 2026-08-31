"""P2I-03 Capability Assessment application orchestration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.application import (
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    CapabilityAssessmentEngine,
    CapabilityAssessmentError,
)
from agentsec.capability_rules import (
    CapabilityRuleFailure,
    CapabilityRuleRunResult,
)

_SECRET_MARKER = "p2i-03-application-secret"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _risky_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "AGENTS.md",
        """
---
delegates_to: [deployer]
persists_memory: release_state
---
# Release Agent
""".lstrip(),
    )
    _write(
        project / ".codex" / "config.toml",
        f"""
[mcp_servers.local]
command = "local-{_SECRET_MARKER}"
enabled = true
bearer_token_env_var = "LOCAL_TOKEN"
default_tools_approval_mode = "auto"

[mcp_servers.remote]
url = "https://example.invalid/mcp?token={_SECRET_MARKER}"
enabled = true
required = true
auth = "oauth"
default_tools_approval_mode = "auto"
""".lstrip(),
    )
    return project


def test_capability_assessment_composes_analysis_and_rules_deterministically(
    tmp_path: Path,
) -> None:
    project = _risky_project(tmp_path)
    engine = CapabilityAssessmentEngine()
    request = AgentAnalysisRequest(project_root=project, agent_id="release-agent")

    first = engine.assess(request)
    second = engine.assess(request)

    assert first == second
    assert first.complete is True
    assert first.analysis.complete is True
    assert first.rules.complete is True
    assert first.rules.agent_id == first.analysis.manifest.identity.agent_id
    assert first.versions == first.analysis.versions
    assert {finding.rule_id for finding in first.rules.findings} == {
        "CAP-APPROVAL-001",
        "CAP-AUTONETWORK-001",
        "CAP-AUTOSECRET-001",
        "CAP-CHAIN-001",
        "CAP-COVERAGE-001",
        "CAP-DELEGATE-001",
        "CAP-DELEGATEEXTERNAL-001",
        "CAP-DELEGATEPERSIST-001",
        "CAP-EXTERNAL-001",
        "CAP-EXTERNALUNVERIFIED-001",
        "CAP-MEMORYNETWORK-001",
        "CAP-MEMORYSECRET-001",
        "CAP-NOSANDBOX-001",
        "CAP-PERSIST-001",
        "CAP-REQUIREDNOFILTER-001",
        "CAP-REQUIREDNOTIMEOUT-001",
    }
    assert _SECRET_MARKER not in repr(first)
    assert "example.invalid" not in repr(first)


def test_capability_assessment_preserves_incomplete_manifest_status(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    (project / "AGENTS.override.md").write_bytes(b"\xff\xfe")
    _write(
        project / ".codex" / "config.toml",
        '[mcp_servers.local]\ncommand = "local"\n',
    )

    result = CapabilityAssessmentEngine().assess(
        AgentAnalysisRequest(project_root=project, agent_id="release-agent")
    )

    assert result.complete is False
    assert result.analysis.manifest.coverage.complete is False
    assert result.rules.complete is True
    assert any(
        finding.rule_id == "CAP-COVERAGE-001" for finding in result.rules.findings
    )


def test_capability_assessment_marks_isolated_rule_failures_incomplete(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")

    class FailingRuleRunner:
        def run(self, manifest):  # type: ignore[no-untyped-def]
            return CapabilityRuleRunResult(
                agent_id=manifest.identity.agent_id,
                evaluated_rule_ids=("CAP-TEST-999",),
                findings=(),
                failures=(CapabilityRuleFailure(rule_id="CAP-TEST-999"),),
            )

    result = CapabilityAssessmentEngine(
        analysis_engine=AgentAnalysisPipeline(),
        rule_runner=FailingRuleRunner(),
    ).assess(AgentAnalysisRequest(project_root=project, agent_id="release-agent"))

    assert result.analysis.complete is True
    assert result.rules.complete is False
    assert result.complete is False


def test_capability_assessment_wraps_required_rule_runner_failure_safely(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")

    class CrashingRuleRunner:
        def run(self, manifest):  # type: ignore[no-untyped-def]
            del manifest
            raise RuntimeError(f"unsafe rule engine failure: {_SECRET_MARKER}")

    engine = CapabilityAssessmentEngine(rule_runner=CrashingRuleRunner())

    with pytest.raises(CapabilityAssessmentError) as captured:
        engine.assess(
            AgentAnalysisRequest(project_root=project, agent_id="release-agent")
        )

    assert _SECRET_MARKER not in str(captured.value)
    assert "unsafe rule engine failure" not in str(captured.value)
