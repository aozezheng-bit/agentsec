"""P2-16 Capability Risk Score Contract regression tests."""

from __future__ import annotations

import json
from pathlib import Path

from agentsec.application import (
    AgentAnalysisRequest,
    CapabilityAssessmentEngine,
)
from agentsec.capability_rules import (
    CapabilityCorrelation,
    CapabilityRuleLanguage,
)
from agentsec.domain import EvidenceConfidence, LikelihoodLevel
from agentsec.reporting import (
    CapabilityAssessmentJsonRenderer,
    CapabilityAssessmentTextRenderer,
)
from agentsec.risk import (
    IMPACT_ORDINALS,
    agentsec_base_score,
    nist_risk_level,
    nist_semi_quantitative_value,
    severity_for_score,
)
from agentsec.versioning import CAPABILITY_RISK_MODEL_VERSION


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _assessment(tmp_path: Path, *, incomplete: bool = False):  # type: ignore[no-untyped-def]
    project = tmp_path / ("incomplete" if incomplete else "complete")
    project.mkdir()
    _write(
        project / "AGENTS.md",
        "---\ndelegates_to: [deployer]\npersists_memory: release_state\n---\n"
        "# Release Agent\n",
    )
    if incomplete:
        (project / "AGENTS.override.md").write_bytes(b"\xff\xfe")
    _write(
        project / ".codex" / "config.toml",
        """
[mcp_servers.local]
command = "local-server"
enabled = true
bearer_token_env_var = "LOCAL_TOKEN"
default_tools_approval_mode = "auto"

[mcp_servers.remote]
url = "https://example.invalid/mcp"
enabled = true
required = true
auth = "oauth"
default_tools_approval_mode = "auto"
""".lstrip(),
    )
    return CapabilityAssessmentEngine().assess(
        AgentAnalysisRequest(project_root=project, agent_id="release-agent")
    )


def test_capability_findings_follow_the_complete_p2_16_score_contract(
    tmp_path: Path,
) -> None:
    """Every materialized Finding preserves the NIST-to-Score trace."""

    result = _assessment(tmp_path)

    assert result.rules.findings
    for finding in result.rules.findings:
        expected_impact = max(
            (rating.level for rating in finding.impact_ratings),
            key=IMPACT_ORDINALS.__getitem__,
        )
        expected_level = nist_risk_level(finding.likelihood, expected_impact)

        assert finding.impact is expected_impact
        assert finding.risk_level is expected_level
        assert finding.nist_semi_quantitative_value == (
            nist_semi_quantitative_value(expected_level)
        )
        assert finding.score == agentsec_base_score(expected_level)
        assert finding.severity is severity_for_score(finding.score)
        assert finding.capability_risk_model_version == CAPABILITY_RISK_MODEL_VERSION
        assert finding.mapping_basis
        assert finding.hard_gate is False


def test_capability_report_text_and_json_preserve_identical_risk_semantics(
    tmp_path: Path,
) -> None:
    """Text and JSON expose the same P2-16 risk fields and version provenance."""

    result = _assessment(tmp_path)
    payload = json.loads(CapabilityAssessmentJsonRenderer().render(result))
    rendered = CapabilityAssessmentTextRenderer(
        language=CapabilityRuleLanguage.ZH
    ).render(result)

    assert payload["versions"]["capability_risk_model"] == CAPABILITY_RISK_MODEL_VERSION
    assert payload["policy"] == {
        "enforcement_mode": "report_only",
        "ci_blocking_enabled": False,
        "global_safety_claimed": False,
        "runtime_capability_verified": False,
    }
    assert "分数：" in rendered
    assert "可能性：" in rendered
    assert "影响：" in rendered
    assert "证据置信度：" in rendered

    json_by_id = {finding["finding_id"]: finding for finding in payload["findings"]}
    for finding in result.rules.findings:
        serialized = json_by_id[finding.finding_id]
        assert serialized["likelihood"] == finding.likelihood.value
        assert serialized["impact"] == finding.impact.value
        assert serialized["risk_level"] == finding.risk_level.value
        assert serialized["nist_semi_quantitative_value"] == (
            finding.nist_semi_quantitative_value
        )
        assert serialized["score"] == finding.score
        assert serialized["severity"] == finding.severity.value
        assert serialized["confidence"] == finding.confidence.value
        assert serialized["hard_gate"] is False
        assert (
            serialized["capability_risk_model_version"] == CAPABILITY_RISK_MODEL_VERSION
        )


def test_correlation_confidence_and_unknown_boundaries_remain_report_only(
    tmp_path: Path,
) -> None:
    """D-confidence and incomplete findings remain visible without score dilution."""

    result = _assessment(tmp_path)
    agent_wide = next(
        finding
        for finding in result.rules.findings
        if finding.correlation is CapabilityCorrelation.AGENT_WIDE
    )

    assert agent_wide.confidence is EvidenceConfidence.D
    assert agent_wide.likelihood is LikelihoodLevel.LOW
    assert agent_wide.hard_gate is False
    assert agent_wide.score == agentsec_base_score(agent_wide.risk_level)
    assert agent_wide.severity is severity_for_score(agent_wide.score)

    incomplete = _assessment(tmp_path, incomplete=True)
    coverage_findings = tuple(
        finding
        for finding in incomplete.rules.findings
        if finding.rule_id == "CAP-COVERAGE-001"
    )

    assert incomplete.complete is False
    assert coverage_findings
    assert all(
        finding.correlation is CapabilityCorrelation.INCOMPLETE_COVERAGE
        for finding in coverage_findings
    )
    assert all(
        finding.confidence is EvidenceConfidence.D for finding in coverage_findings
    )
    assert all(
        finding.likelihood is LikelihoodLevel.LOW for finding in coverage_findings
    )
    assert all(finding.hard_gate is False for finding in coverage_findings)
