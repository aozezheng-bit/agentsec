"""P2I-03 Capability Assessment Text/JSON reporting and schema tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentsec.application import (
    AgentAnalysisRequest,
    CapabilityAssessmentEngine,
)
from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.reporting import (
    CAPABILITY_ASSESSMENT_JSON_FORMAT,
    CAPABILITY_ASSESSMENT_JSON_FORMAT_VERSION,
    CAPABILITY_ASSESSMENT_JSON_SCHEMA_FILENAME,
    CapabilityAssessmentJsonRenderer,
    CapabilityAssessmentJsonReport,
    CapabilityAssessmentTextLimits,
    CapabilityAssessmentTextRenderer,
    CapabilityAssessmentValidationCode,
    CapabilityAssessmentValidationError,
    decode_capability_assessment_json,
    export_capability_assessment_json_schema,
    validate_capability_assessment_payload,
)
from agentsec.versioning import CAPABILITY_ASSESSMENT_OUTPUT_VERSION

_SECRET_MARKER = "p2i-03-assessment-secret"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _assessment(tmp_path: Path, *, incomplete: bool = False):  # type: ignore[no-untyped-def]
    project = tmp_path / ("incomplete" if incomplete else "complete")
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
    if incomplete:
        (project / "AGENTS.override.md").write_bytes(b"\xff\xfe")
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
    return CapabilityAssessmentEngine().assess(
        AgentAnalysisRequest(project_root=project, agent_id="release-agent")
    )


def test_capability_assessment_json_is_versioned_strict_complete_and_deterministic(
    tmp_path: Path,
) -> None:
    result = _assessment(tmp_path)
    renderer = CapabilityAssessmentJsonRenderer()

    first = renderer.render(result)
    second = renderer.render(result)
    payload = json.loads(first)
    validated = CapabilityAssessmentJsonReport.model_validate_json(first)

    assert first == second
    assert payload["format"] == CAPABILITY_ASSESSMENT_JSON_FORMAT
    assert payload["format_version"] == CAPABILITY_ASSESSMENT_OUTPUT_VERSION
    assert (
        CAPABILITY_ASSESSMENT_JSON_FORMAT_VERSION
        == CAPABILITY_ASSESSMENT_OUTPUT_VERSION
        == "0.2.0"
    )
    assert payload["status"] == "complete"
    assert payload["policy"] == {
        "ci_blocking_enabled": False,
        "enforcement_mode": "report_only",
        "global_safety_claimed": False,
        "runtime_capability_verified": False,
    }
    assert payload["summary"]["findings"] == len(result.rules.findings)
    assert payload["summary"]["highest_severity"] == "high"
    assert payload["summary"]["hard_gate_matches"] == 0
    assert payload["summary"]["manifest_coverage_complete"] is True
    assert payload["summary"]["rule_execution_complete"] is True
    assert payload["summary"]["unknowns"] == len(result.analysis.manifest.unknowns)
    assert payload["versions"]["capability_rule_pack"] == "0.2.0"
    assert payload["versions"]["capability_risk_model"] == "0.1.0"
    assert payload["versions"]["capability_assessment_output"] == "0.2.0"
    assert payload["manifest"]["schema_version"] == "0.3.0"
    assert len(payload["stage_trace"]) == 9
    assert payload["rule_failures"] == []
    assert {finding["rule_id"] for finding in payload["findings"]} == {
        finding.rule_id for finding in result.rules.findings
    }
    assert validated.manifest == result.analysis.manifest
    assert _SECRET_MARKER not in first
    assert "example.invalid" not in first
    assert first.endswith("\n")


def test_json_report_rejects_shadow_gate_contract_drift(tmp_path: Path) -> None:
    result = _assessment(tmp_path)
    payload = json.loads(CapabilityAssessmentJsonRenderer().render(result))
    chain = next(
        item for item in payload["findings"] if item["rule_id"] == "CAP-CHAIN-001"
    )
    shadow_gate = chain["capability_shadow_gate"]
    assert shadow_gate is not None

    shadow_gate["gate_version"] = "9.9.9"
    with pytest.raises(ValidationError):
        CapabilityAssessmentJsonReport.model_validate(payload)

    shadow_gate["gate_version"] = "0.1.0"
    shadow_gate["matched"] = True
    with pytest.raises(ValidationError):
        CapabilityAssessmentJsonReport.model_validate(payload)


def test_capability_assessment_json_marks_incomplete_coverage_visibly(
    tmp_path: Path,
) -> None:
    result = _assessment(tmp_path, incomplete=True)

    payload = json.loads(CapabilityAssessmentJsonRenderer().render(result))

    assert payload["status"] == "incomplete"
    assert payload["summary"]["manifest_coverage_complete"] is False
    assert payload["summary"]["rule_execution_complete"] is True
    assert payload["manifest"]["coverage"]["complete"] is False
    assert any(
        finding["rule_id"] == "CAP-COVERAGE-001" for finding in payload["findings"]
    )


def test_capability_assessment_validation_is_compatibility_first_and_safe() -> None:
    payload = {
        "format": CAPABILITY_ASSESSMENT_JSON_FORMAT,
        "format_version": "0.3.0",
        "secret": _SECRET_MARKER,
    }

    with pytest.raises(CapabilityAssessmentValidationError) as captured:
        validate_capability_assessment_payload(payload)

    assert captured.value.code is (
        CapabilityAssessmentValidationCode.UNSUPPORTED_FORMAT_VERSION
    )
    assert _SECRET_MARKER not in str(captured.value)

    with pytest.raises(CapabilityAssessmentValidationError) as invalid_json:
        decode_capability_assessment_json(
            '{"format":"agentsec-capability-assessment","format_version":"0.1.0",'
            f'"secret":"{_SECRET_MARKER}" invalid}}'
        )
    assert invalid_json.value.code is CapabilityAssessmentValidationCode.INVALID_JSON
    assert _SECRET_MARKER not in str(invalid_json.value)

    with pytest.raises(CapabilityAssessmentValidationError) as unsafe_field:
        validate_capability_assessment_payload(
            {
                "format": CAPABILITY_ASSESSMENT_JSON_FORMAT,
                "format_version": CAPABILITY_ASSESSMENT_JSON_FORMAT_VERSION,
                _SECRET_MARKER: True,
            }
        )
    assert unsafe_field.value.code is CapabilityAssessmentValidationCode.INVALID_PAYLOAD
    assert _SECRET_MARKER not in str(unsafe_field.value)
    assert "<field>" in str(unsafe_field.value)


def test_capability_assessment_schema_is_deterministic_strict_and_versioned(
    tmp_path: Path,
) -> None:
    first = export_capability_assessment_json_schema(tmp_path / "first")
    second = export_capability_assessment_json_schema(tmp_path / "second")
    first_text = first.read_text(encoding="utf-8")
    second_text = second.read_text(encoding="utf-8")
    schema = json.loads(first_text)

    assert first.name == CAPABILITY_ASSESSMENT_JSON_SCHEMA_FILENAME
    assert first_text == second_text
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["format"]["const"] == (
        CAPABILITY_ASSESSMENT_JSON_FORMAT
    )
    assert schema["properties"]["format_version"]["const"] == "0.2.0"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "format",
        "format_version",
        "status",
        "versions",
        "policy",
        "summary",
        "manifest",
        "findings",
        "stage_trace",
        "rule_failures",
    }


def test_capability_assessment_text_has_management_summary_and_developer_evidence(
    tmp_path: Path,
) -> None:
    result = _assessment(tmp_path)

    rendered = CapabilityAssessmentTextRenderer().render(result)

    assert "AgentSec Capability Assessment" in rendered
    assert "Status: COMPLETE" in rendered
    assert "Policy: report-only; CI blocking disabled; runtime not verified" in rendered
    assert "Management Summary" in rendered
    assert "Highest severity: HIGH" in rendered
    assert "Confidence:" in rendered
    assert "Coverage:" in rendered
    assert "Rule execution: COMPLETE" in rendered
    assert "Version Vector" in rendered
    assert "Stage Trace" in rendered
    assert "Findings" in rendered
    assert "CAP-APPROVAL-001" in rendered
    assert "Correlation:" in rendered
    assert "Related IDs:" in rendered
    assert "Evidence:" in rendered
    assert ".codex/config.toml" in rendered
    assert "Recommendation:" in rendered
    assert (
        "This report does not prove runtime reachability or global Agent safety."
        in rendered
    )
    assert _SECRET_MARKER not in rendered
    assert "example.invalid" not in rendered
    assert "\x1b" not in rendered


def test_capability_assessment_text_supports_chinese_and_visible_limits(
    tmp_path: Path,
) -> None:
    result = _assessment(tmp_path)
    renderer = CapabilityAssessmentTextRenderer(
        language=CapabilityRuleLanguage.ZH,
        limits=CapabilityAssessmentTextLimits(
            max_findings=1,
            max_evidence_per_finding=1,
            max_related_ids_per_finding=1,
            max_recommendations_per_finding=1,
        ),
    )

    rendered = renderer.render(result)

    assert "AgentSec 能力评估" in rendered
    assert "状态：完整" in rendered
    assert "管理摘要" in rendered
    assert "最高严重性：高" in rendered
    assert "发现项" in rendered
    assert "相关性：" in rendered
    assert "修复建议：" in rendered
    assert "因展示上限省略" in rendered
    assert "不代表运行时可达性或 Agent 全局安全已被证明" in rendered
