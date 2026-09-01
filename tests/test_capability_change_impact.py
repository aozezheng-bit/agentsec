"""P2-13 Capability Change Impact and Finding Delta tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec.application import (
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    DeterministicManifestCapabilityChangeImpactEngine,
)
from agentsec.capability_rules import CapabilityRuleLanguage
from agentsec.change_impact import (
    CAPABILITY_CHANGE_IMPACT_FORMAT_VERSION,
    CapabilityChangeImpactValidationCode,
    CapabilityChangeImpactValidationError,
    CapabilityFindingDeltaStatus,
    CapabilityImpactDirection,
    CapabilitySemanticField,
    decode_capability_change_impact_json,
    encode_capability_change_impact_json,
    export_capability_change_impact_json_schema,
    validate_capability_change_impact_payload,
)
from agentsec.cli import app
from agentsec.cli.exit_codes import ExitCode
from agentsec.domain import Severity
from agentsec.manifests import CapabilityDimension, encode_agent_manifest_json
from agentsec.reporting import (
    CapabilityChangeImpactJsonRenderer,
    CapabilityChangeImpactTextLimits,
    CapabilityChangeImpactTextRenderer,
)
from agentsec.versioning import CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION

REPOSITORY_ROOT = Path(__file__).parents[1]
DEMO_ROOT = REPOSITORY_ROOT / "demos" / "capability-drift-agent"
_SECRET_MARKER = "p2-13-secret-must-not-leak"
runner = CliRunner()


def _manifest(case: str):  # type: ignore[no-untyped-def]
    return (
        AgentAnalysisPipeline()
        .analyze(
            AgentAnalysisRequest(
                project_root=DEMO_ROOT / case,
                agent_id="release-agent",
            )
        )
        .manifest
    )


def _report(before: str, after: str):  # type: ignore[no-untyped-def]
    return DeterministicManifestCapabilityChangeImpactEngine().compare(
        before=_manifest(before),
        after=_manifest(after),
    )


def _write_project(path: Path, *, trailing_comment: str) -> Path:
    path.mkdir()
    (path / "AGENTS.md").write_text("# Agent\n", encoding="utf-8")
    config = path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_text(
        f"""
[mcp_servers.release]
command = "synthetic-{_SECRET_MARKER}"
enabled = true
default_tools_approval_mode = "auto"
{trailing_comment}
""".lstrip(),
        encoding="utf-8",
    )
    return path


def test_risky_drift_reports_semantic_before_after_and_added_findings() -> None:
    first = _report("baseline", "risky-drift")
    second = _report("baseline", "risky-drift")

    assert first == second
    assert first.status == "complete"
    assert first.format_version == CAPABILITY_CHANGE_IMPACT_FORMAT_VERSION
    assert (
        CAPABILITY_CHANGE_IMPACT_FORMAT_VERSION
        == CAPABILITY_CHANGE_IMPACT_OUTPUT_VERSION
        == "0.1.0"
    )
    assert first.summary.capability_changes == 35
    assert first.summary.assessed_change_impacts == 14
    assert first.summary.added_findings == 17
    assert first.summary.resolved_findings == 0
    assert first.summary.added_high_or_critical == 3
    assert first.summary.highest_before_severity is Severity.NONE
    assert first.summary.highest_after_severity is Severity.HIGH
    assert {impact.dimension for impact in first.change_impacts} == {
        CapabilityDimension.TOOL,
        CapabilityDimension.PERMISSION,
        CapabilityDimension.CONTROL,
    }
    assert any(
        impact.direction is CapabilityImpactDirection.INCREASED_EXPOSURE
        for impact in first.change_impacts
    )
    assert all(
        delta.status is CapabilityFindingDeltaStatus.ADDED
        for delta in first.finding_delta
    )
    encoded = encode_capability_change_impact_json(first)
    assert _SECRET_MARKER not in encoded
    assert "example.invalid" not in encoded
    assert decode_capability_change_impact_json(encoded) == first


def test_remediation_reports_reduced_exposure_and_resolved_findings() -> None:
    report = _report("risky-drift", "remediated")

    assert report.status == "complete"
    assert report.summary.before_findings == 17
    assert report.summary.after_findings == 0
    assert report.summary.resolved_findings == 17
    assert report.summary.resolved_high_or_critical == 3
    assert report.summary.highest_before_severity is Severity.HIGH
    assert report.summary.highest_after_severity is Severity.NONE
    assert report.summary.reduced_exposure > report.summary.increased_exposure
    assert all(
        delta.status is CapabilityFindingDeltaStatus.RESOLVED
        for delta in report.finding_delta
    )


def test_semantic_states_expose_only_reviewed_normalized_fields() -> None:
    report = _report("baseline", "risky-drift")
    allowed_fields = set(CapabilitySemanticField)

    for impact in report.change_impacts:
        for state in (impact.before, impact.after):
            if state is None:
                continue
            assert state.dimension is impact.dimension
            assert state.item_id == impact.item_id
            assert {attribute.field for attribute in state.attributes} <= allowed_fields
            assert all(
                _SECRET_MARKER not in value and "example.invalid" not in value
                for attribute in state.attributes
                for value in attribute.values
            )
            assert all(
                attribute.field.value != "name" for attribute in state.attributes
            )


def test_same_logical_findings_are_unchanged_or_evidence_changed(
    tmp_path: Path,
) -> None:
    unchanged = DeterministicManifestCapabilityChangeImpactEngine().compare(
        before=_manifest("risky-drift"),
        after=_manifest("risky-drift"),
    )
    assert unchanged.summary.capability_changes == 0
    assert unchanged.summary.unchanged_findings == 17
    assert all(
        delta.status is CapabilityFindingDeltaStatus.UNCHANGED
        for delta in unchanged.finding_delta
    )

    before_project = _write_project(tmp_path / "before", trailing_comment="# before")
    after_project = _write_project(tmp_path / "after", trailing_comment="# after")
    pipeline = AgentAnalysisPipeline()
    before = pipeline.analyze(
        AgentAnalysisRequest(project_root=before_project, agent_id="release-agent")
    ).manifest
    after = pipeline.analyze(
        AgentAnalysisRequest(project_root=after_project, agent_id="release-agent")
    ).manifest
    changed = DeterministicManifestCapabilityChangeImpactEngine().compare(
        before=before,
        after=after,
    )

    assert changed.summary.before_findings == changed.summary.after_findings == 3
    assert changed.summary.changed_findings == 3
    assert all(
        delta.status is CapabilityFindingDeltaStatus.CHANGED
        and delta.changed_fields == ("evidence",)
        for delta in changed.finding_delta
    )


def test_incomplete_coverage_remains_incomplete_and_visible() -> None:
    report = _report("incomplete", "risky-drift")

    assert report.status == "incomplete"
    assert report.summary.capability_diff_complete is False
    assert report.summary.after_rule_execution_complete is True
    rendered = CapabilityChangeImpactTextRenderer().render(report)
    assert "WARNING:" in rendered
    assert "not exhaustive" in rendered


def test_json_schema_validation_is_deterministic_strict_and_safe(
    tmp_path: Path,
) -> None:
    report = _report("baseline", "risky-drift")
    rendered = CapabilityChangeImpactJsonRenderer().render(report)
    first = export_capability_change_impact_json_schema(tmp_path / "first")
    second = export_capability_change_impact_json_schema(tmp_path / "second")

    assert first.read_bytes() == second.read_bytes()
    schema = json.loads(first.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["x-agentsec-capability-change-impact-output-version"] == "0.1.0"
    assert decode_capability_change_impact_json(rendered) == report

    payload = json.loads(rendered)
    payload[_SECRET_MARKER] = True
    with pytest.raises(CapabilityChangeImpactValidationError) as captured:
        validate_capability_change_impact_payload(payload)
    assert captured.value.code is CapabilityChangeImpactValidationCode.INVALID_PAYLOAD
    assert _SECRET_MARKER not in str(captured.value)
    assert "<field>" in captured.value.field_paths


def test_text_reports_are_bilingual_bounded_and_repeat_boundaries() -> None:
    report = _report("baseline", "risky-drift")
    english = CapabilityChangeImpactTextRenderer(
        limits=CapabilityChangeImpactTextLimits(
            max_change_impacts=1,
            max_finding_delta=1,
        )
    ).render(report)
    chinese = CapabilityChangeImpactTextRenderer(
        language=CapabilityRuleLanguage.ZH,
        limits=CapabilityChangeImpactTextLimits(
            max_change_impacts=1,
            max_finding_delta=1,
        ),
    ).render(report)

    assert "AgentSec Capability Change Impact" in english
    assert "Finding Delta: added=17" in english
    assert "omitted by display limit" in english
    assert "report-only" in english
    assert "does not prove runtime reachability" in english
    assert "AgentSec 能力变化影响" in chinese
    assert "Finding Delta：新增=17" in chinese
    assert "因展示上限省略" in chinese
    assert "不启用 CI 阻断" in chinese
    assert _SECRET_MARKER not in english + chinese


def test_capability_impact_cli_supports_json_chinese_output_and_safe_artifacts(
    tmp_path: Path,
) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    output = tmp_path / "impact.json"
    before.write_text(
        encode_agent_manifest_json(_manifest("baseline")), encoding="utf-8"
    )
    after.write_text(
        encode_agent_manifest_json(_manifest("risky-drift")), encoding="utf-8"
    )

    machine = runner.invoke(
        app,
        [
            "capability",
            "impact",
            "--before",
            str(before),
            "--after",
            str(after),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )
    chinese = runner.invoke(
        app,
        [
            "capability",
            "impact",
            "--before",
            str(before),
            "--after",
            str(after),
            "--language",
            "zh",
        ],
    )

    assert machine.exit_code == chinese.exit_code == ExitCode.SUCCESS
    assert machine.stdout == machine.stderr == ""
    report = decode_capability_change_impact_json(output.read_text(encoding="utf-8"))
    assert report.summary.added_findings == 17
    assert "AgentSec 能力变化影响" in chinese.stdout
    assert "Finding Delta：新增=17" in chinese.stdout

    overwrite = runner.invoke(
        app,
        [
            "capability",
            "impact",
            "--before",
            str(before),
            "--after",
            str(after),
            "--format",
            "json",
            "--output",
            str(before),
            "--force",
        ],
    )
    assert overwrite.exit_code == ExitCode.ARTIFACT_ERROR
    assert "must not replace an input artifact" in overwrite.stderr
