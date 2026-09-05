"""RISK-03 Homi Operation Context extraction tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.frameworks import (
    DeterministicHomiReportOnlyPilot,
    HomiAdapter,
    HomiOperationContextExtractionError,
    HomiOperationContextExtractor,
    HomiPilotReport,
    HomiPilotRequest,
    build_homi_operation_context_report,
    build_homi_operation_context_report_from_workspace,
    build_manifest_operation_context_set,
    encode_homi_operation_context_json,
    export_homi_operation_context_json_schema,
)
from agentsec.frameworks.base import FrameworkInspectionRequest
from agentsec.manifests import AgentManifestBuilder
from agentsec.risk import (
    AuthorizationState,
    ControlState,
    DataClassification,
    DataRetention,
    OperationAction,
    OperationContextStatus,
    OperationTarget,
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _request(workspace: Path, output: Path) -> HomiPilotRequest:
    return HomiPilotRequest(
        pilot_id="risk-03-test",
        project_name="RISK-03 test",
        owner="security",
        target_root=workspace,
        output_root=output,
    )


def _workspace(workspace: Path) -> None:
    _write(
        workspace / "AGENTS.md",
        """# Workspace
Read files for analysis.
Search the web for public information.
Sending emails requires asking first.
When the user asks, store a user preference in USER.md.
Update AGENTS.md when a reviewed lesson matters.
Read secrets only with approval.
""",
    )
    _write(workspace / "SOUL.md", "Be helpful. Have opinions.\n")
    _write(workspace / "IDENTITY.md", "Name: Demo\n")
    _write(workspace / "USER.md", "Name: Alice\nTimezone: Asia/Shanghai\n")
    _write(
        workspace / "TOOLS.md",
        """# Runtime notes
Connect to SSH home-server when the user requests administration.
Use OAuth for the approved calendar integration.
""",
    )
    _write(
        workspace / "HEARTBEAT.md",
        "Search the web for the daily weather summary.\n",
    )


def _report(tmp_path: Path) -> HomiPilotReport:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _workspace(workspace)
    return DeterministicHomiReportOnlyPilot().run(_request(workspace, tmp_path / "out"))


def test_extracts_structured_contexts_without_scoring_or_authority(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _workspace(workspace)
    inspection = HomiAdapter().inspect_workspace(FrameworkInspectionRequest(workspace))
    contexts = HomiOperationContextExtractor().extract(inspection)

    by_id = {item.operation_id: item for item in contexts.contexts}
    assert set(by_id) >= {
        "homi.workspace.read",
        "homi.network.scheduled-read",
        "homi.external-message.send",
        "homi.memory.persist",
        "homi.control-file.modify",
        "homi.secret.read",
        "homi.ssh.connect",
        "homi.oauth.use",
    }
    assert by_id["homi.workspace.read"].action is OperationAction.READ
    assert by_id["homi.network.scheduled-read"].trigger.value == "scheduled"
    assert by_id["homi.network.scheduled-read"].target is OperationTarget.PUBLIC_WEB
    assert by_id["homi.external-message.send"].authorization.state is (
        AuthorizationState.APPROVAL_REQUIRED
    )
    assert by_id["homi.memory.persist"].target is OperationTarget.USER_PROFILE
    assert by_id["homi.secret.read"].data_scope.classification is (
        DataClassification.SECRET
    )
    assert by_id["homi.workspace.read"].status is OperationContextStatus.NEEDS_CONTEXT
    assert contexts.coverage_complete is False
    assert contexts.unknown_dimensions
    assert all(item.runtime_verified is False for item in contexts.contexts)
    assert all(item.score if False else True for item in contexts.contexts)


def test_context_report_is_bound_to_exact_pilot_snapshot(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _workspace(workspace)
    report = DeterministicHomiReportOnlyPilot().run(
        _request(workspace, tmp_path / "out")
    )
    extracted = build_homi_operation_context_report_from_workspace(workspace, report)
    payload = json.loads(encode_homi_operation_context_json(extracted))

    assert payload["format"] == "agentsec-homi-operation-context-extraction"
    assert payload["source_report_sha256"]
    assert payload["context_set"]["format"] == "agentsec-operation-context-set"
    assert payload["authority"] == {
        "report_only": True,
        "runtime_verified": False,
        "ci_blocked": False,
    }
    assert "Sending emails requires asking first" not in json.dumps(payload)

    _write(workspace / "AGENTS.md", "Read files only.\n")
    with pytest.raises(HomiOperationContextExtractionError, match="changed"):
        build_homi_operation_context_report_from_workspace(workspace, report)


def test_template_placeholders_do_not_become_memory_or_tool_operations(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _write(workspace / "AGENTS.md", "Follow the workspace instructions.\n")
    _write(workspace / "SOUL.md", "This file is yours to evolve.\n")
    _write(workspace / "IDENTITY.md", "Fill this in during your first conversation.\n")
    _write(
        workspace / "USER.md",
        "# About Your Human\nUpdate this as you go. Build this over time.\n"
        "Name:\nTimezone:\nContext:\n",
    )
    _write(
        workspace / "TOOLS.md",
        "## What Goes Here\nCamera names and locations.\n\n"
        "## Examples\nhome-server → 192.0.2.10\n\n"
        "## Why Separate?\nSkills are shared.\n",
    )
    _write(workspace / "HEARTBEAT.md", "# Keep this file empty\n")
    inspection = HomiAdapter().inspect_workspace(FrameworkInspectionRequest(workspace))
    contexts = HomiOperationContextExtractor().extract(inspection)

    assert {item.operation_id for item in contexts.contexts} == {
        "homi.operation.unknown"
    }
    assert contexts.contexts[0].status is OperationContextStatus.UNKNOWN


def test_empty_operation_set_uses_an_honest_unknown_fallback(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for name in ("AGENTS.md", "SOUL.md", "IDENTITY.md", "USER.md", "TOOLS.md"):
        _write(workspace / name, "No operation declaration.\n")
    _write(workspace / "HEARTBEAT.md", "# disabled\n")
    inspection = HomiAdapter().inspect_workspace(FrameworkInspectionRequest(workspace))
    context_set = HomiOperationContextExtractor().extract(inspection)

    assert len(context_set.contexts) == 1
    assert context_set.contexts[0].operation_id == "homi.operation.unknown"
    assert context_set.contexts[0].action is OperationAction.UNKNOWN
    assert context_set.contexts[0].status is OperationContextStatus.UNKNOWN
    assert context_set.coverage_complete is False


def test_manifest_context_extraction_preserves_manifest_evidence_boundary(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _workspace(workspace)
    inspection = HomiAdapter().inspect_workspace(FrameworkInspectionRequest(workspace))
    manifest = AgentManifestBuilder().build(inspection.framework_result)

    context_set = build_manifest_operation_context_set(manifest)

    assert context_set.subject_id == manifest.identity.agent_id
    assert context_set.contexts
    assert context_set.contexts[0].operation_id == "manifest.operation.unknown"
    assert context_set.contexts[0].evidence[0].extraction_method.value == "manifest"
    assert context_set.contexts[0].evidence[0].confidence.value == "C"
    assert context_set.coverage_complete is False


def test_schema_export_is_deterministic(tmp_path: Path) -> None:
    first = export_homi_operation_context_json_schema(tmp_path)
    first_text = first.read_text(encoding="utf-8")
    second = export_homi_operation_context_json_schema(tmp_path)
    payload = json.loads(second.read_text(encoding="utf-8"))

    assert first == second
    assert first_text == second.read_text(encoding="utf-8")
    assert payload["properties"]["format"]["const"] == (
        "agentsec-homi-operation-context-extraction"
    )
    assert "context_set" in payload["required"]


def test_direct_report_builder_requires_pilot_report(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _workspace(workspace)
    inspection = HomiAdapter().inspect_workspace(FrameworkInspectionRequest(workspace))
    with pytest.raises(TypeError, match="HomiPilotReport"):
        build_homi_operation_context_report(inspection, object())


@pytest.mark.parametrize(
    ("scenario", "operation_id"),
    (
        ("scenario-07", "homi.memory.persist"),
        ("scenario-08", "homi.mailbox.scheduled-read"),
        ("scenario-10", "homi.external-message.send"),
        ("scenario-12", "homi.approval-policy.disable"),
    ),
)
def test_risk_replay_scenarios_extract_action_context(
    scenario: str,
    operation_id: str,
) -> None:
    repository_root = Path(__file__).parents[1]
    workspace = repository_root / "pilots" / "risk-replay-r09" / scenario
    inspection = HomiAdapter().inspect_workspace(FrameworkInspectionRequest(workspace))
    contexts = HomiOperationContextExtractor().extract(inspection)
    by_id = {item.operation_id: item for item in contexts.contexts}

    assert operation_id in by_id
    if scenario == "scenario-07":
        assert by_id[operation_id].data_scope.classification is (
            DataClassification.PERSONAL
        )
        assert by_id[operation_id].data_scope.retention is DataRetention.INDEFINITE
    if scenario == "scenario-08":
        assert by_id[operation_id].target is OperationTarget.USER_MAILBOX
        assert by_id[operation_id].trigger.value == "scheduled"
    if scenario == "scenario-10":
        assert by_id[operation_id].trigger.value == "autonomous"
        assert by_id[operation_id].authorization.state is (
            AuthorizationState.APPROVAL_MISSING
        )
        assert by_id[operation_id].controls.approval is ControlState.ABSENT
    if scenario == "scenario-12":
        assert by_id[operation_id].action is OperationAction.MODIFY_POLICY
        assert by_id[operation_id].controls.approval is ControlState.ABSENT
