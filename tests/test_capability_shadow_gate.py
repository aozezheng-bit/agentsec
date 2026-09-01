"""P2-15A-PILOT-02 shadow-mode Capability Gate (HG-CAPCHAIN-001) tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from agentsec.application import (
    AgentAnalysisPipeline,
    AgentAnalysisRequest,
    CapabilityAssessmentEngine,
)
from agentsec.capability_rules import (
    CapabilityCorrelation,
    CapabilityRuleLanguage,
    CapabilityRuleRunResult,
    CapabilityShadowGateAssessment,
    CapabilityShadowGateMatch,
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
from agentsec.reporting import (
    CapabilityAssessmentJsonRenderer,
    CapabilityAssessmentTextRenderer,
)
from agentsec.versioning import CAPABILITY_SHADOW_GATE_VERSION

_SECRET_MARKER = "p2-15a-pilot-02-secret-must-not-leak"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _project(project: Path) -> None:
    project.mkdir()
    _write(project / "AGENTS.md", "# Agent\n")
    _write(
        project / ".codex" / "config.toml",
        f"""
[mcp_servers.remote]
url = "https://example.invalid/mcp?token={_SECRET_MARKER}"
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
        .analyze(AgentAnalysisRequest(project_root=project, agent_id="release-agent"))
        .manifest
    )


def _explicit_chain_manifest(project: Path) -> AgentManifest:
    """Return a Manifest with an explicit same-target chain and no Unknowns."""

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
        item["effect"] = "allow"
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
        identity["privileged"] = False
        identities.append(identity)
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


def _run(manifest: AgentManifest) -> CapabilityRuleRunResult:
    return DeterministicCapabilityRuleRunner(builtin_capability_rules()).run(manifest)


def _gate(manifest: AgentManifest) -> CapabilityRuleRunResult:
    return DeterministicCapabilityShadowGateEngine().apply(manifest, _run(manifest))


def _chain_gate(result: CapabilityRuleRunResult) -> CapabilityShadowGateAssessment:
    gates = [
        finding.capability_shadow_gate
        for finding in result.findings
        if finding.capability_shadow_gate is not None
    ]
    assert len(gates) == 1
    gate = gates[0]
    assert gate is not None
    return gate


def test_shadow_gate_matches_explicit_same_target_chain(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
    manifest = _explicit_chain_manifest(project)

    result = _gate(manifest)
    gate = _chain_gate(result)

    assert gate.gate_id == "HG-CAPCHAIN-001"
    assert gate.gate_version == CAPABILITY_SHADOW_GATE_VERSION == "0.1.0"
    assert gate.mode == "shadow"
    assert gate.qualification == "pilot_only"
    assert gate.matched is True
    assert gate.blocks is False
    assert gate.coverage_complete is True
    assert gate.relevant_unknowns == 0
    assert gate.match is not None
    assert gate.match.floor == "high"
    assert gate.match.correlation is CapabilityCorrelation.SAME_TARGET
    assert gate.match.related_ids == ("mcp-server:remote",)


def test_shadow_gate_never_changes_risk_or_enforcement(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
    manifest = _explicit_chain_manifest(project)

    plain = _run(manifest)
    gated = _gate(manifest)

    assert len(plain.findings) == len(gated.findings)
    for before, after in zip(plain.findings, gated.findings, strict=True):
        assert after.finding_id == before.finding_id
        assert after.score == before.score
        assert after.severity is before.severity
        assert after.confidence is before.confidence
        assert after.hard_gate is False
        if before.rule_id != "CAP-CHAIN-001":
            assert after.capability_shadow_gate is None


def test_shadow_gate_rejects_agent_wide_d_confidence(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
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
default_tools_approval_mode = "prompt"
""".lstrip(),
    )
    manifest = _analyze(project)

    result = _gate(manifest)
    chain = [
        finding for finding in result.findings if finding.rule_id == "CAP-CHAIN-001"
    ]
    assert chain
    for finding in chain:
        gate = finding.capability_shadow_gate
        assert gate is not None
        if finding.correlation is CapabilityCorrelation.AGENT_WIDE:
            assert gate.matched is False
            assert gate.match is None


def _natural_chain_manifest(project: Path) -> AgentManifest:
    """Return a Manifest with a same-target chain that retains Unknowns."""

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
            permission_id="permission:execute:mcp-server:remote:synthetic",
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


def _parent_child_chain_manifest(project: Path) -> AgentManifest:
    """Return a complete chain split between one MCP server and its child tool."""

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


def test_shadow_gate_rejects_relevant_unknowns(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
    manifest = _natural_chain_manifest(project)

    gate = _chain_gate(_gate(manifest))

    assert gate.matched is False
    assert gate.match is None
    assert gate.relevant_unknowns > 0


def test_shadow_gate_matches_reviewed_parent_child_family(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
    manifest = _parent_child_chain_manifest(project)

    gate = _chain_gate(_gate(manifest))

    assert gate.matched is True
    assert gate.match is not None
    assert gate.match.correlation is CapabilityCorrelation.PARENT_CHILD
    assert gate.match.related_ids == (
        "mcp-server:remote",
        "mcp-tool:remote:execute",
    )


def test_shadow_gate_rejects_incomplete_coverage(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
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
    manifest = UnknownExtractor().extract(AgentManifest.model_validate(payload))

    gate = _chain_gate(_gate(manifest))

    assert gate.matched is False
    assert gate.match is None
    assert gate.coverage_complete is False


def test_shadow_gate_engine_validates_inputs(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
    manifest = _explicit_chain_manifest(project)
    result = _run(manifest)
    engine = DeterministicCapabilityShadowGateEngine()

    with pytest.raises(TypeError, match="AgentManifest"):
        engine.apply(object(), result)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="CapabilityRuleRunResult"):
        engine.apply(manifest, object())  # type: ignore[arg-type]
    other = CapabilityRuleRunResult(
        agent_id="other-agent",
        evaluated_rule_ids=result.evaluated_rule_ids,
        findings=result.findings,
    )
    with pytest.raises(ValueError, match="Agent binding"):
        engine.apply(manifest, other)

    non_chain = next(
        item for item in result.findings if item.rule_id != "CAP-CHAIN-001"
    )
    forged_gate = replace(
        _chain_gate(_gate(manifest)),
        finding_id=non_chain.finding_id,
    )
    forged = non_chain.attach_capability_shadow_gate(forged_gate)
    forged_result = replace(
        result,
        findings=tuple(
            forged if item.finding_id == non_chain.finding_id else item
            for item in result.findings
        ),
    )
    with pytest.raises(ValueError, match="CAP-CHAIN-001 only"):
        engine.apply(manifest, forged_result)


def test_shadow_gate_assessment_contract_is_enforced(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
    gate = _chain_gate(_gate(_explicit_chain_manifest(project)))
    assert gate.match is not None

    with pytest.raises(ValueError, match="never block"):
        CapabilityShadowGateAssessment(
            gate_version=gate.gate_version,
            gate_id=gate.gate_id,
            finding_id=gate.finding_id,
            mode="shadow",
            qualification="pilot_only",
            matched=False,
            blocks=True,  # type: ignore[arg-type]
            coverage_complete=True,
            relevant_unknowns=0,
            match=None,
        )
    with pytest.raises(ValueError, match="inconsistent"):
        CapabilityShadowGateAssessment(
            gate_version=gate.gate_version,
            gate_id=gate.gate_id,
            finding_id=gate.finding_id,
            mode="shadow",
            qualification="pilot_only",
            matched=True,
            blocks=False,
            coverage_complete=True,
            relevant_unknowns=0,
            match=None,
        )
    with pytest.raises(ValueError, match="must be shadow"):
        CapabilityShadowGateAssessment(
            gate_version=gate.gate_version,
            gate_id=gate.gate_id,
            finding_id=gate.finding_id,
            mode="enforce",  # type: ignore[arg-type]
            qualification="pilot_only",
            matched=False,
            blocks=False,
            coverage_complete=True,
            relevant_unknowns=0,
            match=None,
        )
    with pytest.raises(ValueError, match="pilot_only"):
        CapabilityShadowGateAssessment(
            gate_version=gate.gate_version,
            gate_id=gate.gate_id,
            finding_id=gate.finding_id,
            mode="shadow",
            qualification="formal",  # type: ignore[arg-type]
            matched=False,
            blocks=False,
            coverage_complete=True,
            relevant_unknowns=0,
            match=None,
        )
    with pytest.raises(ValueError, match="Finding binding"):
        finding = next(
            item
            for item in _gate(_explicit_chain_manifest(project)).findings
            if item.rule_id != "CAP-CHAIN-001"
        )
        finding.attach_capability_shadow_gate(gate)


def test_shadow_gate_match_contract_is_enforced(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
    gate = _chain_gate(_gate(_explicit_chain_manifest(project)))
    assert gate.match is not None

    with pytest.raises(ValueError, match="Gate ID"):
        CapabilityShadowGateMatch(
            gate_id="CAP-CHAIN-001",
            floor="high",
            correlation=CapabilityCorrelation.SAME_TARGET,
            related_ids=("mcp-server:remote",),
            rationale=("valid rationale",),
        )
    with pytest.raises(ValueError, match="floor"):
        CapabilityShadowGateMatch(
            gate_id="HG-CAPCHAIN-001",
            floor="medium",  # type: ignore[arg-type]
            correlation=CapabilityCorrelation.SAME_TARGET,
            related_ids=("mcp-server:remote",),
            rationale=("valid rationale",),
        )
    with pytest.raises(ValueError, match="Gate-eligible"):
        CapabilityShadowGateMatch(
            gate_id="HG-CAPCHAIN-001",
            floor="high",
            correlation=CapabilityCorrelation.AGENT_WIDE,
            related_ids=("mcp-server:remote",),
            rationale=("valid rationale",),
        )
    with pytest.raises(ValueError, match="requires related IDs"):
        CapabilityShadowGateMatch(
            gate_id="HG-CAPCHAIN-001",
            floor="high",
            correlation=CapabilityCorrelation.SAME_TARGET,
            related_ids=(),
            rationale=("valid rationale",),
        )


def test_shadow_gate_assessment_rejects_unsupported_version_and_unsafe_match(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _project(project)
    gate = _chain_gate(_gate(_explicit_chain_manifest(project)))
    assert gate.match is not None

    with pytest.raises(ValueError, match="version is unsupported"):
        CapabilityShadowGateAssessment(
            gate_version="9.9.9",
            gate_id=gate.gate_id,
            finding_id=gate.finding_id,
            mode="shadow",
            qualification="pilot_only",
            matched=False,
            blocks=False,
            coverage_complete=True,
            relevant_unknowns=0,
            match=None,
        )
    with pytest.raises(ValueError, match="incomplete or Unknown"):
        CapabilityShadowGateAssessment(
            gate_version=gate.gate_version,
            gate_id=gate.gate_id,
            finding_id=gate.finding_id,
            mode="shadow",
            qualification="pilot_only",
            matched=True,
            blocks=False,
            coverage_complete=False,
            relevant_unknowns=0,
            match=gate.match,
        )
    with pytest.raises(ValueError, match="incomplete or Unknown"):
        CapabilityShadowGateAssessment(
            gate_version=gate.gate_version,
            gate_id=gate.gate_id,
            finding_id=gate.finding_id,
            mode="shadow",
            qualification="pilot_only",
            matched=True,
            blocks=False,
            coverage_complete=True,
            relevant_unknowns=1,
            match=gate.match,
        )


def test_shadow_gate_flows_through_assessment_engine_and_reports() -> None:
    project = Path(__file__).parents[1] / "demos/capability-drift-agent/risky-drift"
    request = AgentAnalysisRequest(project_root=project)
    result = CapabilityAssessmentEngine().assess(request)

    gate = _chain_gate(result.rules)
    assert gate.matched is False  # agent-wide D evidence can never match
    assert gate.relevant_unknowns > 0

    import json

    payload = json.loads(CapabilityAssessmentJsonRenderer().render(result))
    chain = next(
        item for item in payload["findings"] if item["rule_id"] == "CAP-CHAIN-001"
    )
    assert chain["capability_shadow_gate"] == {
        "blocks": False,
        "coverage_complete": True,
        "finding_id": chain["finding_id"],
        "gate_id": "HG-CAPCHAIN-001",
        "gate_version": "0.1.0",
        "match": None,
        "matched": False,
        "mode": "shadow",
        "qualification": "pilot_only",
        "relevant_unknowns": gate.relevant_unknowns,
    }
    assert payload["summary"]["shadow_gate_matches"] == 0
    assert payload["summary"]["hard_gate_matches"] == 0
    assert _SECRET_MARKER not in json.dumps(payload)

    for language, expected in (
        (CapabilityRuleLanguage.EN, "Shadow Gate: HG-CAPCHAIN-001 not matched"),
        (CapabilityRuleLanguage.ZH, "Shadow Gate：HG-CAPCHAIN-001 未命中"),
    ):
        text = CapabilityAssessmentTextRenderer(language=language).render(result)
        assert expected in text
        assert _SECRET_MARKER not in text


def test_shadow_gate_json_report_serializes_positive_match(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _project(project)
    manifest = _explicit_chain_manifest(project)
    result = _gate(manifest)
    finding = next(item for item in result.findings if item.rule_id == "CAP-CHAIN-001")
    assert finding.capability_shadow_gate is not None
    assert finding.capability_shadow_gate.matched is True

    from agentsec.reporting.capability_assessment_json import _finding as _to_report

    report_finding = _to_report(finding)
    gate = report_finding.capability_shadow_gate
    assert gate is not None
    assert gate.matched is True
    assert gate.blocks is False
    assert gate.match is not None
    assert gate.match.gate_id == "HG-CAPCHAIN-001"
    assert gate.match.floor == "high"
    assert gate.match.correlation is CapabilityCorrelation.SAME_TARGET
    serialized = gate.model_dump(mode="json")
    assert serialized["mode"] == "shadow"
    assert serialized["qualification"] == "pilot_only"
    assert _SECRET_MARKER not in str(serialized)
