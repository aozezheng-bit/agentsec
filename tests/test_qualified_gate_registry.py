"""P2-EXIT-01 Trusted Gate Qualification Registry tests."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from agentsec.cli import ExitCode, app
from agentsec.policy import PolicyError
from agentsec.policy.qualification_registry import (
    QUALIFIED_GATE_REGISTRY_FORMAT,
    QUALIFIED_GATE_REGISTRY_SCHEMA_VERSION,
    load_qualification_registry,
    verify_gate_qualification,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RISKY_CAPABILITY = REPOSITORY_ROOT / "demos" / "capability-drift-agent" / "risky-drift"
GATE_ID = "HG-CAPCHAIN-001"
RULE_ID = "CAP-CHAIN-001"

runner = CliRunner()


def _canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _artifact_id(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned["artifact_id"] = None
    return (
        "qualification-report-sha256:"
        + hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
    )


def _valid_report_payload(
    *, gate_id: str = GATE_ID, rule_id: str = RULE_ID
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "format": "agentsec-gate-scoped-qualification-report",
        "schema_version": "0.1.0",
        "status": "complete",
        "gate_id": gate_id,
        "rule_id": rule_id,
        "evidence_mode": "human",
        "package_id": "gate-review-package-sha256:" + "a1" * 32,
        "selection_id": "gate-subset-selection-sha256:" + "b2" * 32,
        "human_evidence_artifact_id": "human-evidence-sha256:" + "c3" * 32,
        "source_corpus_id": "test-corpus",
        "detector": {"evaluator_id": "test-evaluator", "evaluator_version": "0.1.0"},
        "thresholds": {"min_positive_samples": 20},
        "sample_scope": {"case_count": 40},
        "confusion_matrix": {"true_positive": 20},
        "metrics": {"precision": 1.0},
        "reviewer_agreement": {"confidence_kappa": 1.0},
        "confidence_calibration": {"items": 40},
        "qualification": {
            "status": "accepted",
            "eligible_for_report_only_gate": True,
            "checks": {"sample_threshold": {"status": "pass", "detail": "20/20"}},
            "blocking_reasons": [],
        },
        "policy": {
            "enforcement_mode": "report_only",
            "hard_gate": False,
            "ci_blocking": False,
            "fail_on": False,
            "runtime_capability_verified": False,
            "llm_used": False,
        },
        "limitations": ["Synthetic test evidence."],
        "cases": [],
        "artifact_id": None,
    }
    report["artifact_id"] = _artifact_id(report)
    return report


def _write_report(path: Path, payload: dict[str, Any]) -> str:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _registry_payload(
    report_path: Path,
    *,
    artifact_id: str | None = None,
    sha256: str | None = None,
    floor: str = "high",
    gate_id: str = GATE_ID,
) -> dict[str, Any]:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    pinned_artifact = payload.get("artifact_id") or (
        "qualification-report-sha256:" + "00" * 32
    )
    return {
        "format": QUALIFIED_GATE_REGISTRY_FORMAT,
        "schema_version": QUALIFIED_GATE_REGISTRY_SCHEMA_VERSION,
        "registry_id": "test-approved-gates",
        "registry_version": "2026.08.25",
        "gates": [
            {
                "gate_id": gate_id,
                "qualification_report_path": report_path.name,
                "qualification_artifact_id": artifact_id or pinned_artifact,
                "qualification_sha256": sha256
                or hashlib.sha256(report_path.read_bytes()).hexdigest(),
                "evidence_mode": "human",
                "qualification_status": "accepted",
                "allowed_floor": floor,
            }
        ],
    }


def _write_registry(directory: Path, payload: Mapping[str, Any]) -> Path:
    registry_path = directory / "qualified-gate-registry.yaml"
    registry_path.write_text(
        yaml.safe_dump(json.loads(json.dumps(payload)), sort_keys=False),
        encoding="utf-8",
    )
    return registry_path


def _evidence_bundle(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    report_path = tmp_path / "qualification-report.json"
    report = _valid_report_payload()
    _write_report(report_path, report)
    registry = _registry_payload(report_path)
    registry_path = _write_registry(tmp_path, registry)
    return registry_path, registry


def test_valid_pinned_qualification_is_accepted(tmp_path: Path) -> None:
    registry_path, registry = _evidence_bundle(tmp_path)
    loaded = load_qualification_registry(registry_path)

    assert loaded.registry.registry_id == "test-approved-gates"
    entry = loaded.registry.gates[0]
    evidence = verify_gate_qualification(entry, registry_dir=registry_path.parent)

    assert evidence.gate_id == GATE_ID
    assert evidence.rule_id == RULE_ID
    assert evidence.allowed_floor == "high"
    assert (
        evidence.qualification_artifact_id
        == registry["gates"][0]["qualification_artifact_id"]
    )


def test_minimal_forged_qualification_is_rejected(tmp_path: Path) -> None:
    forged: dict[str, Any] = {
        "format": "agentsec-gate-scoped-qualification-report",
        "schema_version": "0.1.0",
        "gate_id": GATE_ID,
        "qualification": {"status": "accepted"},
    }
    report_path = tmp_path / "qualification-report.json"
    report_path.write_text(json.dumps(forged), encoding="utf-8")
    registry_path = _write_registry(tmp_path, _registry_payload(report_path))
    loaded = load_qualification_registry(registry_path)

    with pytest.raises(PolicyError):
        verify_gate_qualification(loaded.registry.gates[0], registry_dir=tmp_path)


def test_truncated_qualification_is_rejected(tmp_path: Path) -> None:
    registry_path, registry = _evidence_bundle(tmp_path)
    report_path = tmp_path / "qualification-report.json"
    truncated = report_path.read_text(encoding="utf-8")[:120]
    report_path.write_text(truncated, encoding="utf-8")
    loaded = load_qualification_registry(registry_path)

    with pytest.raises(PolicyError):
        verify_gate_qualification(loaded.registry.gates[0], registry_dir=tmp_path)


def test_wrong_evidence_artifact_id_is_rejected(tmp_path: Path) -> None:
    registry_path, registry = _evidence_bundle(tmp_path)
    registry["gates"][0]["qualification_artifact_id"] = (
        "qualification-report-sha256:" + "00" * 32
    )
    _write_registry(tmp_path, registry)
    loaded = load_qualification_registry(registry_path)

    with pytest.raises(PolicyError):
        verify_gate_qualification(loaded.registry.gates[0], registry_dir=tmp_path)


def test_wrong_qualification_sha256_is_rejected(tmp_path: Path) -> None:
    registry_path, registry = _evidence_bundle(tmp_path)
    registry["gates"][0]["qualification_sha256"] = "00" * 32
    _write_registry(tmp_path, registry)
    loaded = load_qualification_registry(registry_path)

    with pytest.raises(PolicyError):
        verify_gate_qualification(loaded.registry.gates[0], registry_dir=tmp_path)


@pytest.mark.parametrize("field", ["gate_id", "rule_id"])
def test_wrong_gate_or_rule_binding_is_rejected(tmp_path: Path, field: str) -> None:
    report_path = tmp_path / "qualification-report.json"
    forged = _valid_report_payload()
    forged[field] = "MD-EXEC-001"
    forged["artifact_id"] = _artifact_id(forged)
    _write_report(report_path, forged)
    registry_path = _write_registry(tmp_path, _registry_payload(report_path))
    loaded = load_qualification_registry(registry_path)

    with pytest.raises(PolicyError):
        verify_gate_qualification(loaded.registry.gates[0], registry_dir=tmp_path)


def test_wrong_floor_is_rejected(tmp_path: Path) -> None:
    report_path = tmp_path / "qualification-report.json"
    _write_report(report_path, _valid_report_payload())
    with pytest.raises(PolicyError):
        _write_registry(tmp_path, _registry_payload(report_path, floor="critical"))
        load_qualification_registry(tmp_path / "qualified-gate-registry.yaml")


def test_report_symlink_is_rejected(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real_report = real_dir / "qualification-report.json"
    _write_report(real_report, _valid_report_payload())

    registry_dir = tmp_path / "evidence"
    registry_dir.mkdir()
    os.symlink(real_report, registry_dir / "qualification-report.json")
    registry_path = _write_registry(registry_dir, _registry_payload(real_report))
    loaded = load_qualification_registry(registry_path)

    with pytest.raises(PolicyError):
        verify_gate_qualification(loaded.registry.gates[0], registry_dir=registry_dir)


def test_registry_symlink_is_rejected(tmp_path: Path) -> None:
    registry_path, _ = _evidence_bundle(tmp_path)
    link = tmp_path / "linked-registry.yaml"
    os.symlink(registry_path, link)

    with pytest.raises(PolicyError):
        load_qualification_registry(link)


def test_registry_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    text = (
        "format: agentsec-qualified-gate-registry\n"
        "format: agentsec-qualified-gate-registry\n"
        "schema_version: '0.1.0'\n"
        "registry_id: duplicated\n"
        "registry_version: '2026.08.25'\n"
        "gates: []\n"
    )
    path = tmp_path / "qualified-gate-registry.yaml"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(PolicyError):
        load_qualification_registry(path)


def test_qualification_report_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    report_path = tmp_path / "qualification-report.json"
    _write_report(report_path, _valid_report_payload())
    registry_path = _write_registry(tmp_path, _registry_payload(report_path))
    text = report_path.read_text(encoding="utf-8")
    duplicated = text.replace(
        '"status": "complete"', '"status": "x", "status": "complete"', 1
    )
    report_path.write_text(duplicated, encoding="utf-8")
    loaded = load_qualification_registry(registry_path)

    with pytest.raises(PolicyError):
        verify_gate_qualification(loaded.registry.gates[0], registry_dir=tmp_path)


def test_registry_unknown_fields_and_escapes_are_rejected(tmp_path: Path) -> None:
    report_path = tmp_path / "qualification-report.json"
    _write_report(report_path, _valid_report_payload())
    registry = _registry_payload(report_path)
    registry["unexpected"] = "reject me"
    with pytest.raises(PolicyError):
        _write_registry(tmp_path, registry)
        load_qualification_registry(tmp_path / "qualified-gate-registry.yaml")

    registry = _registry_payload(report_path)
    registry["gates"][0]["qualification_report_path"] = "../escape.json"
    _write_registry(tmp_path, registry)
    with pytest.raises(PolicyError):
        load_qualification_registry(tmp_path / "qualified-gate-registry.yaml")


def _policy_payload(
    *,
    enabled: bool,
    mode: str,
    registry_path: str | None = None,
    registry_sha256: str | None = None,
    unknown_free: bool = False,
) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "format": "agentsec-capability-ci-policy",
        "schema_version": "0.2.0",
        "policy_id": "p2-exit-01-test",
        "policy_version": "0.1.0",
        "enabled": enabled,
        "enforcement_mode": mode,
        "fail_on": {"qualified_gates": [GATE_ID]},
        "coverage": {"require_complete": True, "require_unknown_free": unknown_free},
        "safety": {
            "allow_llm_authority": False,
            "allow_runtime_unverified_authority": False,
        },
    }
    if registry_path is not None:
        policy["qualification"] = {
            "registry_path": registry_path,
            "registry_sha256": registry_sha256 or "0" * 64,
        }
    return policy


def _write_policy(tmp_path: Path, policy: Mapping[str, Any]) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def test_policy_with_gates_requires_registry_binding(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path, _policy_payload(enabled=True, mode="enforce"))
    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(RISKY_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR
    assert "policy error" in result.stderr.lower()


def test_missing_registry_fails_closed(tmp_path: Path) -> None:
    policy_path = _write_policy(
        tmp_path,
        _policy_payload(
            enabled=True,
            mode="enforce",
            registry_path="missing-registry.yaml",
            registry_sha256="1" * 64,
        ),
    )
    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(RISKY_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR


def test_registry_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    registry_path, _ = _evidence_bundle(tmp_path)
    policy_path = _write_policy(
        tmp_path,
        _policy_payload(
            enabled=True,
            mode="enforce",
            registry_path=registry_path.name,
            registry_sha256="2" * 64,
        ),
    )
    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(RISKY_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR


def test_forged_qualification_fails_closed_under_enforce(tmp_path: Path) -> None:
    forged: dict[str, Any] = {
        "format": "agentsec-gate-scoped-qualification-report",
        "schema_version": "0.1.0",
        "gate_id": GATE_ID,
        "qualification": {"status": "accepted"},
    }
    report_path = tmp_path / "qualification-report.json"
    report_path.write_text(json.dumps(forged), encoding="utf-8")
    registry_path = _write_registry(tmp_path, _registry_payload(report_path))
    registry_sha256 = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    policy_path = _write_policy(
        tmp_path,
        _policy_payload(
            enabled=True,
            mode="enforce",
            registry_path=registry_path.name,
            registry_sha256=registry_sha256,
        ),
    )
    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(RISKY_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.CONFIGURATION_ERROR
    payload = json.loads(result.stdout)
    assert payload["decision"] == "configuration_error"
    assert payload["matched_gates"][0]["qualification"] == "not_qualified"


def test_valid_registry_blocks_matched_gate_under_enforce(tmp_path: Path) -> None:
    from dataclasses import replace

    from agentsec.application import (
        AgentAnalysisPipeline,
        AgentAnalysisRequest,
        CapabilityAssessmentResult,
    )
    from agentsec.capability_rules import (
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
        UnknownExtractor,
    )
    from agentsec.policy import CapabilityCiPolicy, enforce_capability_assessment

    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("# Agent\n", encoding="utf-8")
    (project / ".codex").mkdir()
    (project / ".codex" / "config.toml").write_text(
        "[mcp_servers.remote]\n"
        'url = "https://example.invalid/mcp"\n'
        "enabled = true\n"
        "required = true\n"
        'auth = "oauth"\n'
        'bearer_token_env_var = "REMOTE_TOKEN"\n'
        'default_tools_approval_mode = "prompt"\n',
        encoding="utf-8",
    )

    analysis = AgentAnalysisPipeline().analyze(
        AgentAnalysisRequest(project_root=project, agent_id="exit-01-agent")
    )
    manifest = analysis.manifest
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
    chain_manifest = UnknownExtractor().extract(AgentManifest.model_validate(payload))
    analysis = replace(analysis, manifest=chain_manifest)

    rules = DeterministicCapabilityRuleRunner(builtin_capability_rules()).run(
        chain_manifest
    )
    rules = DeterministicCapabilityShadowGateEngine().apply(chain_manifest, rules)
    matched = [
        finding
        for finding in rules.findings
        if finding.capability_shadow_gate is not None
        and finding.capability_shadow_gate.matched
    ]
    assert matched, "synthetic manifest must produce a matched shadow Gate"
    result = CapabilityAssessmentResult(analysis=analysis, rules=rules)

    registry_path, _ = _evidence_bundle(tmp_path)
    loaded = load_qualification_registry(registry_path)
    policy = CapabilityCiPolicy.model_validate(
        _policy_payload(
            enabled=True,
            mode="enforce",
            registry_path=registry_path.name,
            registry_sha256=loaded.sha256,
        )
    )
    decision = enforce_capability_assessment(
        result,
        policy,
        policy_path=tmp_path / "policy.json",
        qualification_registry=loaded,
    )

    assert decision.decision == "block"
    assert decision.exit_code is ExitCode.RISK_THRESHOLD_EXCEEDED
    gate = decision.matched_gates[0]
    assert gate.gate_id == GATE_ID
    assert gate.qualification == "accepted"
    assert gate.matched is True and gate.blocks is True
    assert gate.finding_ids
    serialized = decision.to_dict()
    assert serialized["schema_version"] == "0.5.0"
    provenance = serialized["qualification_registry"]
    assert provenance["registry_id"] == "test-approved-gates"
    assert provenance["registry_sha256"] == loaded.sha256


def test_qualified_gate_registry_schema_is_frozen(tmp_path: Path) -> None:
    from agentsec.policy.qualification_registry import (
        export_qualified_gate_registry_json_schema,
    )

    generated = export_qualified_gate_registry_json_schema(tmp_path / "schemas")
    frozen = (
        REPOSITORY_ROOT / "schemas" / "policy" / "qualified-gate-registry.schema.json"
    )
    assert generated.read_bytes() == frozen.read_bytes()


def test_repository_registry_binds_real_qualification_report() -> None:
    registry_path = (
        REPOSITORY_ROOT
        / "calibration"
        / "p2-15a-capchain-40"
        / "human-evidence"
        / "qualified-gate-registry.yaml"
    )
    loaded = load_qualification_registry(registry_path)
    entry = loaded.registry.entry_for(GATE_ID)
    assert entry is not None
    evidence = verify_gate_qualification(entry, registry_dir=registry_path.parent)
    assert evidence.gate_id == GATE_ID
    assert evidence.rule_id == RULE_ID
    assert evidence.allowed_floor == "high"


def test_valid_registry_report_only_keeps_zero_exit(tmp_path: Path) -> None:
    registry_path, _ = _evidence_bundle(tmp_path)
    registry_sha256 = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    policy_path = _write_policy(
        tmp_path,
        _policy_payload(
            enabled=False,
            mode="report_only",
            registry_path=registry_path.name,
            registry_sha256=registry_sha256,
        ),
    )
    result = runner.invoke(
        app,
        [
            "capability",
            "enforce",
            str(RISKY_CAPABILITY),
            "--agent-id",
            "capability-drift-agent",
            "--policy",
            str(policy_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.SUCCESS
    payload = json.loads(result.stdout)
    assert payload["decision"] == "allow"
    gate = payload["matched_gates"][0]
    assert gate["qualification"] == "accepted"
    assert gate["blocks"] is False
